use crate::DomainFilterResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use tracing::{debug, trace};

use lazy_static::lazy_static;

/// Global callback registry - mirrors the one in leaf-ffi
static DOMAIN_FILTER_CALLBACK: Mutex<Option<DomainFilterCallback>> = Mutex::new(None);
static DOMAIN_FILTER_USER_DATA: Mutex<Option<usize>> = Mutex::new(None);

// Pending request with timestamp for cleanup
struct PendingRequest {
    sender: tokio::sync::oneshot::Sender<DomainFilterResult>,
    created_at: std::time::Instant,
}

lazy_static! {
    static ref PENDING_REQUESTS: Mutex<HashMap<u64, PendingRequest>> =
        Mutex::new(HashMap::new());
}
static REQUEST_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Domain filtering callback type (mirrors leaf-ffi)
pub type DomainFilterCallback = extern "C" fn(
    domain: *const std::ffi::c_char,
    request_id: u64,
    user_data: *mut std::ffi::c_void,
);

/// Register a domain filtering callback (called from leaf-ffi)
pub fn register_callback(
    callback: DomainFilterCallback,
    user_data: *mut std::ffi::c_void,
) {
    {
        let mut cb = DOMAIN_FILTER_CALLBACK.lock().unwrap();
        *cb = Some(callback);
    }
    {
        let mut data = DOMAIN_FILTER_USER_DATA.lock().unwrap();
        *data = Some(user_data as usize);
    }
    debug!("Domain filter callback registered in leaf core");
}

/// Resolve a domain filtering request (called from leaf-ffi)
pub fn resolve_request(request_id: u64, result: DomainFilterResult) -> bool {
    let mut pending = PENDING_REQUESTS.lock().unwrap();
    if let Some(pending_req) = pending.remove(&request_id) {
        let _ = pending_req.sender.send(result);
        true
    } else {
        false
    }
}

/// Implementation of domain filtering check
///
/// IMPORTANT: The domain string pointer passed to the callback is EPHEMERAL.
/// It is ONLY valid during the callback execution. The callback implementation
/// MUST copy the string immediately (e.g., using Swift's String(cString:)).
pub async fn check_domain_filter_impl(domain: &str) -> DomainFilterResult {
    // Check if callback is registered
    let callback = {
        let cb = DOMAIN_FILTER_CALLBACK.lock().unwrap();
        *cb
    };

    let user_data = {
        let data = DOMAIN_FILTER_USER_DATA.lock().unwrap();
        *data
    };

    if let Some(callback) = callback {
        // Wrap request IDs to prevent overflow and reuse old IDs
        // 1 million is enough to avoid collisions given the 5-second timeout
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 1_000_000;
        
        // Create oneshot channel for response
        let (sender, receiver) = tokio::sync::oneshot::channel();

        // Store the sender with timestamp
        {
            let mut pending = PENDING_REQUESTS.lock().unwrap();

            // Periodic cleanup every 100 requests to prevent buildup
            if request_id % 100 == 0 {
                let now = std::time::Instant::now();
                let initial_count = pending.len();
                pending.retain(|_, req| {
                    now.duration_since(req.created_at) < std::time::Duration::from_secs(10)
                });
                let cleaned = initial_count - pending.len();
                if cleaned > 0 {
                    debug!("Auto-cleaned {} stale requests", cleaned);
                }
            }

            pending.insert(request_id, PendingRequest {
                sender,
                created_at: std::time::Instant::now(),
            });
        }
        
        // Convert domain to C string
        let domain_cstr = std::ffi::CString::new(domain).unwrap();

        // Call the callback
        trace!("Calling domain filter callback for: {}", domain);
        let user_data_ptr = user_data.map(|addr| addr as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut());

        // IMPORTANT: The domain pointer is EPHEMERAL and ONLY valid during the callback.
        // The Swift callback MUST copy the string immediately using String(cString:).
        // The CString will be dropped after this function returns.
        callback(domain_cstr.as_ptr(), request_id, user_data_ptr);

        // CString is automatically dropped here, freeing the memory
        
        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await {
            Ok(Ok(result)) => {
                trace!("Domain filter result for {}: {:?}", domain, result);
                result
            }
            _ => {
                // Timeout or error - cleanup and default to Allow
                let mut pending = PENDING_REQUESTS.lock().unwrap();
                pending.remove(&request_id);
                debug!("Domain filter timeout for {}, defaulting to Allow", domain);
                DomainFilterResult::Allow
            }
        }
    } else {
        // No callback registered - default to Allow
        trace!("No domain filter callback registered, allowing: {}", domain);
        DomainFilterResult::Allow
    }
}

/// Cleanup stale domain filter requests older than the specified duration.
/// Returns the number of cleaned requests.
///
/// This function is safe to call from FFI and can be invoked by Swift
/// to proactively free memory when high memory pressure is detected.
///
/// # Arguments
/// * `max_age` - Maximum age of requests to keep. Requests older than this will be removed.
///
/// # Returns
/// The number of requests that were cleaned up.
///
/// # Thread Safety
/// This function is thread-safe and can be called from any thread.
pub fn cleanup_stale_requests(max_age: std::time::Duration) -> usize {
    let mut pending = PENDING_REQUESTS.lock().unwrap();
    let now = std::time::Instant::now();
    let initial_count = pending.len();

    pending.retain(|_id, req| {
        let age = now.duration_since(req.created_at);
        age < max_age
    });

    let cleaned = initial_count - pending.len();
    if cleaned > 0 {
        debug!("Cleaned {} stale domain filter requests (age > {:?})", cleaned, max_age);
    }
    cleaned
}

/// Memory statistics for domain filter system.
#[derive(Debug, Clone)]
pub struct DomainFilterMemoryStats {
    /// Number of pending domain filter requests
    pub pending_requests: usize,
    /// Total number of requests processed since startup
    pub total_requests: u64,
    /// Age of the oldest pending request in seconds, if any
    pub oldest_request_age_secs: Option<u64>,
}

/// Get current memory statistics for the domain filter system.
///
/// This function provides visibility into the internal state of the domain
/// filtering system, useful for monitoring and debugging memory issues.
///
/// # Returns
/// `DomainFilterMemoryStats` containing current statistics.
///
/// # Thread Safety
/// This function is thread-safe and can be called from any thread.
pub fn get_memory_stats() -> DomainFilterMemoryStats {
    let pending = PENDING_REQUESTS.lock().unwrap();
    let now = std::time::Instant::now();

    let oldest_age = pending.values()
        .map(|req| now.duration_since(req.created_at).as_secs())
        .max();

    DomainFilterMemoryStats {
        pending_requests: pending.len(),
        total_requests: REQUEST_ID_COUNTER.load(std::sync::atomic::Ordering::SeqCst),
        oldest_request_age_secs: oldest_age,
    }
}