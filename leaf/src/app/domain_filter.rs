use crate::DomainFilterResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use tracing::{debug, trace};

use lazy_static::lazy_static;

/// Global callback registry - mirrors the one in leaf-ffi
static DOMAIN_FILTER_CALLBACK: Mutex<Option<DomainFilterCallback>> = Mutex::new(None);
static DOMAIN_FILTER_USER_DATA: Mutex<Option<usize>> = Mutex::new(None);

lazy_static! {
    static ref PENDING_REQUESTS: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<DomainFilterResult>>> = 
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
    if let Some(sender) = pending.remove(&request_id) {
        let _ = sender.send(result);
        true
    } else {
        false
    }
}

/// Implementation of domain filtering check
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
        // Generate unique request ID
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        // Create oneshot channel for response
        let (sender, receiver) = tokio::sync::oneshot::channel();
        
        // Store the sender
        {
            let mut pending = PENDING_REQUESTS.lock().unwrap();
            pending.insert(request_id, sender);
        }
        
        // Convert domain to C string
        let domain_cstr = std::ffi::CString::new(domain).unwrap();
        
        // Call the callback
        trace!("Calling domain filter callback for: {}", domain);
        let user_data_ptr = user_data.map(|addr| addr as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut());
        callback(domain_cstr.as_ptr(), request_id, user_data_ptr);
        
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