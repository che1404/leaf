use std::{
    ffi::CStr, 
    os::raw::c_char,
    sync::{Arc, Mutex},
    collections::HashMap,
};

/// Domain filtering callback type.
/// 
/// Parameters:
/// - domain: The domain name to check (null-terminated string)
/// - request_id: Unique ID for this request
/// - user_data: User-provided data passed during callback registration
///
/// The client app should call `leaf_resolve_domain_filter` with the result.
pub type DomainFilterCallback = extern "C" fn(
    domain: *const c_char,
    request_id: u64,
    user_data: *mut std::ffi::c_void,
);

/// Domain filter result
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum DomainFilterResult {
    Allow = 0,
    Deny = 1,
}

/// Global callback registry
static DOMAIN_FILTER_CALLBACK: Mutex<Option<DomainFilterCallback>> = Mutex::new(None);
// Use usize instead of raw pointer to work around Send requirement
static DOMAIN_FILTER_USER_DATA: Mutex<Option<usize>> = Mutex::new(None);

/// Pending domain filter requests
lazy_static::lazy_static! {
    static ref PENDING_REQUESTS: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<DomainFilterResult>>> = 
        Mutex::new(HashMap::new());
}

/// Request ID counter
static REQUEST_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// No error.
pub const ERR_OK: i32 = 0;
/// Config path error.
pub const ERR_CONFIG_PATH: i32 = 1;
/// Config parsing error.
pub const ERR_CONFIG: i32 = 2;
/// IO error.
pub const ERR_IO: i32 = 3;
/// Config file watcher error.
pub const ERR_WATCHER: i32 = 4;
/// Async channel send error.
pub const ERR_ASYNC_CHANNEL_SEND: i32 = 5;
/// Sync channel receive error.
pub const ERR_SYNC_CHANNEL_RECV: i32 = 6;
/// Runtime manager error.
pub const ERR_RUNTIME_MANAGER: i32 = 7;
/// No associated config file.
pub const ERR_NO_CONFIG_FILE: i32 = 8;

fn to_errno(e: leaf::Error) -> i32 {
    match e {
        leaf::Error::Config(..) => ERR_CONFIG,
        leaf::Error::NoConfigFile => ERR_NO_CONFIG_FILE,
        leaf::Error::Io(..) => ERR_IO,
        #[cfg(feature = "auto-reload")]
        leaf::Error::Watcher(..) => ERR_WATCHER,
        leaf::Error::AsyncChannelSend(..) => ERR_ASYNC_CHANNEL_SEND,
        leaf::Error::SyncChannelRecv(..) => ERR_SYNC_CHANNEL_RECV,
        leaf::Error::RuntimeManager => ERR_RUNTIME_MANAGER,
    }
}

/// Starts leaf with options, on a successful start this function blocks the current
/// thread.
///
/// @note This is not a stable API, parameters will change from time to time.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @param auto_reload Enabls auto reloading when config file changes are detected,
///                    takes effect only when the "auto-reload" feature is enabled.
/// @param multi_thread Whether to use a multi-threaded runtime.
/// @param auto_threads Sets the number of runtime worker threads automatically,
///                     takes effect only when multi_thread is true.
/// @param threads Sets the number of runtime worker threads, takes effect when
///                     multi_thread is true, but can be overridden by auto_threads.
/// @param stack_size Sets stack size of the runtime worker threads, takes effect when
///                   multi_thread is true.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn leaf_run_with_options(
    rt_id: u16,
    config_path: *const c_char,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::util::run_with_options(
            rt_id,
            config_path.to_string(),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            multi_thread,
            auto_threads,
            threads as usize,
            stack_size as usize,
        ) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Starts leaf with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub extern "C" fn leaf_run(rt_id: u16, config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::File(config_path.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

#[no_mangle]
pub extern "C" fn leaf_run_with_config_string(rt_id: u16, config: *const c_char) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::Str(config.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns ERR_OK on success.
#[no_mangle]
pub extern "C" fn leaf_reload(rt_id: u16) -> i32 {
    if let Err(e) = leaf::reload(rt_id) {
        return to_errno(e);
    }
    ERR_OK
}

/// Shuts down leaf.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns true on success, false otherwise.
#[no_mangle]
pub extern "C" fn leaf_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub extern "C" fn leaf_test_config(config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::test_config(config_path) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Registers a domain filtering callback.
///
/// @param callback The callback function to call for domain filtering decisions
/// @param user_data User data to pass to the callback
/// @return ERR_OK on success
#[no_mangle]
pub extern "C" fn leaf_register_domain_filter_callback(
    callback: DomainFilterCallback,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    {
        let mut cb = DOMAIN_FILTER_CALLBACK.lock().unwrap();
        *cb = Some(callback);
    }
    {
        let mut data = DOMAIN_FILTER_USER_DATA.lock().unwrap();
        *data = Some(user_data as usize);
    }
    
    // Also register in the leaf core module
    leaf::app::domain_filter::register_callback(callback, user_data);
    
    ERR_OK
}

/// Resolves a domain filtering request with the result.
///
/// @param request_id The request ID from the callback
/// @param result The filtering decision (Allow or Deny)
/// @return ERR_OK on success
#[no_mangle]
pub extern "C" fn leaf_resolve_domain_filter(
    request_id: u64,
    result: DomainFilterResult,
) -> i32 {
    // Convert FFI enum to leaf enum
    let leaf_result = match result {
        DomainFilterResult::Allow => leaf::DomainFilterResult::Allow,
        DomainFilterResult::Deny => leaf::DomainFilterResult::Deny,
    };
    
    // Try to resolve in both locations
    let resolved_in_ffi = {
        let mut pending = PENDING_REQUESTS.lock().unwrap();
        if let Some(sender) = pending.remove(&request_id) {
            let _ = sender.send(result);
            true
        } else {
            false
        }
    };
    
    let resolved_in_leaf = leaf::app::domain_filter::resolve_request(request_id, leaf_result);
    
    if resolved_in_ffi || resolved_in_leaf {
        ERR_OK
    } else {
        ERR_IO // Request not found
    }
}

/// Checks if a domain should be allowed or denied.
/// This function will call the registered callback and wait for the result.
///
/// @param domain The domain name to check
/// @return The filtering result
pub async fn check_domain_filter(domain: &str) -> DomainFilterResult {
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
        let user_data_ptr = user_data.map(|addr| addr as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut());
        callback(domain_cstr.as_ptr(), request_id, user_data_ptr);
        
        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await {
            Ok(Ok(result)) => result,
            _ => {
                // Timeout or error - cleanup and default to Allow
                let mut pending = PENDING_REQUESTS.lock().unwrap();
                pending.remove(&request_id);
                DomainFilterResult::Allow
            }
        }
    } else {
        // No callback registered - default to Allow
        DomainFilterResult::Allow
    }
}
