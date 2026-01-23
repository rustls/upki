#![crate_type = "staticlib"]
#![allow(non_camel_case_types)]

use core::ffi::c_char;
use std::ffi::CStr;
use std::path::Path;
use std::slice;

use upki::Config;
use upki::revocation::{
    CertSerial, CtTimestamp, IssuerSpkiHash, Manifest, RevocationCheckInput, RevocationStatus,
};

/// Check the revocation status of a certificate.
///
/// Returns a `upki_result` indicating success (with revocation status) or an error.
///
/// # Safety
///
/// - `config` must be a valid pointer returned by `upki_config_new`.
/// - `serial_ptr` must point to `serial_len` bytes.
/// - `issuer_spki_hash` must point to exactly 32 bytes.
/// - `ct_timestamps` must point to `ct_timestamps_len` `upki_ct_timestamp` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_check_revocation(
    config: *const upki_config,
    serial_ptr: *const u8,
    serial_len: usize,
    issuer_spki_hash: *const u8,
    ct_timestamps: *const upki_ct_timestamp,
    ct_timestamps_len: usize,
) -> upki_result {
    if config.is_null()
        || serial_ptr.is_null()
        || issuer_spki_hash.is_null()
        || ct_timestamps.is_null()
    {
        return upki_result::UPKI_ERR_NULL_POINTER;
    }

    let config = unsafe { &(*config).0 };
    let serial = unsafe { slice::from_raw_parts(serial_ptr, serial_len) };
    let issuer_spki_hash = unsafe { &*issuer_spki_hash.cast::<[u8; 32]>() };
    let ct_timestamps = unsafe { slice::from_raw_parts(ct_timestamps, ct_timestamps_len) };

    let Ok(manifest) = Manifest::from_config(config) else {
        return upki_result::UPKI_ERR_MANIFEST;
    };

    let input = RevocationCheckInput {
        cert_serial: CertSerial(serial.to_vec()),
        issuer_spki_hash: IssuerSpkiHash(*issuer_spki_hash),
        sct_timestamps: ct_timestamps
            .iter()
            .map(|ts| CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp,
            })
            .collect(),
    };

    match manifest.check(&input, config) {
        Ok(status) => match status {
            RevocationStatus::NotCoveredByRevocationData => {
                upki_result::UPKI_REVOCATION_NOT_COVERED
            }
            RevocationStatus::CertainlyRevoked => upki_result::UPKI_REVOCATION_REVOKED,
            RevocationStatus::NotRevoked => upki_result::UPKI_REVOCATION_NOT_REVOKED,
        },
        Err(_) => upki_result::UPKI_ERR_REVOCATION_CHECK,
    }
}

/// Opaque type representing a `upki::Config`.
pub struct upki_config(Config);

/// Create a new `upki_config` by loading it from the file at `path`.
///
/// On success, writes the config pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the config with `upki_config_free`.
///
/// # Safety
///
/// - `out` must be a valid pointer to a `*mut upki_config`.
/// - `path` must be a valid pointer to a null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_from_file(
    path: *const c_char,
    out: *mut *mut upki_config,
) -> upki_result {
    if path.is_null() || out.is_null() {
        return upki_result::UPKI_ERR_NULL_POINTER;
    }

    let path = unsafe { CStr::from_ptr(path) };
    let Ok(path) = path.to_str() else {
        return upki_result::UPKI_ERR_CONFIG_PATH;
    };

    match Config::from_file(Path::new(path)) {
        Ok(config) => {
            unsafe { *out = Box::into_raw(Box::new(upki_config(config))) };
            upki_result::UPKI_OK
        }
        Err(_) => upki_result::UPKI_ERR_CONFIG_FILE,
    }
}

/// Create a new `upki_config` with default settings.
///
/// On success, writes the config pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the config with `upki_config_free`.
///
/// # Safety
///
/// `out` must be a valid pointer to a `*mut upki_config`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_new(out: *mut *mut upki_config) -> upki_result {
    if out.is_null() {
        return upki_result::UPKI_ERR_NULL_POINTER;
    }

    match Config::try_default() {
        Ok(config) => {
            unsafe { *out = Box::into_raw(Box::new(upki_config(config))) };
            upki_result::UPKI_OK
        }
        Err(_) => upki_result::UPKI_ERR_PLATFORM,
    }
}

/// Free a `upki_config` created by `upki_config_new`.
///
/// # Safety
///
/// `config` must be a valid pointer returned by `upki_config_new`,
/// or null (in which case this is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_free(config: *mut upki_config) {
    if !config.is_null() {
        drop(unsafe { Box::from_raw(config) });
    }
}

/// A certificate transparency timestamp.
#[repr(C)]
pub struct upki_ct_timestamp {
    /// CT log ID (32 bytes).
    pub log_id: [u8; 32],
    /// Issuance timestamp.
    pub timestamp: u64,
}

/// Result type for upki C API functions.
///
/// Values 0-15 indicate success (with specific status information).
/// Values 16 and above indicate errors.
#[repr(C)]
pub enum upki_result {
    /// Operation succeeded.
    UPKI_OK = 0,
    /// The certificate is not covered by the revocation data.
    UPKI_REVOCATION_NOT_COVERED = 1,
    /// The certificate has been revoked.
    UPKI_REVOCATION_REVOKED = 2,
    /// The certificate is not revoked.
    UPKI_REVOCATION_NOT_REVOKED = 3,

    /// A null pointer was passed where a valid pointer was required.
    UPKI_ERR_NULL_POINTER = 16,
    /// Failed to determine platform-specific default directories.
    UPKI_ERR_PLATFORM = 17,
    /// Failed to load the revocation manifest.
    UPKI_ERR_MANIFEST = 18,
    /// Failed to perform the revocation check.
    UPKI_ERR_REVOCATION_CHECK = 19,
    /// The config path is not valid UTF-8.
    UPKI_ERR_CONFIG_PATH = 20,
    /// Failed to load the config file.
    UPKI_ERR_CONFIG_FILE = 21,
}
