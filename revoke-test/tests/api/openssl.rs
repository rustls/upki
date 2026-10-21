use core::ffi::{c_int, c_long, c_void};
use core::{mem, ptr};
use std::ffi::{CStr, CString};

use openssl_sys::{
    ERR_GET_REASON, ERR_clear_error, ERR_get_error, ERR_lib_error_string, OPENSSL_STACK,
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, SSL, SSL_CTX, SSL_CTX_free, SSL_CTX_new,
    SSL_free, SSL_get_ex_data_X509_STORE_CTX_idx, SSL_new, TLS_client_method, X509_STORE_CTX,
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_new, X509_STORE_CTX_set_error,
    X509_V_ERR_CERT_REVOKED, d2i_X509, stack_st_X509,
};
use revoke_test::CertificateDetail;
use upki::ffi::{upki_config_new, upki_result};
use upki_openssl::{upki_openssl_set_config, upki_openssl_verify_callback};

use super::TestResult;

pub(super) fn openssl(detail: &CertificateDetail, config_path: &str) -> TestResult {
    let (rc, error) = verify(detail, config_path);

    match (rc, upki_error_reason()) {
        (1, _) => TestResult::IncorrectlyNotRevoked,
        (0, Some(reason))
            if error == X509_V_ERR_CERT_REVOKED
                && reason == upki_result::UPKI_ERR_REVOCATION_COMPROMISED_KEY as c_int =>
        {
            TestResult::CompromisedKey
        }
        (0, None) if error == X509_V_ERR_CERT_REVOKED => TestResult::CorrectlyRevoked,
        _ => panic!("upki_openssl_verify_callback failed with rc={rc:?} store_ctx.error={error:?}"),
    }
}

pub(super) fn verify(detail: &CertificateDetail, config_path: &str) -> (c_int, c_int) {
    // Ensure any errors found by `upki_error_reason` came from this call.
    unsafe { ERR_clear_error() };

    let mut chain = Chain::new();

    for cert in [detail.end_entity_cert_der().unwrap()]
        .into_iter()
        .chain(
            detail
                .intermediates_der()
                .collect::<eyre::Result<Vec<_>>>()
                .unwrap(),
        )
    {
        chain.push(&cert);
    }

    let mut config = ptr::null_mut();
    assert!(matches!(
        unsafe {
            upki_config_new(
                CString::new(config_path)
                    .unwrap()
                    .as_ptr(),
                &mut config,
            )
        },
        upki_result::UPKI_OK
    ));

    let ssl_ctx = SslCtx::new();
    unsafe { upki_openssl_set_config(ssl_ctx.0, config) };

    let ssl = ssl_ctx.new_ssl();

    let mut store_ctx = StoreCtx::new();
    store_ctx.attach_ssl(ssl);
    store_ctx.set_error_depth(0);
    store_ctx.set_error(UNTOUCHED_ERROR);
    store_ctx.set_verified_chain(chain);

    let rc = unsafe { upki_openssl_verify_callback(1, store_ctx.ptr) };
    (rc, store_ctx.error())
}

pub(super) const UNTOUCHED_ERROR: c_int = 12345678;

/// Drain this thread's OpenSSL error stack, returning the reason code of the last
/// error reported by upki (which is a `upki_result` value).
fn upki_error_reason() -> Option<c_int> {
    let mut reason = None;
    loop {
        let err = unsafe { ERR_get_error() };
        if err == 0 {
            return reason;
        }

        let lib = unsafe { ERR_lib_error_string(err) };
        if !lib.is_null() && unsafe { CStr::from_ptr(lib) } == c"upki" {
            reason = Some(ERR_GET_REASON(err));
        }
    }
}

struct SslCtx(*mut SSL_CTX);

impl SslCtx {
    fn new() -> Self {
        Self(unsafe { SSL_CTX_new(TLS_client_method()) })
    }

    fn new_ssl(&self) -> Ssl {
        Ssl(unsafe { SSL_new(self.0) })
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { SSL_CTX_free(self.0) };
    }
}

struct Ssl(*mut SSL);

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { SSL_free(self.0) };
    }
}

struct StoreCtx {
    ptr: *mut X509_STORE_CTX,
    attached_ssl: Option<Ssl>,
}

impl StoreCtx {
    fn new() -> Self {
        Self {
            ptr: unsafe { X509_STORE_CTX_new() },
            attached_ssl: None,
        }
    }

    fn error(&self) -> c_int {
        unsafe { X509_STORE_CTX_get_error(self.ptr) }
    }

    fn set_error(&mut self, error: c_int) {
        unsafe { X509_STORE_CTX_set_error(self.ptr, error) };
    }

    fn set_error_depth(&mut self, depth: i32) {
        unsafe { X509_STORE_CTX_set_error_depth(self.ptr, depth) };
    }

    fn set_verified_chain(&mut self, mut chain: Chain) {
        unsafe { X509_STORE_CTX_set0_verified_chain(self.ptr, chain.steal()) };
    }

    fn attach_ssl(&mut self, ssl: Ssl) {
        unsafe {
            X509_STORE_CTX_set_ex_data(self.ptr, SSL_get_ex_data_X509_STORE_CTX_idx(), ssl.0.cast())
        };
        self.attached_ssl = Some(ssl);
    }
}

impl Drop for StoreCtx {
    fn drop(&mut self) {
        unsafe { X509_STORE_CTX_free(self.ptr) }
    }
}

struct Chain(*mut stack_st_X509);

impl Chain {
    fn new() -> Self {
        Self(unsafe { OPENSSL_sk_new_null() as *mut stack_st_X509 })
    }

    fn push(&mut self, der_bytes: &[u8]) {
        unsafe {
            let mut ptr = der_bytes.as_ptr();
            let x509 = d2i_X509(ptr::null_mut(), &mut ptr, der_bytes.len() as c_long);
            assert!(!x509.is_null());
            OPENSSL_sk_push(self.0 as *mut OPENSSL_STACK, x509 as *mut c_void);
        }
    }

    fn steal(&mut self) -> *mut stack_st_X509 {
        mem::replace(&mut self.0, ptr::null_mut())
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        unsafe { OPENSSL_sk_free(self.0 as *mut OPENSSL_STACK) }
    }
}

unsafe extern "C" {
    fn X509_STORE_CTX_set_error_depth(ctx: *mut X509_STORE_CTX, depth: c_int);
    fn X509_STORE_CTX_set0_verified_chain(ctx: *mut X509_STORE_CTX, chain: *mut stack_st_X509);
    fn X509_STORE_CTX_set_ex_data(ctx: *mut X509_STORE_CTX, idx: c_int, ptr: *mut c_void);
}
