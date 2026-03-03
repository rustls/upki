#![allow(clippy::undocumented_unsafe_blocks)]

use core::{mem, ptr};
use std::os::raw::c_int;

use openssl_sys::{
    OPENSSL_STACK, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, SSL_CTX_free,
    SSL_CTX_new, TLS_client_method, X509_STORE_CTX, X509_STORE_CTX_free, X509_STORE_CTX_get_error,
    X509_STORE_CTX_new, X509_STORE_CTX_set_error, X509_V_ERR_APPLICATION_VERIFICATION,
    stack_st_X509,
};
use upki::ffi::upki_config_new;

use super::upki_openssl_verify_callback;
use crate::upki_openssl_set_config;

#[test]
fn preverify_zero_returns_zero() {
    assert_eq!(
        unsafe { upki_openssl_verify_callback(0, ptr::null_mut()) },
        0
    );
}

#[test]
fn null_ctx_returns_zero() {
    assert_eq!(
        unsafe { upki_openssl_verify_callback(1, ptr::null_mut()) },
        0
    );
}

#[test]
fn preverify_ok_zero_valid_ctx_returns_zero() {
    let ctx = StoreCtx::new();
    assert_eq!(unsafe { upki_openssl_verify_callback(0, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn preverify_ok_zero_nonzero_depth_returns_zero() {
    let mut ctx = StoreCtx::new();
    ctx.set_error_depth(3);

    assert_eq!(unsafe { upki_openssl_verify_callback(0, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn error_depth_various_nonzero_all_pass_through() {
    for depth in [-1, 1, 3, 5, 10, 100] {
        let mut ctx = StoreCtx::new();
        ctx.set_error_depth(depth);

        assert_eq!(
            unsafe { upki_openssl_verify_callback(1, ctx.0) },
            1,
            "expected preverify_ok pass-through at error_depth={depth}"
        );
        assert!(ctx.untouched_error());
    }
}

#[test]
fn error_depth_nonzero_preserves_arbitrary_preverify_ok_value() {
    for (depth, pv) in [(1, 2), (2, 42), (5, -1), (10, 100)] {
        let mut ctx = StoreCtx::new();
        ctx.set_error_depth(depth);

        assert_eq!(
            unsafe { upki_openssl_verify_callback(pv, ctx.0) },
            pv,
            "preverify_ok={pv} should be returned unchanged at error_depth={depth}"
        );
        assert!(ctx.untouched_error());
    }
}

#[test]
fn missing_chain_returns_zero() {
    let ctx = StoreCtx::new();
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn empty_chain_reports_error() {
    let mut ctx = StoreCtx::new();
    ctx.set_verified_chain(Chain::new());
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert_eq!(ctx.error(), X509_V_ERR_APPLICATION_VERIFICATION);
}

#[test]
fn malformed_chain_returns_zero() {
    let mut chain = Chain::new();
    chain.push_null();
    let mut ctx = StoreCtx::new();
    ctx.set_verified_chain(chain);
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn set_config_twice() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let mut config = ptr::null_mut();

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config);

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config);

        SSL_CTX_free(ctx);
    }
}

#[test]
fn set_config_is_freed() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let mut config = ptr::null_mut();

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config); // takes ownership.

        // frees config for us.
        SSL_CTX_free(ctx);
    }
}

struct StoreCtx(*mut X509_STORE_CTX);

impl StoreCtx {
    fn new() -> Self {
        let mut v = Self(unsafe { X509_STORE_CTX_new() });
        // we set a placeholder error here, which is intended to be unused
        // anywhere else, and allows detection of whether the error has been
        // set or preserved.
        assert!(!v.untouched_error());
        v.set_error(UNTOUCHED_ERROR);
        assert!(v.untouched_error());
        v
    }

    fn set_error_depth(&mut self, depth: i32) {
        unsafe { X509_STORE_CTX_set_error_depth(self.0, depth) };
    }

    fn error(&self) -> c_int {
        unsafe { X509_STORE_CTX_get_error(self.0) }
    }

    fn untouched_error(&self) -> bool {
        self.error() == UNTOUCHED_ERROR
    }

    fn set_error(&mut self, e: c_int) {
        unsafe { X509_STORE_CTX_set_error(self.0, e) }
    }

    fn set_verified_chain(&mut self, mut chain: Chain) {
        unsafe { X509_STORE_CTX_set0_verified_chain(self.0, chain.steal()) };
    }
}

impl Drop for StoreCtx {
    fn drop(&mut self) {
        unsafe { X509_STORE_CTX_free(self.0) }
    }
}

struct Chain(*mut stack_st_X509);

impl Chain {
    fn new() -> Self {
        Self(unsafe { OPENSSL_sk_new_null() as *mut stack_st_X509 })
    }

    fn push_null(&mut self) {
        unsafe { OPENSSL_sk_push(self.0 as *mut OPENSSL_STACK, ptr::null()) };
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

const UNTOUCHED_ERROR: c_int = 12345678;

unsafe extern "C" {
    fn X509_STORE_CTX_set_error_depth(ctx: *mut X509_STORE_CTX, depth: c_int);
    fn X509_STORE_CTX_set0_verified_chain(ctx: *mut X509_STORE_CTX, chain: *mut stack_st_X509);
}
