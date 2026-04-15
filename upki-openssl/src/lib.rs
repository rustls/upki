#![warn(clippy::undocumented_unsafe_blocks)]

use core::ptr;
use std::os::raw::c_int;
use std::slice;

use openssl_sys::{
    OPENSSL_free, OPENSSL_sk_num, OPENSSL_sk_value, X509, X509_STORE_CTX,
    X509_STORE_CTX_get0_chain, X509_STORE_CTX_set_error, X509_V_ERR_APPLICATION_VERIFICATION,
    X509_V_ERR_CERT_REVOKED, i2d_X509, stack_st_X509,
};
use rustls_pki_types::CertificateDer;
use upki::Error;
use upki::revocation::{Manifest, RevocationCheckInput, RevocationStatus};

/// This is a function matching OpenSSL's `SSL_verify_cb` type which does
/// revocation checking using upki.
///
/// The configuration file and data location is found automatically.
///
/// # Safety
/// This function is called by OpenSSL typically, and its correct operation
/// hinges almost entirely on being called properly.  For example, that
/// `x509_ctx` is a valid pointer, or NULL.
///
/// On unexpected/unrecoverable errors, this function returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_verify_callback(
    mut preverify_ok: c_int,
    x509_ctx: *mut X509_STORE_CTX,
) -> c_int {
    // Revocation checking never improves the situation if the verification has failed.
    if preverify_ok == 0 {
        return preverify_ok;
    }

    // SAFETY: via essential and established principles of the C type system, we rely on
    // OpenSSL to call this function with a `x509_ctx` that points to a valid value, or
    // exceptionally is NULL.
    let Some(mut x509_ctx) = (unsafe { BorrowedX509StoreCtx::from_ptr(x509_ctx) }) else {
        return 0;
    };

    let Some(chain) = x509_ctx.chain() else {
        return 0;
    };

    let Some(certs) = chain.copy_certs() else {
        return 0;
    };

    match revocation_check(&certs) {
        Ok(RevocationStatus::CertainlyRevoked) => {
            x509_ctx.set_error(X509_V_ERR_CERT_REVOKED);
            preverify_ok = 0;
        }
        Ok(RevocationStatus::NotCoveredByRevocationData | RevocationStatus::NotRevoked) => {}
        Err(_e) => {
            x509_ctx.set_error(X509_V_ERR_APPLICATION_VERIFICATION);
            preverify_ok = 0;
        }
    }

    preverify_ok
}

fn revocation_check(certs: &[CertificateDer<'_>]) -> Result<RevocationStatus, Error> {
    let path = upki::ConfigPath::new(None)?;
    let config = upki::Config::from_file_or_default(&path)?;
    let manifest = Manifest::from_config(&config)?;
    let input = RevocationCheckInput::from_certificates(certs)?;
    match manifest.check(&input, &config) {
        Ok(st) => Ok(st),
        Err(e) => Err(Error::Revocation(e)),
    }
}

struct BorrowedX509StoreCtx<'a>(&'a mut X509_STORE_CTX);

impl<'a> BorrowedX509StoreCtx<'a> {
    unsafe fn from_ptr(ptr: *mut X509_STORE_CTX) -> Option<Self> {
        // SAFETY: we pass up the requirements of `ptr::as_mut()` to our caller
        unsafe { ptr.as_mut() }.map(Self)
    }

    fn chain(&self) -> Option<BorrowedX509Stack<'a>> {
        // SAFETY: X509_STORE_CTX_get0_chain has no published documentation saying when it is
        // safe to call.  This type guarantees that the pointer is of the correct type, alignment, etc,
        // and is non-NULL.
        let chain = unsafe { X509_STORE_CTX_get0_chain(ptr::from_ref(self.0)) };

        // SAFETY: we require that openssl correctly returns a valid pointer, or NULL.
        unsafe { chain.as_ref() }.map(BorrowedX509Stack)
    }

    fn set_error(&mut self, err: i32) {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        // OpenSSL does not document any other preconditions.
        unsafe { X509_STORE_CTX_set_error(ptr::from_mut(self.0), err) };
    }
}

struct BorrowedX509Stack<'a>(&'a stack_st_X509);

impl<'a> BorrowedX509Stack<'a> {
    fn copy_certs(&self) -> Option<Vec<CertificateDer<'static>>> {
        // SAFETY: the stack pointer is valid, thanks to it being from a reference.
        let count = unsafe { OPENSSL_sk_num(ptr::from_ref(self.0).cast()) };
        if count < 0 {
            return None;
        }

        let mut certs = vec![];
        for i in 0..count {
            // SAFETY: the stack pointer is valid, thanks to it being from a reference.  `OPENSSL_sk_value` returns
            // a valid pointer to the item or NULL.
            let x509: *const X509 =
                unsafe { OPENSSL_sk_value(ptr::from_ref(self.0).cast(), i).cast() };

            // SAFETY: we require OpenSSL only fills the stack with valid pointers to X509 objects (or NULL)
            let x509 = unsafe { x509.as_ref() }?;
            certs.push(x509_to_certificate_der(x509));
        }

        Some(certs)
    }
}

fn x509_to_certificate_der(x509: &'_ X509) -> CertificateDer<'static> {
    // SAFETY: the x509 pointer is valid, thanks to it coming from a reference.
    let (ptr, len) = unsafe {
        let mut ptr = ptr::null_mut();
        let len = i2d_X509(ptr::from_ref(x509), &mut ptr);
        (ptr, len)
    };

    if len <= 0 {
        return vec![].into();
    }
    let len = len as usize;

    let mut v = Vec::with_capacity(len);
    // SAFETY: we rely on i2d_X509 allocating `ptr` correctly and signalling an error via negative `len` if not.
    // `ptr` must be an allocated pointer.
    unsafe {
        v.extend_from_slice(slice::from_raw_parts(ptr, len));
        OPENSSL_free(ptr as *mut _);
    }
    v.into()
}
