use core::ptr;
use std::os::raw::c_int;
use std::slice;

use openssl_sys::{
    OPENSSL_free, OPENSSL_sk_num, OPENSSL_sk_value, X509, X509_STORE_CTX,
    X509_STORE_CTX_get0_chain, X509_STORE_CTX_set_error, X509_V_ERR_APPLICATION_VERIFICATION,
    X509_V_ERR_CERT_REVOKED, i2d_X509,
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
/// Not very.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_verify_callback(
    mut preverify_ok: c_int,
    x509_ctx: *mut X509_STORE_CTX,
) -> c_int {
    // Revocation checking never improves the situation if the verification has failed.
    if preverify_ok == 0 {
        return preverify_ok;
    }

    let mut certs = vec![];
    let chain = unsafe { X509_STORE_CTX_get0_chain(x509_ctx) };
    let chain_count = unsafe { OPENSSL_sk_num(chain.cast()) };

    for i in 0..chain_count {
        let x509: *const X509 = unsafe { OPENSSL_sk_value(chain.cast(), i).cast() };
        certs.push(x509_to_certificate_der(x509));
    }

    match revocation_check(&certs) {
        Ok(RevocationStatus::CertainlyRevoked) => {
            unsafe { X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED) };
            preverify_ok = 0;
        }
        Ok(RevocationStatus::NotCoveredByRevocationData | RevocationStatus::NotRevoked) => {}
        Err(_e) => {
            unsafe { X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION) };
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

fn x509_to_certificate_der(x509: *const X509) -> CertificateDer<'static> {
    let (ptr, len) = unsafe {
        let mut ptr = ptr::null_mut();
        let len = i2d_X509(x509, &mut ptr);
        (ptr, len)
    };

    if len <= 0 {
        return vec![].into();
    }
    let len = len as usize;

    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(unsafe { slice::from_raw_parts(ptr, len) });

    unsafe { OPENSSL_free(ptr as *mut _) };
    v.into()
}
