use core::ptr;
use std::ffi::CString;

use revoke_test::CertificateDetail;
use rustls_pki_types::CertificateDer;
use upki_ffi::{
    upki_certificate_der, upki_check_revocation, upki_config, upki_config_free, upki_config_new,
    upki_result,
};

use super::{TEST_CONFIG_PATH, TestResult};

pub(super) fn ffi(detail: &CertificateDetail) -> TestResult {
    let certs = [detail.end_entity_cert_der().unwrap()]
        .into_iter()
        .chain(
            detail
                .intermediates_der()
                .collect::<eyre::Result<Vec<CertificateDer<'static>>>>()
                .unwrap(),
        )
        .collect::<Vec<_>>();

    let mut cert_pointers = Vec::new();
    for c in &certs {
        cert_pointers.push(upki_certificate_der {
            data: c.as_ptr(),
            len: c.len(),
        });
    }

    let mut config = OwnedConfig(ptr::null_mut());
    assert!(matches!(
        unsafe {
            upki_config_new(
                CString::new(TEST_CONFIG_PATH)
                    .unwrap()
                    .as_ptr(),
                &mut config.0,
            )
        },
        upki_result::UPKI_OK
    ));
    let rc =
        unsafe { upki_check_revocation(config.0, cert_pointers.as_ptr(), cert_pointers.len()) };

    drop(certs); // extend lifetime for benefit of cert_pointers

    match rc {
        upki_result::UPKI_REVOCATION_REVOKED => TestResult::CorrectlyRevoked,
        upki_result::UPKI_REVOCATION_NOT_COVERED | upki_result::UPKI_REVOCATION_NOT_REVOKED => {
            TestResult::IncorrectlyNotRevoked
        }
        e => panic!("upki_check_revocation() failed with {:?}", e as usize),
    }
}

struct OwnedConfig(*mut upki_config);

impl Drop for OwnedConfig {
    fn drop(&mut self) {
        unsafe { upki_config_free(self.0) };
    }
}
