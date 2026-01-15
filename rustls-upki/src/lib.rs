#![doc = include_str!("../../README.md")]
#![warn(missing_docs)]

use core::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::hash::{Hash, HashAlgorithm};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertRevocationListError, CertificateError, DigitallySignedStruct, DistinguishedName,
    ExtendedKeyPurpose, RootCertStore, SignatureScheme, SupportedCipherSuite,
};
use upki::revocation::{
    CertSerial, CtTimestamp, IssuerSpkiHash, Manifest, RevocationCheckInput, RevocationStatus,
};
use upki::{self, Config, ConfigPath};
use webpki::{EndEntityCert, ExtendedKeyUsage, InvalidNameContext, VerifiedPath};

/// A [`ServerCertVerifier`] that uses upki to check revocation status of server certificates.
pub struct ServerVerifier {
    provider: Arc<CryptoProvider>,
    sha256: &'static dyn Hash,
    roots: Arc<RootCertStore>,
    config: Config,
    policy: Policy,
}

impl ServerVerifier {
    /// Make a verifier that checks revocation status using upki.
    ///
    /// This first verifies the certificate using the `webpki` crate, against the supplied `roots`.
    /// This uses cryptography specified in `provider`.
    ///
    /// `config_path` points to where the upki configuration file can be found -- if it is
    /// [`None`] then it is searched for in usual places.  The configuration file is read and kept
    /// in memory during this construction, so later changes to it will not be respected.
    ///
    /// A certificate which is acceptable in the normal way, issued by one of the `roots` and
    /// valid for the given server name, is then checked for revocation.  `policy` controls
    /// whether failures in this process are hard errors.
    pub fn new(
        policy: Policy,
        config_path: Option<PathBuf>,
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, rustls::Error> {
        let sha256 = provider
            .cipher_suites
            .iter()
            .find_map(|scs| {
                let hash = match scs {
                    SupportedCipherSuite::Tls12(tls12) => tls12.common.hash_provider,
                    SupportedCipherSuite::Tls13(tls13) => tls13.common.hash_provider,
                };

                match hash.algorithm() {
                    HashAlgorithm::SHA256 => Some(hash),
                    _ => None,
                }
            })
            .expect("no cipher suites supported with SHA256");

        // TODO: Pre-roll storage to check it works, and bring (eg permanant configuration) errors
        // to forefront prior to any networking happens.
        let config = ConfigPath::new(config_path)
            .and_then(|path| Config::from_file_or_default(&path))
            .map_err(|report| rustls::Error::General(report.to_string()))?;

        Ok(Self {
            provider,
            sha256,
            roots,
            config,
            policy,
        })
    }

    /// Determine the revocation status of `ee`.
    ///
    /// This should have been determined to be issued by a trusted root.  `verified_path`
    /// proves this.
    ///
    /// This returns errors only for hard failure cases.
    fn check_revocation_status(
        &self,
        verified_path: &VerifiedPath<'_>,
    ) -> Result<RevocationStatus, rustls::Error> {
        let issuer_spki = verified_path.issuer_spki();
        let issuer_spki_hash = self.sha256.hash(&issuer_spki);
        let issuer_spki_hash = issuer_spki_hash
            .as_ref()
            .try_into()
            .expect("sha256 must have a 32-byte output");

        let mut sct_timestamps = vec![];
        let sct_iter = verified_path
            .end_entity()
            .sct_log_timestamps();
        for ts in sct_iter.map_err(sct_error)? {
            let ts = ts.map_err(sct_error)?;
            sct_timestamps.push(CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp_ms,
            });
        }

        // Lacking SCTs means we cannot check revocation, and the certificate
        // probably is not publicly trusted anyway.
        if sct_timestamps.is_empty() {
            return self.policy.cert_has_no_scts.as_result();
        }

        let input = RevocationCheckInput {
            cert_serial: CertSerial(
                verified_path
                    .end_entity()
                    .serial()
                    .to_vec(),
            ),
            issuer_spki_hash: IssuerSpkiHash(issuer_spki_hash),
            sct_timestamps,
        };

        match Manifest::from_config(&self.config)
            .and_then(|manifest| manifest.check(&input, &self.config))
        {
            Ok(rs) => Ok(rs),
            Err(e) => Err(rustls::Error::General(e.to_string())),
        }
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ee = EndEntityCert::try_from(end_entity).map_err(webpki_error)?;

        let verified_path = ee
            .verify_for_usage(
                self.provider
                    .signature_verification_algorithms
                    .all,
                &self.roots.roots,
                intermediates,
                now,
                &ExtendedKeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(webpki_error)?;

        ee.verify_is_valid_for_subject_name(server_name)
            .map_err(webpki_error)?;

        match self.check_revocation_status(&verified_path)? {
            RevocationStatus::NotRevoked => Ok(ServerCertVerified::assertion()),
            RevocationStatus::NotCoveredByRevocationData => self
                .policy
                .cert_not_covered
                .as_result()
                .map(|_| ServerCertVerified::assertion()),
            RevocationStatus::CertainlyRevoked => Err(CertificateError::Revoked.into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

impl fmt::Debug for ServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            provider,
            roots,
            policy,
            sha256: _,
            config,
        } = self;

        f.debug_struct("ServerVerifier")
            .field("provider", &provider)
            .field("roots", &roots)
            .field("config", &config)
            .field("policy", &policy)
            .finish_non_exhaustive()
    }
}

/// Controls the error behavior of this crate.
#[derive(Debug)]
pub struct Policy {
    /// What to do if upki filter data is missing
    pub missing_data: Outcome,

    /// What to do if upki filter data does not cover a certificate
    ///
    /// A certificate can be not covered by the crlite filter if:
    ///
    /// - the data is out of date, perhaps because it has not been fetched recently.
    /// - the data does not cover the certificate, because the backend processing does not cover
    ///   it (at the time of writing, this is the case for some certifcates).
    pub cert_not_covered: Outcome,

    /// What to do if certificate was not logged in CT
    pub cert_has_no_scts: Outcome,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            missing_data: Outcome::Error(rustls::Error::General("upki data is missing".into())),
            cert_not_covered: Outcome::Allowed,
            cert_has_no_scts: Outcome::Allowed,
        }
    }
}

/// For a given item in a [`Policy`], controls what the outcome is.
#[derive(Debug)]
pub enum Outcome {
    /// It's not an error.
    Allowed,

    /// The certificate is treated as revoked.
    TreatAsRevoked,

    /// The given error is returned.
    Error(rustls::Error),
}

impl Outcome {
    fn as_result(&self) -> Result<RevocationStatus, rustls::Error> {
        match self {
            Self::Allowed => Ok(RevocationStatus::NotCoveredByRevocationData),
            Self::TreatAsRevoked => Err(CertificateError::Revoked.into()),
            Self::Error(err) => Err(err.clone()),
        }
    }
}

fn sct_error(error: webpki::sct::Error) -> rustls::Error {
    let message = match error {
        webpki::sct::Error::MalformedSct => "malformed sct",
        webpki::sct::Error::UnsupportedSctVersion => "unsupported sct version",
        _ => "unknown sct error",
    };

    rustls::Error::General(message.into())
}

fn webpki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName(InvalidNameContext {
            expected,
            presented,
        }) => CertificateError::NotValidForNameContext {
            expected,
            presented,
        }
        .into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        UnsupportedSignatureAlgorithm(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedSignatureAlgorithmForPublicKey(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        UnsupportedCrlSignatureAlgorithm(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedCrlSignatureAlgorithmForPublicKey(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        RequiredEkuNotFound(webpki::RequiredEkuNotFoundContext { required, present }) => {
            rustls::Error::from(CertificateError::InvalidPurposeContext {
                required: ekp_for_values(required.oid_values()),
                presented: present
                    .into_iter()
                    .map(|eku| ekp_for_values(eku.into_iter()))
                    .collect(),
            })
        }

        _ => CertificateError::Other(rustls::OtherError(Arc::new(error))).into(),
    }
}

pub(crate) fn ekp_for_values(values: impl Iterator<Item = usize>) -> ExtendedKeyPurpose {
    let values = values.collect::<Vec<_>>();
    match &*values {
        ExtendedKeyUsage::CLIENT_AUTH_REPR => ExtendedKeyPurpose::ClientAuth,
        ExtendedKeyUsage::SERVER_AUTH_REPR => ExtendedKeyPurpose::ServerAuth,
        _ => ExtendedKeyPurpose::Other(values),
    }
}
