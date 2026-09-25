use std::{
    ffi::CStr,
    io,
    ptr::{self, NonNull},
    sync::Arc,
};

use anyhow::Result;
use aws_lc_sys as ffi;
use rustls::{
    CertificateError, ClientConfig, ConfigBuilder, DigitallySignedStruct, Error, OtherError,
    SignatureScheme,
    client::{
        WantsClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use crate::config::pem;

pub(crate) fn builder(
    bundle: Option<&str>,
) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = match bundle {
        Some(bundle) => Arc::new(Verifier::new(&pem(bundle)?, provider.clone())?),
        None => Arc::new(rustls_platform_verifier::Verifier::new(provider.clone())?),
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier))
}

struct Owned<T> {
    pointer: NonNull<T>,
    free: unsafe extern "C" fn(*mut T),
}

impl<T> Owned<T> {
    unsafe fn new(pointer: *mut T, free: unsafe extern "C" fn(*mut T)) -> Result<Self, Error> {
        Ok(Self {
            pointer: NonNull::new(pointer).ok_or_else(failure)?,
            free,
        })
    }

    fn as_ptr(&self) -> *mut T {
        self.pointer.as_ptr()
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe { (self.free)(self.as_ptr()) }
    }
}

struct Verifier {
    store: Owned<ffi::X509_STORE>,
    provider: Arc<CryptoProvider>,
}

// AWS-LC shares stores across concurrent verifications; parameters live in each context.
unsafe impl Send for Verifier {}
unsafe impl Sync for Verifier {}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl Verifier {
    fn new(mut bundle: &[u8], provider: Arc<CryptoProvider>) -> Result<Self> {
        ffi::init();
        let store = unsafe { Owned::new(ffi::X509_STORE_new(), ffi::X509_STORE_free)? };
        for certificate in rustls_native_certs::load_native_certs().certs {
            if let Ok(certificate) = parse(&certificate) {
                check(unsafe { ffi::X509_STORE_add_cert(store.as_ptr(), certificate.as_ptr()) })?;
            }
        }
        let mut count = 0;
        for certificate in rustls_pemfile::certs(&mut bundle).flatten() {
            if let Ok(certificate) = parse(&certificate) {
                check(unsafe { ffi::X509_STORE_add_cert(store.as_ptr(), certificate.as_ptr()) })?;
                count += 1;
            }
        }
        anyhow::ensure!(count > 0, "PEM bundle contained no certificates");
        Ok(Self { store, provider })
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let leaf = parse(end_entity)?;
        let certificates = intermediates
            .iter()
            .map(|certificate| parse(certificate))
            .collect::<Result<Vec<_>, _>>()?;
        // The context borrows the chain, which in turn borrows the certificate objects.
        unsafe {
            let chain = Owned::new(ffi::OPENSSL_sk_new_null(), ffi::OPENSSL_sk_free)?;
            for certificate in &certificates {
                if ffi::OPENSSL_sk_push(chain.as_ptr(), certificate.as_ptr().cast()) == 0 {
                    return Err(failure());
                }
            }
            let context = Owned::new(ffi::X509_STORE_CTX_new(), ffi::X509_STORE_CTX_free)?;
            check(ffi::X509_STORE_CTX_init(
                context.as_ptr(),
                self.store.as_ptr(),
                leaf.as_ptr(),
                chain.as_ptr().cast(),
            ))?;
            let parameters = ffi::X509_STORE_CTX_get0_param(context.as_ptr());
            check(ffi::X509_VERIFY_PARAM_set_flags(
                parameters,
                ffi::X509_V_FLAG_PARTIAL_CHAIN as _,
            ))?;
            ffi::X509_VERIFY_PARAM_set_time_posix(
                parameters,
                now.as_secs()
                    .try_into()
                    .map_err(|_| Error::FailedToGetCurrentTime)?,
            );
            ffi::X509_VERIFY_PARAM_set_hostflags(
                parameters,
                (ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
                    | ffi::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS) as _,
            );
            match server_name {
                ServerName::DnsName(name) => {
                    let name = name.as_ref().trim_end_matches('.');
                    check(ffi::X509_VERIFY_PARAM_set1_host(
                        parameters,
                        name.as_ptr().cast(),
                        name.len(),
                    ))?;
                }
                ServerName::IpAddress(ip) => {
                    let octets = match std::net::IpAddr::from(*ip) {
                        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
                    };
                    check(ffi::X509_VERIFY_PARAM_set1_ip(
                        parameters,
                        octets.as_ptr(),
                        octets.len(),
                    ))?;
                }
                _ => return Err(Error::UnsupportedNameType),
            }
            if ffi::X509_verify_cert(context.as_ptr()) != 1 {
                return Err(certificate_error(ffi::X509_STORE_CTX_get_error(
                    context.as_ptr(),
                )));
            }
            // Go checks EKU throughout the chain, while leaf KeyUsage does not restrict TLS use.
            let verified = ffi::X509_STORE_CTX_get0_chain(context.as_ptr()).cast();
            for index in 0..ffi::OPENSSL_sk_num(verified) {
                let certificate = ffi::OPENSSL_sk_value(verified, index).cast();
                if ffi::X509_get_extension_flags(certificate) & ffi::EXFLAG_XKUSAGE as u32 != 0
                    && ffi::X509_get_extended_key_usage(certificate)
                        & (ffi::XKU_SSL_SERVER | ffi::XKU_ANYEKU) as u32
                        == 0
                {
                    return Err(certificate_error(ffi::X509_V_ERR_INVALID_PURPOSE));
                }
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn parse(bytes: &[u8]) -> Result<Owned<ffi::X509>, Error> {
    let mut pointer = bytes.as_ptr();
    let length = bytes
        .len()
        .try_into()
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    unsafe {
        ffi::ERR_clear_error();
        let certificate = Owned::new(
            ffi::d2i_X509(ptr::null_mut(), &mut pointer, length),
            ffi::X509_free,
        )
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if pointer != bytes.as_ptr().add(bytes.len()) {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        Ok(certificate)
    }
}

fn check(result: i32) -> Result<(), Error> {
    if result == 1 { Ok(()) } else { Err(failure()) }
}

fn failure() -> Error {
    let mut buffer = [0; 256];
    unsafe {
        ffi::ERR_error_string_n(ffi::ERR_get_error(), buffer.as_mut_ptr(), buffer.len());
        Error::General(
            CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned(),
        )
    }
}

fn certificate_error(code: i32) -> Error {
    Error::InvalidCertificate(match code {
        ffi::X509_V_ERR_CERT_HAS_EXPIRED => CertificateError::Expired,
        ffi::X509_V_ERR_CERT_NOT_YET_VALID => CertificateError::NotValidYet,
        ffi::X509_V_ERR_CERT_SIGNATURE_FAILURE => CertificateError::BadSignature,
        ffi::X509_V_ERR_HOSTNAME_MISMATCH | ffi::X509_V_ERR_IP_ADDRESS_MISMATCH => {
            CertificateError::NotValidForName
        }
        ffi::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | ffi::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | ffi::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE => CertificateError::UnknownIssuer,
        _ => {
            let message =
                unsafe { CStr::from_ptr(ffi::X509_verify_cert_error_string(code.into())) };
            CertificateError::Other(OtherError(Arc::new(io::Error::other(
                message.to_string_lossy().into_owned(),
            ))))
        }
    })
}
