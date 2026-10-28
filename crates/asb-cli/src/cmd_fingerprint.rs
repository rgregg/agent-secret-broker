//! `asb fingerprint HOST[:PORT]`: the sha256 of the certificate a server presents, for `tls_fingerprint`.
//! The handshake trusts nothing on purpose (the point is to read a self-signed certificate); the human checks it is
//! the device they mean before pinning it.

use crate::exit::{die, R, USAGE};
use crate::pyfmt::repr;
use crate::util::{die_help, os_error};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct Capture {
    seen: Mutex<Option<Vec<u8>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn fetch(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let timeout = Duration::from_secs(10);
    let mut last = None;
    let mut tcp = None;
    for addr in (host, port).to_socket_addrs().map_err(|e| os_error(&e))? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let mut tcp = tcp.ok_or_else(|| {
        last.map(|e| os_error(&e))
            .unwrap_or_else(|| "no address".into())
    })?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let provider = Arc::new(ring::default_provider());
    let verifier = Arc::new(Capture {
        seen: Mutex::new(None),
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(|e| match e.raw_os_error() {
                Some(_) => os_error(&e),
                None => e.to_string(),
            })?;
    }
    let der = verifier.seen.lock().unwrap().take();
    der.ok_or_else(|| "the server presented no certificate".to_string())
}

pub fn run(argv: &[String]) -> R {
    if argv.len() != 1 {
        return Err(die_help("fingerprint"));
    }
    let arg = &argv[0];
    let (host, _, port) = match arg.split_once(':') {
        Some((h, p)) => (h, ":", p),
        None => (arg.as_str(), "", ""),
    };
    let fail = |why: String| {
        die(
            format!("could not read a certificate from {arg}: {why}"),
            USAGE,
        )
    };
    let port = if port.is_empty() {
        443
    } else {
        match crate::ssh_claim::port_number(port) {
            Some(p) if p <= 65535 => p as u16,
            Some(_) => return Err(fail("bind(): port must be 0-65535.".into())),
            None => {
                return Err(fail(format!(
                    "invalid literal for int() with base 10: {}",
                    repr(port)
                )))
            }
        }
    };
    crate::broker::ignore_sigpipe();
    let der = fetch(host, port).map_err(fail)?;
    println!("sha256:{}", hex(&Sha256::digest(der)));
    eprintln!(
        "asb: put this in the item's broker metadata as \"tls_fingerprint\" only after checking it is the device you mean."
    );
    Ok(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
