/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// This module converts between tokio01_hyper <> futures03 <> tokio02_rustls
// and runs on top of a tokio_compat runtime which supports tokio 0.1 and 0.2.
// TODO: When upgrading to hyper 0.13, this can be removed in favor of the hyper_rustls crate.
mod hyper_rustls {
    // Based on https://github.com/ctz/hyper-rustls/tree/v/0.18.0 for hyper 0.12 (tokio 0.1)
    // and https://github.com/ctz/hyper-rustls/blob/v/0.21.0/src/connector.rs#L125-L136 for tokio_rustls (tokio 0.2).
    // All credit goes to this: https://github.com/tokio-rs/tokio-compat/issues/26#issuecomment-591077614
    mod connector {
        use futures01::{Future, Poll};
        // converts between tokio01 and futures03
        use futures_util::{
            compat::{Compat, Compat01As03},
            FutureExt,
        };
        use hyper::client::connect::{self, Connect};
        use rustls::{ClientConfig, Session};
        use std::sync::Arc;
        use std::{fmt, io};
        use tokio_rustls::TlsConnector;
        // futures03.compat() converts to tokio02
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        use webpki::DNSNameRef;

        use super::stream::MaybeHttpsStream;

        /// A Connector for the `https` scheme.
        #[derive(Clone)]
        pub struct HttpsConnector<T> {
            http: T,
            tls_config: Arc<ClientConfig>,
        }

        impl<T> fmt::Debug for HttpsConnector<T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_struct("HttpsConnector").finish()
            }
        }

        impl<T> From<(T, Arc<ClientConfig>)> for HttpsConnector<T> {
            fn from(args: (T, Arc<ClientConfig>)) -> Self {
                HttpsConnector {
                    http: args.0,
                    tls_config: args.1,
                }
            }
        }

        impl<T> Connect for HttpsConnector<T>
        where
            T: Connect<Error = io::Error>,
            T::Transport: 'static,
            T::Future: 'static,
        {
            type Transport = MaybeHttpsStream<T::Transport>;
            type Error = io::Error;
            type Future = HttpsConnecting<T::Transport>;

            fn connect(&self, dst: connect::Destination) -> Self::Future {
                let is_https = dst.scheme() == "https";
                let hostname = dst.host().to_string();
                let connecting = self.http.connect(dst);

                if !is_https {
                    let fut01 = connecting.map(|(tcp, conn)| (MaybeHttpsStream::Http(tcp), conn));
                    HttpsConnecting(Box::new(fut01))
                } else {
                    let cfg = self.tls_config.clone();
                    let fut03 = async move {
                        let connecting_future = Compat01As03::new(connecting);
                        let (tcp_tokio01, conn) = connecting_future
                            .await
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        let tcp_futures03 = Compat01As03::new(tcp_tokio01);
                        let tcp_tokio02 = tcp_futures03.compat();

                        let connector = TlsConnector::from(cfg);
                        let dnsname = DNSNameRef::try_from_ascii_str(&hostname)
                            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid dnsname"))?;

                        let tls = connector
                            .connect(dnsname, tcp_tokio02)
                            .await
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                        let connected = if tls.get_ref().1.get_alpn_protocol() == Some(b"h2") {
                            conn.negotiated_h2()
                        } else {
                            conn
                        };

                        Ok((MaybeHttpsStream::Https(tls), connected))
                    }
                    .boxed();

                    let fut01 = Compat::new(fut03);

                    HttpsConnecting(Box::new(fut01))
                }
            }
        }

        /// A Future representing work to connect to a URL, and a TLS handshake.
        pub struct HttpsConnecting<T>(
            Box<
                dyn Future<Item = (MaybeHttpsStream<T>, connect::Connected), Error = io::Error>
                    + Send,
            >,
        );

        impl<T> Future for HttpsConnecting<T> {
            type Item = (MaybeHttpsStream<T>, connect::Connected);
            type Error = io::Error;

            fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
                self.0.poll()
            }
        }

        impl<T> fmt::Debug for HttpsConnecting<T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.pad("HttpsConnecting")
            }
        }
    }
    mod stream {
        // Originally copied from hyperium/hyper-tls#62e3376/src/stream.rs
        use bytes::{Buf, BufMut};
        use futures01::Poll;
        // converts between tokio 0.1 and futures 0.3
        use futures_util::compat::{Compat, Compat01As03};
        use std::fmt;
        use std::io::{self, Read, Write};
        use tokio1::io::{AsyncRead, AsyncWrite};
        use tokio_rustls::client::TlsStream;
        // tokio02.compat() converts to futures03
        use tokio_util::compat::Tokio02AsyncReadCompatExt;

        /// A stream that might be protected with TLS.
        pub enum MaybeHttpsStream<T> {
            /// A stream over plain text.
            Http(T),
            /// A stream protected with TLS.
            Https(TlsStream<tokio_util::compat::Compat<Compat01As03<T>>>),
        }

        impl<T: fmt::Debug> fmt::Debug for MaybeHttpsStream<T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
                    MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
                }
            }
        }

        impl<T: AsyncRead + AsyncWrite> Read for MaybeHttpsStream<T> {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.read(buf),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.read(buf)
                    },
                }
            }
        }

        impl<T: AsyncRead + AsyncWrite> Write for MaybeHttpsStream<T> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.write(buf),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.write(buf)
                    },
                }
            }

            #[inline]
            fn flush(&mut self) -> io::Result<()> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.flush(),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.flush()
                    },
                }
            }
        }

        impl<T: AsyncRead + AsyncWrite> AsyncRead for MaybeHttpsStream<T> {
            fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.read_buf(buf),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.read_buf(buf)
                    },
                }
            }
        }

        impl<T: AsyncRead + AsyncWrite> AsyncWrite for MaybeHttpsStream<T> {
            fn shutdown(&mut self) -> Poll<(), io::Error> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.shutdown(),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.shutdown()
                    },
                }
            }

            fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
                match *self {
                    MaybeHttpsStream::Http(ref mut s) => s.write_buf(buf),
                    MaybeHttpsStream::Https(ref mut tls_tokio02) => {
                        let tls_futures03 = tls_tokio02.compat();
                        let mut tls_tokio01 = Compat::new(tls_futures03);
                        tls_tokio01.write_buf(buf)
                    },
                }
            }
        }
    }
    pub use connector::HttpsConnector;
}

use crate::hosts::replace_host;
use hyper::client::connect::{Connect, Destination};
use hyper::client::HttpConnector as HyperHttpConnector;
use hyper::{Body, Client};
use hyper_rustls::HttpsConnector;
use rustls::{
    Certificate, ClientConfig, ClientSessionMemoryCache, RootCertStore, ServerCertVerified,
    ServerCertVerifier, TLSError,
};
use std::collections::hash_map::{Entry, HashMap};
use std::sync::{Arc, Mutex};
use tokio_compat::runtime::TaskExecutor;

pub const BUF_SIZE: usize = 32768;

pub type Connector = HttpsConnector<HttpConnector>;
pub type TlsConfig = Arc<ClientConfig>;

pub struct HttpConnector {
    inner: HyperHttpConnector,
}

impl HttpConnector {
    fn new() -> HttpConnector {
        let mut inner = HyperHttpConnector::new(4);
        inner.enforce_http(false);
        inner.set_happy_eyeballs_timeout(None);
        HttpConnector { inner }
    }
}

impl Connect for HttpConnector {
    type Transport = <HyperHttpConnector as Connect>::Transport;
    type Error = <HyperHttpConnector as Connect>::Error;
    type Future = <HyperHttpConnector as Connect>::Future;

    fn connect(&self, dest: Destination) -> Self::Future {
        // Perform host replacement when making the actual TCP connection.
        let mut new_dest = dest.clone();
        let addr = replace_host(dest.host());
        new_dest.set_host(&*addr).unwrap();

        self.inner.connect(new_dest)
    }
}

#[derive(Clone)]
pub struct ReceivedCerts {
    certs: Arc<Mutex<HashMap<String, (Certificate, u32)>>>,
}

impl ReceivedCerts {
    pub fn new() -> Self {
        Self {
            certs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn store(&self, host: String, certificate: Certificate) {
        debug!(
            "storing received cert from {}:\n{}",
            host,
            certificate.as_pem()
        );
        let mut certs = self.certs.lock().unwrap();
        let entry = certs.entry(host).or_insert((certificate, 0));
        entry.1 += 1;
    }

    pub(crate) fn remove(&self, host: String) -> Option<String> {
        match self.certs.lock().unwrap().entry(host) {
            Entry::Vacant(_) => None,
            Entry::Occupied(mut e) => {
                e.get_mut().1 -= 1;
                let certificate = if e.get().1 == 0 {
                    (e.remove_entry().1).0
                } else {
                    e.get().0.clone()
                };
                Some(certificate.as_pem())
            },
        }
    }
}

trait CertAsPemExt {
    fn as_pem(&self) -> String;
}
impl CertAsPemExt for Certificate {
    fn as_pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----{}\n-----END CERTIFICATE-----",
            base64::encode(&self.0)
                .chars()
                .enumerate()
                .flat_map(|(i, c)| {
                    if i % 64 == 0 { Some('\n') } else { None }
                        .into_iter()
                        .chain(std::iter::once(c))
                })
                .collect::<String>()
        )
    }
}

#[derive(Clone)]
pub struct CertExceptions(Arc<Mutex<Vec<Certificate>>>);

impl CertExceptions {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(vec![])))
    }

    pub fn add(&self, pem: String) {
        let mut certs = rustls::internal::pemfile::certs(&mut pem.as_bytes()).unwrap();
        self.0.lock().unwrap().push(certs.remove(0));
    }
}

// from https://github.com/ctz/rustls/blob/v/0.18.1/rustls/src/verify.rs#L16-L33
type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

// from https://github.com/ctz/rustls/blob/v/0.18.1/rustls/src/verify.rs#L292-L322
type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);

fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    presented_certs: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&presented_certs[0].0).map_err(TLSError::WebPKIError)?;

    let chain: Vec<&'a [u8]> = presented_certs
        .iter()
        .skip(1)
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots
        .roots
        .iter()
        // slightly modified because module is private
        .map(|owned_trust_anchor| owned_trust_anchor.to_trust_anchor())
        .collect();

    Ok((cert, chain, trustroots))
}

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
}

// from https://github.com/ctz/rustls/blob/v/0.18.1/rustls/src/verify.rs#L230-L270
pub struct ServoWebPKIVerifier {
    pub cert_exceptions: CertExceptions,
    pub received_certs: ReceivedCerts,
    /// time provider
    pub time: fn() -> Result<webpki::Time, TLSError>,
}
impl ServoWebPKIVerifier {
    pub fn new(
        cert_exceptions: CertExceptions,
        received_certs: ReceivedCerts,
    ) -> ServoWebPKIVerifier {
        ServoWebPKIVerifier {
            cert_exceptions,
            received_certs,
            time: try_now,
        }
    }
}
impl ServerCertVerifier for ServoWebPKIVerifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: webpki::DNSNameRef,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        if !presented_certs.is_empty() {
            // certificate exceptions
            // TODO: WIP: dns_name must be compared
            let presented_cert = &presented_certs[0];
            let cert_exceptions = &*self.cert_exceptions.0.lock().unwrap();
            for cert in cert_exceptions {
                if *cert == *presented_cert {
                    return Ok(ServerCertVerified::assertion());
                }
            }
            let hostname: &str = dns_name.into();
            self.received_certs
                .store(hostname.to_string(), presented_cert.clone());
        }

        let (cert, chain, trustroots) = prepare(roots, presented_certs)?;
        let now = (self.time)()?;
        let cert = cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(&trustroots),
                &chain,
                now,
            )
            .map_err(TLSError::WebPKIError)
            .map(|_| cert)?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(TLSError::WebPKIError)
            .map(|_| ServerCertVerified::assertion())
    }
}

pub fn create_tls_config(
    additional_ca_certs: &str,
    alpn: Vec<Vec<u8>>,
    cert_exceptions: CertExceptions,
    received_certs: ReceivedCerts,
) -> TlsConfig {
    let mut cfg = ClientConfig::new();
    cfg.alpn_protocols = alpn;
    cfg.ct_logs = Some(&ct_logs::LOGS);
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(ServoWebPKIVerifier::new(
            cert_exceptions,
            received_certs,
        )));
    cfg.set_persistence(ClientSessionMemoryCache::new(128));
    cfg.root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let _ = cfg
        .root_store
        .add_pem_file(&mut additional_ca_certs.as_bytes());

    Arc::new(cfg)
}

pub fn create_http_client(
    tls_config: TlsConfig,
    executor: TaskExecutor,
) -> Client<Connector, Body> {
    let connector = HttpsConnector::from((HttpConnector::new(), tls_config));

    Client::builder()
        .http1_title_case_headers(true)
        .executor(executor)
        .build(connector)
}
