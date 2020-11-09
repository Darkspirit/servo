/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![cfg(test)]

#[macro_use]
extern crate lazy_static;

mod cookie;
mod cookie_http_state;
mod data_loader;
mod fetch;
mod file_loader;
mod filemanager_thread;
mod hsts;
mod http_cache;
mod http_loader;
mod mime_classifier;
mod resource_thread;
mod subresource_integrity;

use crossbeam_channel::{unbounded, Sender};
use devtools_traits::DevtoolsControlMsg;
use embedder_traits::resources::{self, Resource};
use embedder_traits::{EmbedderProxy, EventLoopWaker};
use futures_util::{
    compat::{Compat, Compat01As03},
    FutureExt,
};
use hyper::server::conn::Http;
use hyper::server::Server as HyperServer;
use hyper::service::service_fn_ok;
use hyper::{Body, Request as HyperRequest, Response as HyperResponse};
use net::connector::{create_tls_config, CertExceptions, ReceivedCerts};
use net::fetch::cors_cache::CorsCache;
use net::fetch::methods::{self, CancellationListener, FetchContext};
use net::filemanager_thread::FileManager;
use net::resource_thread::CoreResourceThreadPool;
use net::test::HttpState;
use net_traits::filemanager_thread::FileTokenCheck;
use net_traits::request::Request;
use net_traits::response::Response;
use net_traits::{FetchTaskTarget, ResourceFetchTiming, ResourceTimingType};
use servo_arc::Arc as ServoArc;
use servo_url::ServoUrl;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use tokio2::net::TcpListener;
use tokio_compat::runtime::{Runtime, TaskExecutor};
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::Tokio02AsyncReadCompatExt;

lazy_static! {
    pub static ref HANDLE: Mutex<Runtime> = Mutex::new(Runtime::new().unwrap());
}

const DEFAULT_USER_AGENT: &'static str = "Such Browser. Very Layout. Wow.";

struct FetchResponseCollector {
    sender: Sender<Response>,
}

fn create_embedder_proxy() -> EmbedderProxy {
    let (sender, _) = unbounded();
    let event_loop_waker = || {
        struct DummyEventLoopWaker {}
        impl DummyEventLoopWaker {
            fn new() -> DummyEventLoopWaker {
                DummyEventLoopWaker {}
            }
        }
        impl EventLoopWaker for DummyEventLoopWaker {
            fn wake(&self) {}
            fn clone_box(&self) -> Box<dyn EventLoopWaker> {
                Box::new(DummyEventLoopWaker {})
            }
        }

        Box::new(DummyEventLoopWaker::new())
    };

    EmbedderProxy {
        sender: sender,
        event_loop_waker: event_loop_waker(),
    }
}

fn new_fetch_context(
    dc: Option<Sender<DevtoolsControlMsg>>,
    fc: Option<EmbedderProxy>,
    pool_handle: Option<Weak<CoreResourceThreadPool>>,
) -> FetchContext {
    let certs = resources::read_string(Resource::SSLCertificates);
    let tls_config = create_tls_config(
        &certs,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        CertExceptions::new(),
        ReceivedCerts::new(),
    );
    let sender = fc.unwrap_or_else(|| create_embedder_proxy());

    FetchContext {
        state: Arc::new(HttpState::new(tls_config)),
        user_agent: DEFAULT_USER_AGENT.into(),
        devtools_chan: dc,
        filemanager: FileManager::new(sender, pool_handle.unwrap_or_else(|| Weak::new())),
        file_token: FileTokenCheck::NotRequired,
        cancellation_listener: Arc::new(Mutex::new(CancellationListener::new(None))),
        timing: ServoArc::new(Mutex::new(ResourceFetchTiming::new(
            ResourceTimingType::Navigation,
        ))),
    }
}
impl FetchTaskTarget for FetchResponseCollector {
    fn process_request_body(&mut self, _: &Request) {}
    fn process_request_eof(&mut self, _: &Request) {}
    fn process_response(&mut self, _: &Response) {}
    fn process_response_chunk(&mut self, _: Vec<u8>) {}
    /// Fired when the response is fully fetched
    fn process_response_eof(&mut self, response: &Response) {
        let _ = self.sender.send(response.clone());
    }
}

fn fetch(request: &mut Request, dc: Option<Sender<DevtoolsControlMsg>>) -> Response {
    fetch_with_context(request, &mut new_fetch_context(dc, None, None))
}

fn fetch_with_context(request: &mut Request, mut context: &mut FetchContext) -> Response {
    let (sender, receiver) = unbounded();
    let mut target = FetchResponseCollector { sender: sender };

    methods::fetch(request, &mut target, &mut context);

    receiver.recv().unwrap()
}

fn fetch_with_cors_cache(request: &mut Request, cache: &mut CorsCache) -> Response {
    let (sender, receiver) = unbounded();
    let mut target = FetchResponseCollector { sender: sender };

    methods::fetch_with_cors_cache(
        request,
        cache,
        &mut target,
        &mut new_fetch_context(None, None, None),
    );

    receiver.recv().unwrap()
}

pub(crate) struct Server {
    pub close_channel: futures03::channel::oneshot::Sender<()>,
}

impl Server {
    fn close(self) {
        self.close_channel.send(()).unwrap();
    }
}

fn make_server<H>(handler: H) -> (Server, ServoUrl)
where
    H: Fn(HyperRequest<Body>, &mut HyperResponse<Body>) + Send + Sync + 'static,
{
    use futures01::Future;
    let handler = Arc::new(handler);
    let listener = StdTcpListener::bind("0.0.0.0:0").unwrap();
    let url_string = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let url = ServoUrl::parse(&url_string).unwrap();
    let (tx, rx) = futures03::channel::oneshot::channel::<()>();
    let server = HyperServer::from_tcp(listener)
        .unwrap()
        .serve(move || {
            let handler = handler.clone();
            service_fn_ok(move |req: HyperRequest<Body>| {
                let mut response = HyperResponse::new(Vec::<u8>::new().into());
                handler(req, &mut response);
                response
            })
        })
        .with_graceful_shutdown(Compat::new(rx))
        .map_err(|_| ());

    HANDLE.lock().unwrap().spawn(server);
    let server = Server { close_channel: tx };
    (server, url)
}

fn load_certs(path: &Path) -> std::io::Result<Vec<Certificate>> {
    certs(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> std::io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key"))
}

fn make_ssl_server<H>(handler: H, cert_path: PathBuf, key_path: PathBuf) -> (Server, ServoUrl)
where
    H: Fn(HyperRequest<Body>, &mut HyperResponse<Body>) + Send + Sync + 'static,
{
    let listener = StdTcpListener::bind("[::0]:0").unwrap();
    let url_string = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let url = ServoUrl::parse(&url_string).unwrap();
    let executor = HANDLE.lock().unwrap().executor();
    let tls_server = tls_server(executor, handler, cert_path, key_path, listener);
    let (tx, rx) = futures03::channel::oneshot::channel::<()>();
    HANDLE.lock().unwrap().spawn_std(async {
        futures_util::future::select(tls_server.boxed(), rx).await;
    });
    let server = Server { close_channel: tx };

    (server, url)
}

async fn tls_server<H>(
    executor: TaskExecutor,
    handler: H,
    cert_path: PathBuf,
    key_path: PathBuf,
    listener: StdTcpListener,
) -> std::io::Result<()>
where
    H: Fn(HyperRequest<Body>, &mut HyperResponse<Body>) + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let cfg = {
        let certs = load_certs(&cert_path).unwrap();
        let mut keys = load_keys(&key_path).unwrap();
        let mut cfg = ServerConfig::new(NoClientAuth::new());
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.set_single_cert(certs, keys.remove(0)).unwrap();
        Arc::new(cfg)
    };
    let acceptor = TlsAcceptor::from(cfg);
    let mut listener = TcpListener::from_std(listener)?;

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let handler = handler.clone();
        let acceptor = acceptor.clone();

        executor.spawn_std(async move {
            let stream_tokio02 = acceptor.accept(stream).await.unwrap();
            let stream_tokio01 = Compat::new(stream_tokio02.compat());
            let fut01 = Http::new().serve_connection(
                stream_tokio01,
                service_fn_ok(move |req: HyperRequest<Body>| {
                    let mut response = HyperResponse::new(Vec::<u8>::new().into());
                    handler(req, &mut response);
                    response
                }),
            );
            Compat01As03::new(fut01).await.unwrap();
        });
    }
}
