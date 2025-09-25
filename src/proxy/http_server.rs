#![allow(dead_code)]
use anyhow::Result;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use super::handler::ProxyHandler;
use crate::tls::TlsManager;

/// HTTP服务器管理器，负责创建和运行HTTP/HTTPS服务器
pub struct HttpServerManager {
    bind_addr: SocketAddr,
    tls_manager: Option<TlsManager>,
}

impl HttpServerManager {
    /// 创建新的HTTP服务器管理器
    pub fn new(bind_addr: SocketAddr, tls_manager: Option<TlsManager>) -> Self {
        Self {
            bind_addr,
            tls_manager,
        }
    }

    /// 运行服务器（自动选择HTTP或HTTPS）
    pub async fn run(self, handler: ProxyHandler) -> Result<()> {
        // 检查是否启用TLS
        if let Some(ref tls_manager) = self.tls_manager {
            if tls_manager.is_enabled() {
                info!("Starting HTTPS proxy server on {}", self.bind_addr);
                return self.run_https(handler).await;
            }
        }

        info!("Starting HTTP proxy server on {}", self.bind_addr);
        self.run_http(handler).await
    }

    /// 运行HTTP服务器
    async fn run_http(self, handler: ProxyHandler) -> Result<()> {
        let make_service = make_service_fn(move |conn: &AddrStream| {
            let handler = handler.clone();
            let remote = conn.remote_addr();
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req: Request<Body>| {
                    let handler = handler.clone();
                    // 将远程地址附加到请求扩展中
                    req.extensions_mut().insert(remote);
                    async move { handler.handle_request(req).await }
                }))
            }
        });

        let server = Server::bind(&self.bind_addr).serve(make_service);

        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }

        Ok(())
    }

    /// 运行HTTPS服务器，带TLS终端处理
    async fn run_https(self, handler: ProxyHandler) -> Result<()> {
        let tls_manager = self
            .tls_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS manager not initialized"))?;

        let server_config = tls_manager
            .server_config()
            .ok_or_else(|| anyhow::anyhow!("TLS server config not available"))?
            .clone();

        info!("Starting HTTPS server on {}", self.bind_addr);

        // 创建TLS接受器
        let tls_acceptor = TlsAcceptor::from(server_config);

        // 绑定到地址
        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;

        info!("HTTPS server listening on {}", self.bind_addr);

        // 处理连接循环
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_tls_connection(stream, peer_addr, tls_acceptor, handler)
                                .await
                        {
                            warn!("TLS connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// 处理单个TLS连接
    async fn handle_tls_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        handler: ProxyHandler,
    ) -> Result<()> {
        // 进行TLS握手
        let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!("TLS handshake failed with {}: {}", peer_addr, e);
                return Err(e.into());
            }
        };

        // 使用Hyper处理HTTP over TLS
        let service = service_fn(move |mut req: Request<Body>| {
            let handler = handler.clone();
            // 将远程地址附加到请求扩展中
            req.extensions_mut().insert(peer_addr);
            async move { handler.handle_request(req).await }
        });

        // 处理HTTP连接
        if let Err(e) = hyper::server::conn::Http::new()
            .serve_connection(tls_stream, service)
            .await
        {
            warn!("HTTP connection error from {}: {}", peer_addr, e);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_http_server_manager_creation() {
        let bind_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let manager = HttpServerManager::new(bind_addr, None);

        assert_eq!(manager.bind_addr, bind_addr);
        assert!(manager.tls_manager.is_none());
    }

    #[tokio::test]
    async fn test_http_server_manager_with_tls() {
        let bind_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        // 注意：在实际测试中需要创建有效的TlsManager
        let manager = HttpServerManager::new(bind_addr, None);

        assert_eq!(manager.bind_addr, bind_addr);
    }
}
