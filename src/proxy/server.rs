use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{error, info};

use crate::config::Config;
use crate::balancer::LoadBalancer;
use crate::logger::TrafficLogger;
use super::handler::ProxyHandler;

pub struct ProxyServer {
    config: Config,
    bind_addr: SocketAddr,
    load_balancer: LoadBalancer,
    traffic_logger: TrafficLogger,
}

impl ProxyServer {
    pub fn new(config: Config, bind_addr: SocketAddr, traffic_logger: TrafficLogger) -> Self {
        let load_balancer = LoadBalancer::new(config.targets.clone());

        Self {
            config,
            bind_addr,
            load_balancer,
            traffic_logger,
        }
    }

    pub async fn run(self) -> Result<()> {
        info!("Proxy server listening on {}", self.bind_addr);

        let handler = ProxyHandler::new(
            self.config.domains.clone(),
            self.load_balancer,
            self.traffic_logger,
        );

        let make_service = make_service_fn(move |_conn| {
            let handler = handler.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let handler = handler.clone();
                    async move { handler.handle_request(req).await }
                }))
            }
        });

        let server = Server::bind(&self.bind_addr).serve(make_service);

        if let Err(e) = server.await {
            error!("Server error: {}", e);
        }

        Ok(())
    }
}