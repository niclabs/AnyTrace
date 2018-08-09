mod handler;
pub mod reader;
pub mod writer;

pub use self::handler::PingHandler;
pub use self::reader::Responce;

use std::net::Ipv4Addr;

#[derive(PartialEq, Debug, Clone)]
pub enum PingMethod {
    ICMP,
    UDP,
}

pub struct PingHandlerBuilder {
    localip: Option<Ipv4Addr>,
    method: Option<PingMethod>,
    rate_limit: Option<u32>,
}

impl PingHandlerBuilder {
    /// Create a new PingHandlerBuilder to build a PingHandler.
    pub fn new() -> PingHandlerBuilder {
        return PingHandlerBuilder {
            localip: None,
            method: None,
            rate_limit: None,
        };
    }

    /// Set the local IP address to listen.
    pub fn localip(mut self, localip: &str) -> Self {
        let local: Ipv4Addr = localip.parse().unwrap();
        self.localip = Some(local);
        return self;
    }

    /// Set the method used to send the ping packets.
    pub fn method(mut self, method: PingMethod) -> Self {
        self.method = Some(method);
        return self;
    }

    /// Set the frequency of packets per seconds to send.
    pub fn rate_limit(mut self, rate_limit: u32) -> Self {
        self.rate_limit = Some(rate_limit);
        return self;
    }

    /// Build the PingHandler
    pub fn build(self) -> PingHandler {
        return PingHandler::new(
            self.localip.unwrap(),
            self.method.unwrap(),
            self.rate_limit.unwrap_or(100_000),
        );
    }
}
