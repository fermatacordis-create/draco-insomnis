//! # Draco Insomnis for Rust
//!
//! The Draco Insomnis firewall for Rust web apps: firewall signatures, block list, country filter,
//! anti-copy pace, security headers, review requests and the CrowdSec bridge, with the same rules
//! and the same shared test cases as the PHP, JavaScript, Python, Go, Ruby, .NET and Java editions.
//!
//! - axum, or any tower stack: `Router::new()...layer(DracoLayer::new(gate))` (feature `axum` or `tower`).
//! - actix-web: `App::new().wrap(DracoMiddleware::new(gate))` (feature `actix`).
//!
//! ```
//! use draco_insomnis::{Gatekeeper, Options, Request};
//! let gate = Gatekeeper::new(Options { waf: "block".into(), ..Options::default() });
//! let r = Request { path: "/.env".into(), ..Request::default() };
//! assert_eq!(gate.decide(&r).unwrap().status, 403);
//! ```

pub mod adapt;
pub mod blocks;
pub mod crowdsec;
mod fetch;
mod gatekeeper;
pub mod geo;
pub mod json;
pub mod net;
mod options;
pub mod review;
mod store;
pub mod util;
pub mod waf;

#[cfg(feature = "actix")]
mod actix;
#[cfg(feature = "tower")]
mod tower;

#[cfg(feature = "actix")]
pub use actix::DracoMiddleware;
#[cfg(feature = "dns")]
pub use gatekeeper::SystemResolver;
pub use gatekeeper::{page, Answer, Gatekeeper, Rendered, Request, Resolver, DEFAULT_TEXTS, SENSITIVE_PATHS, VERSION};
pub use options::{GeoOptions, Options};
pub use review::ReviewRequest;
pub use store::{Clock, Event, MemoryStore, Store};
#[cfg(feature = "tower")]
pub use tower::{DracoLayer, DracoService, RemoteAddr};
