//! Pure, runtime-agnostic state machines for the auth and VPN flows.
//!
//! These modules hold the *state* and *transition logic* (issue: keep this in
//! `core`, not the daemon). The daemon is the imperative shell: it owns OS
//! resources (TUN/WG, sockets), the cookie jar, and persistence, builds the
//! [`ApiClient`](rustylink_api::ApiClient), runs the async effects, and applies
//! the states these modules return.

pub mod auth;
pub mod vpn;
