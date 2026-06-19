pub use buffa;

#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
pub mod proto {
    connectrpc::include_generated!();
}

mod projections;
