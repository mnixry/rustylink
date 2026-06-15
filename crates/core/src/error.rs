use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("authentication operation failed"))]
    Auth {
        #[snafu(source(from(crate::auth::Error, Box::new)))]
        source: Box<crate::auth::Error>,
    },

    #[snafu(display("application context operation failed"))]
    Context {
        #[snafu(source(from(crate::context::Error, Box::new)))]
        source: Box<crate::context::Error>,
    },

    #[snafu(display("security report operation failed"))]
    Security {
        #[snafu(source(from(crate::security::Error, Box::new)))]
        source: Box<crate::security::Error>,
    },

    #[snafu(display("state operation failed"))]
    State {
        #[snafu(source(from(crate::state::Error, Box::new)))]
        source: Box<crate::state::Error>,
    },

    #[snafu(display("VPN operation failed"))]
    Vpn {
        #[snafu(source(from(crate::vpn::Error, Box::new)))]
        source: Box<crate::vpn::Error>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<crate::auth::Error> for Error {
    fn from(source: crate::auth::Error) -> Self {
        Self::Auth {
            source: Box::new(source),
        }
    }
}

impl From<crate::context::Error> for Error {
    fn from(source: crate::context::Error) -> Self {
        Self::Context {
            source: Box::new(source),
        }
    }
}

impl From<crate::security::Error> for Error {
    fn from(source: crate::security::Error) -> Self {
        Self::Security {
            source: Box::new(source),
        }
    }
}

impl From<crate::state::Error> for Error {
    fn from(source: crate::state::Error) -> Self {
        Self::State {
            source: Box::new(source),
        }
    }
}

impl From<crate::vpn::Error> for Error {
    fn from(source: crate::vpn::Error) -> Self {
        Self::Vpn {
            source: Box::new(source),
        }
    }
}
