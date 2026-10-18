//! Platforms without a gateway lookup: every lookup is `Unsupported`, so the port mapper never
//! sends anything there, but the crate still builds.

use super::{DefaultRoutes, LookupError};

/// Always [`LookupError::Unsupported`].
pub(super) fn default_routes() -> Result<DefaultRoutes, LookupError> {
    Err(LookupError::Unsupported)
}
