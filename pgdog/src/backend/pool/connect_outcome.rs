//! Outcome of the last backend connection attempt made by a pool.

/// Outcome of the last connection attempt a pool made with its own
/// credentials.
///
/// Token validation performed on behalf of a client doesn't count: it dials
/// with the client's credential, so its result says nothing about the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ConnectOutcome {
    /// No connection has been attempted yet.
    #[default]
    NotAttempted,
    /// The server accepted the connection.
    Connected,
    /// The server rejected the credentials.
    AuthFailed,
    /// The connection failed for another reason: network, timeout or a
    /// server error.
    Failed,
}
