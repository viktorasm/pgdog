//! Client authentication tests.

use pgdog_config::{AuthType, PassthroughAuth, User};

use crate::{
    backend::databases,
    config::{config, set},
    expect_message,
    net::{Authentication, ErrorResponse, Parameters, Password},
};

use super::SpawnedClient;

/// Connect to the admin database and answer the plaintext password
/// request with the given password.
async fn login_admin(password: &str) -> SpawnedClient {
    let cfg = config();
    let mut params = Parameters::default();
    params.insert("user", cfg.config.admin.user.as_str());
    params.insert("database", cfg.config.admin.name.as_str());

    let mut client = SpawnedClient::new_with_login(params).await;

    // Both the admin and the passthrough branches request the password
    // in plaintext; what matters is what happens with the answer.
    let request = expect_message!(client.read().await, Authentication);
    assert!(matches!(request, Authentication::ClearTextPassword));

    client.send(Password::new_password(password)).await;
    client
}

/// Admin connections must be authenticated against the admin password even
/// when passthrough auth is enabled. Regression test for the passthrough
/// branch running first and accepting any password for the admin database.
#[tokio::test]
async fn test_admin_password_checked_with_passthrough_auth() {
    crate::logger();
    crate::config::load_test();

    let mut cfg = (*config()).clone();
    cfg.config.general.auth_type = AuthType::Plain;
    cfg.config.general.passthrough_auth = PassthroughAuth::EnabledPlain;
    cfg.config.admin.password = "admin-password".into();
    set(cfg).unwrap();

    // The wrong password is rejected instead of being passed through.
    let mut client = login_admin("not-the-admin-password").await;
    let error = ErrorResponse::try_from(client.read().await).unwrap();
    assert_eq!(error.code, "28000");
    client.join().await;

    // The correct password is accepted.
    let mut client = login_admin("admin-password").await;
    let response = expect_message!(client.read().await, Authentication);
    assert!(matches!(response, Authentication::Ok));
    client.read_until('Z').await;
    client.join().await;
}

/// A passthrough pool that is down because the server rejected the stored
/// credential must surface an authentication error to the client, not a
/// generic 58000 "pool is down" availability error. Under passthrough auth
/// the client owns the credential, so this is the only way it can tell a
/// stale credential from an outage and react (refresh the token and retry).
///
/// Covers the stale-match case: the client presents the same password that
/// is already stored, so no database validation runs (only new users and
/// password changes are validated) and the pool must open a backend
/// connection with the stored credential, which the server rejects.
#[tokio::test]
async fn test_passthrough_stale_password_surfaces_auth_error() {
    crate::logger();
    crate::config::load_test();

    let mut cfg = (*config()).clone();
    cfg.config.general.passthrough_auth = PassthroughAuth::EnabledPlainAllowChange;
    // Simulate a stale stored credential, e.g. a passthrough user restored
    // after a config reload whose IAM token has since expired: the password
    // was valid when it was learned, but the server now rejects it.
    cfg.users.users.push(User {
        name: "pgdog_stale_credential".into(),
        database: "pgdog".into(),
        password: Some("stale_password".into()),
        ..Default::default()
    });
    set(cfg).unwrap();
    databases::init().unwrap();

    let mut params = Parameters::default();
    params.insert("user", "pgdog_stale_credential");
    params.insert("database", "pgdog");
    let mut client = SpawnedClient::new_with_login(params).await;

    let request = expect_message!(client.read().await, Authentication);
    assert!(matches!(request, Authentication::ClearTextPassword));
    // Presenting the stored (stale) password matches, so the passthrough
    // branch accepts it without a database validation.
    client.send(Password::new_password("stale_password")).await;

    let ok = expect_message!(client.read().await, Authentication);
    assert!(matches!(ok, Authentication::Ok));

    // The pool goes down because the server rejects the credential: the
    // client must see an auth-class error (28000), not "pool is down".
    let error = ErrorResponse::try_from(client.read().await).unwrap();
    assert_eq!(error.code, "28000");
    assert!(
        error.message.contains("password for user"),
        "unexpected error: {}",
        error.message
    );
    client.join().await;
}
