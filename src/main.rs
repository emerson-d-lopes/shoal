use anyhow::Result;
use shoal::{db, server};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shoal=info,tower_http=info".into()),
        )
        .init();

    let db_path = std::env::var("SHOAL_DB").unwrap_or_else(|_| "shoal.db".into());
    let bind = std::env::var("SHOAL_BIND").unwrap_or_else(|_| "0.0.0.0:7420".into());
    let addr: SocketAddr = bind.parse()?;

    let limits = server::Limits::from_env();
    let access = server::Access::from_env();

    // An operator who leaves the server open and sets no global ceiling has
    // no bound on disk use, because anyone who can reach the port can mint
    // unlimited identities. Say so at startup rather than in the docs only.
    if access.is_open() && limits.max_users == 0 && limits.max_total_ops == 0 {
        tracing::warn!(
            "no SHOAL_ALLOWED_PUBKEYS, SHOAL_MAX_USERS or SHOAL_MAX_TOTAL_OPS set: \
             any public key can create a user, so per-user limits do not bound total storage. \
             Safe on a tailnet, risky on the public internet."
        );
    }

    let state = Arc::new(server::AppState::with_access(
        db::Db::open(&PathBuf::from(&db_path))?,
        limits,
        access,
    ));
    let app = server::router(state);

    tracing::info!(%addr, db = %db_path, "shoal listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
