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

    let state = Arc::new(server::AppState::new(db::Db::open(&PathBuf::from(&db_path))?));
    let app = server::router(state);

    tracing::info!(%addr, db = %db_path, "shoal listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
