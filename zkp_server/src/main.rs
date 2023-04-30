use tonic::transport::Server;
use tracing::info;
use tracing_subscriber;

use zkp_server::{zkp_auth::auth_server::AuthServer, Verifier};

/// The entryppint for the ZKP Auth Server
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // In production, these would be read off of configuration files.
    const SERVER_ADDR: &'static str = "0.0.0.0";
    const SERVER_PORT: &'static str = "9999";

    let address = format!("{SERVER_ADDR}:{SERVER_PORT}").parse()?;
    let verifier = Verifier::default();

    info!("Started ZKP Server on port {SERVER_PORT}");

    Server::builder()
        .add_service(AuthServer::new(verifier))
        .serve(address)
        .await?;

    Ok(())
}
