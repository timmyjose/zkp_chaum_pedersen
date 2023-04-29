use tonic::transport::Server;
use tracing::info;
use tracing_subscriber;

use zkp_server::{zkp_auth::auth_server::AuthServer, Verifier};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let address = "0.0.0.0:9999".parse()?;
    let verifier = Verifier::default();

    info!("Started ZKP Auth Server on port 9999");

    Server::builder()
        .add_service(AuthServer::new(verifier))
        .serve(address)
        .await?;

    Ok(())
}
