use tonic::{transport::Server, Request, Response, Status};

use zkp_server::{
    zkp_auth::{
        auth_server::{Auth, AuthServer},
        RegisterRequest, RegisterResponse,
    },
    Verifier,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = "0.0.0.0:9999".parse()?;

    let verifier = Verifier::default();

    Server::builder()
        .add_service(AuthServer::new(verifier))
        .serve(address)
        .await?;

    Ok(())
}
