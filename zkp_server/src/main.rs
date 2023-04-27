use tonic::{transport::Server, Request, Response, Status};

use zkp_server::{
    zkp_auth::{
        auth_server::{Auth, AuthServer},
        RegisterRequest, RegisterResponse,
    },
    AuthImpl,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = "0.0.0.0:9999".parse()?;

    let auth_server = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(address)
        .await?;

    Ok(())
}
