use zkp_auth::auth_client::AuthClient;
use zkp_auth::{RegisterRequest, RegisterResponse};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut auth_client = AuthClient::connect("http://127.0.0.1:9999").await?;

    let request = tonic::Request::new(RegisterRequest {
        user: "dummy user".into(),
        y1: 54321,
        y2: 54321,
    });

    let response = auth_client.register(request).await?;
    println!("{response:?}");

    Ok(())
}