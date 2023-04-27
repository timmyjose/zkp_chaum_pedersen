use tonic::{transport::Server, Request, Response, Status};

use crate::zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Debug, Default)]
pub struct AuthImpl {}

#[tonic::async_trait]
impl Auth for AuthImpl {
    /// Register the user with the ZKP verifier
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Got a register request: {request:?}");

        let reply = zkp_auth::RegisterResponse {};

        Ok(Response::new(reply))
    }

    /// Create an authentication challenge for the ZKP Prover
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Got an authentication challenge request: {request:?}");

        let reply = zkp_auth::AuthenticationChallengeResponse {
            auth_id: "fake auth string".into(),
            c: 12345,
        };

        Ok(Response::new(reply))
    }

    /// Verify the authentication challenge received from the ZKP Prover
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Got an authentication answer request: {request:?}");

        let reply = zkp_auth::AuthenticationAnswerResponse {
            session_id: "fake session id".into(),
        };

        Ok(Response::new(reply))
    }
}
