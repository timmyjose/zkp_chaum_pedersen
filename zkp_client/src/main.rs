use tracing::info;

/// External REST endpoints for the ZKP Client
mod filters {
    use super::handlers;
    use super::models::LoginDetails;
    use warp::Filter;

    pub fn ext_clients(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        register().or(login())
    }

    /// POST /register with expected payload, { user : String, password: String  }
    pub fn register() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
    {
        warp::path!("register")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_registration)
    }

    /// POST /login with expected payload, { user: String, password: String }
    pub fn login() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("login")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_login)
    }

    fn json_body() -> impl Filter<Extract = (LoginDetails,), Error = warp::Rejection> + Clone {
        warp::body::json()
    }
}

/// Handlers for the external REST endpoints
mod handlers {
    use super::models::LoginDetails;
    use std::convert::Infallible;
    use tracing::{debug, info};
    use warp::{http::StatusCode, reply};
    use zkp_client::{zkp_auth_client, ZkpClientAuthenticationStatus, ZkpClientRegistrationStatus};

    /// Register the user with the Auth Server via the ZKP Auth client
    pub async fn handle_registration(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        info!("Registering user {:?} with the server", login.user);
        debug!("Registration payload: {login:?}");

        Ok(
            match zkp_auth_client::register(login.user.clone(), login.password)
                .await
                .unwrap()
            {
                ZkpClientRegistrationStatus::Registered => {
                    reply::with_status("User registered", StatusCode::CREATED)
                }

                ZkpClientRegistrationStatus::AlreadyRegistered => {
                    reply::with_status("User already registered", StatusCode::CONFLICT)
                }
            },
        )
    }

    /// Attempt to log onto the Auth Server via the ZKP Auth Client
    pub async fn handle_login(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        info!("Attempting to log user {:?} in", login.user);
        debug!("Login payload: {login:?}");

        Ok(
            match zkp_auth_client::login(login.user.clone(), login.password)
                .await
                .unwrap()
            {
                ZkpClientAuthenticationStatus::UnregisteredUser => reply::with_status(
                    format!("User {} is not registered!", login.user),
                    StatusCode::NOT_FOUND,
                ),
                ZkpClientAuthenticationStatus::Authenticated { session_id } => reply::with_status(
                    format!("login successful, session_id = {session_id}"),
                    StatusCode::UNAUTHORIZED,
                ),
                ZkpClientAuthenticationStatus::NotAuthenticated { status } => {
                    reply::with_status(format!("login failed, reason = {status}"), StatusCode::OK)
                }
            },
        )
    }
}

/// A simple model for the putative user
mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct LoginDetails {
        pub user: String,
        // so that we can read in a BigInt. `serde` and `num_bigint` do support native big integers
        // but the JSON format does not, unfortunately.
        pub password: String,
    }
}

/// The REST interface for the ZKP Auth client
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In a real project, this would be read off of a configuration file
    const CLIENT_ADDR: [u8; 4] = [0u8, 0u8, 0u8, 0u8];
    const CLIENT_PORT: u16 = 8888u16;

    tracing_subscriber::fmt::init();

    let endpoints = filters::ext_clients();

    info!("Started ZKP Client on port {CLIENT_PORT:?}");

    warp::serve(endpoints).run((CLIENT_ADDR, CLIENT_PORT)).await;

    Ok(())
}