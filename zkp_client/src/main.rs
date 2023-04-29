/// External routes
mod filters {
    use super::handlers;
    use super::models::LoginDetails;
    use warp::Filter;

    pub fn ext_clients(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        register().or(login())
    }

    /// POST /register with expected payload, { user : String, password: i64  }
    pub fn register() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
    {
        warp::path!("register")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_registration)
    }

    /// POST /login with expected payload, { user: String, password: i64 }
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

/// Handlers for the external routes
mod handlers {
    use super::models::LoginDetails;
    use std::convert::Infallible;
    use warp::{http::StatusCode, reply};
    use zkp_client::{zkp_auth_client, ZkpClientAuthenticationStatus, ZkpClientRegistrationStatus};

    /// Register the user with the Auth Server
    pub async fn handle_registration(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        println!("l[Registration] payload: {login:?}");

        // todo - fix unwrap
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

    /// Attempt to log onto the Auth Server
    pub async fn handle_login(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        println!("l[Login] payload: {login:?}");

        Ok(
            match zkp_auth_client::login(login.user.clone(), login.password)
                .await
                .unwrap()
            {
                ZkpClientAuthenticationStatus::UnregisteredUser => {
                    reply::with_status("user is not registered!", StatusCode::NOT_FOUND)
                }
                ZkpClientAuthenticationStatus::Authenticated => {
                    reply::with_status("login successful", StatusCode::UNAUTHORIZED)
                }
                ZkpClientAuthenticationStatus::NotAuthenticated => {
                    reply::with_status("login failed", StatusCode::OK)
                }
            },
        )
    }
}

/// A simple model for the putative user
mod models {
    use num_bigint::BigInt;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct LoginDetails {
        pub user: String,
        pub password: String,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = filters::ext_clients();

    warp::serve(endpoints).run(([0, 0, 0, 0], 8888)).await;

    Ok(())
}