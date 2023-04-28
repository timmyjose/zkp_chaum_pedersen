use once_cell::sync::OnceCell;
use std::collections::HashMap;

type SessionId = String;

static mut LOGGED_IN_USERS: OnceCell<HashMap<String, SessionId>> = OnceCell::new();

/// External routes
mod filters {
    use super::handlers;
    use super::models::LoginDetails;
    use warp::Filter;

    pub fn ext_clients(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        good_login().or(bad_login())
    }

    /// /good_login
    pub fn good_login(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("good_login")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_good_login)
    }

    /// /bad_login
    pub fn bad_login() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
    {
        warp::path!("bad_login")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_bad_login)
    }

    fn json_body() -> impl Filter<Extract = (LoginDetails,), Error = warp::Rejection> + Clone {
        warp::body::json()
    }
}

/// Handlers for the external routes
mod handlers {
    use super::models::LoginDetails;
    use std::convert::Infallible;
    use warp::http::StatusCode;
    use zkp_client::zkp_auth_client;

    pub async fn handle_good_login(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        println!("login: {login:?}");
        zkp_auth_client::authenticate(login.user.clone(), login.password).await;
        Ok(StatusCode::NOT_FOUND)
    }

    pub async fn handle_bad_login(login: LoginDetails) -> Result<impl warp::Reply, Infallible> {
        println!("login: {login:?}");
        zkp_auth_client::authenticate(login.user.clone(), login.password).await;
        Ok(StatusCode::NOT_FOUND)
    }
}

/// A simple model for the putative user
mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct LoginDetails {
        pub user: String,
        pub password: i64,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = filters::ext_clients();

    warp::serve(endpoints).run(([0, 0, 0, 0], 8888)).await;

    Ok(())
}