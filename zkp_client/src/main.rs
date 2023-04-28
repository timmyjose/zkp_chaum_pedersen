use zkp_auth::auth_client::AuthClient;
use zkp_auth::{RegisterRequest, RegisterResponse};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

mod filters {
    use super::handlers;
    use super::models::User;
    use warp::Filter;

    pub fn ext_clients(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        good_login().or(bad_login())
    }

    // /good_login
    pub fn good_login(
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("good_login")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_good_login)
    }

    // /bad_login
    pub fn bad_login() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
    {
        warp::path!("bad_login")
            .and(warp::post())
            .and(json_body())
            .and_then(handlers::handle_bad_login)
    }

    fn json_body() -> impl Filter<Extract = (User,), Error = warp::Rejection> + Clone {
        warp::body::json()
    }
}

mod handlers {
    use super::models::User;
    use std::convert::Infallible;
    use warp::http::StatusCode;

    pub async fn handle_good_login(user: User) -> Result<impl warp::Reply, Infallible> {
        println!("user: {user:?}");
        Ok(StatusCode::NOT_FOUND)
    }

    pub async fn handle_bad_login(user: User) -> Result<impl warp::Reply, Infallible> {
        println!("user: {user:?}");
        Ok(StatusCode::NOT_FOUND)
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct User {
        name: String,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = filters::ext_clients();

    warp::serve(endpoints).run(([0, 0, 0, 0], 8888)).await;

    Ok(())
}