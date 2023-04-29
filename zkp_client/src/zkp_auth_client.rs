use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use tonic::{transport::Channel, Response, Status};

use zkp_auth::auth_client::AuthClient;
use zkp_auth::{
    AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest, RegisterResponse,
};

use crate::{ZkpClientAuthenticationStatus, ZkpClientRegistrationStatus};

// Currently registered users based on their name.
lazy_static! {
    static ref REGISTERED_USERS: Mutex<HashMap<String, BigInt>> = {
        let mut m = Mutex::new(HashMap::new());
        m
    };
}

// The ZKP Chaum-Pedersen prover
mod zkp_prover {
    use num_bigint::{BigInt, RandomBits};
    use num_integer::Integer;
    use num_traits::{identities::Zero, One, Signed};
    use once_cell::sync::OnceCell;
    use rand::Rng;

    static P: OnceCell<BigInt> = OnceCell::new();
    static G: OnceCell<BigInt> = OnceCell::new();
    static H: OnceCell<BigInt> = OnceCell::new();

    fn get_p() -> &'static BigInt {
        P.get().unwrap()
    }

    fn get_g() -> &'static BigInt {
        G.get().unwrap()
    }

    fn get_h() -> &'static BigInt {
        H.get().unwrap()
    }

    pub fn gen_random_with_n_bits<const N: u64>() -> BigInt {
        let mut rng = rand::thread_rng();
        rng.sample::<BigInt, _>(RandomBits::new(N)).abs()
    }

    /// Initialise the ZKP Prover
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32))
            .map_err(|_| format!("Could not set prime P"))?;
        println!("P = {}", get_p());
        G.set(BigInt::from(5u32))
            .map_err(|_| format!("Could not set generator G"))?;
        H.set(BigInt::from(3u32))
            .map_err(|_| format!("Could not set generator H"))?;

        Ok(())
    }

    pub fn gen_public(x: BigInt) -> (BigInt, BigInt) {
        (get_g().modpow(&x, get_p()), get_h().modpow(&x, get_p()))
    }

    pub fn gen_random(k: BigInt) -> (BigInt, BigInt) {
        println!("k = {:?}", k);
        (get_g().modpow(&k, get_p()), get_h().modpow(&k, get_p()))
    }

    pub fn challenge_answer(c: BigInt, k: BigInt, x: BigInt) -> BigInt {
        println!("c = {c:?}, x = {x:?}");
        k.clone() - c * x
    }
}

/// The interface module for the Auth protocol buffer definition
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

/// Connect to the gRPC auth server
pub async fn connect_to_zkp_server() -> Result<AuthClient<Channel>, Box<dyn std::error::Error>> {
    let zkp_server_addr = std::env::var("DOCKER_MODE").map_or("0.0.0.0", |_| "zkp_server");
    let mut auth_client = AuthClient::connect(format!("http://{}:9999", zkp_server_addr)).await?;
    println!("auth_client = {auth_client:?}");

    Ok(auth_client)
}

/// Register the user with the gRPC auth server
pub async fn register(
    user: String,
    password: String,
) -> Result<ZkpClientRegistrationStatus, Box<dyn std::error::Error>> {
    println!("{:?}", REGISTERED_USERS.lock().unwrap());

    if REGISTERED_USERS.lock().unwrap().contains_key(&user) {
        return Ok(ZkpClientRegistrationStatus::AlreadyRegistered);
    }

    let mut auth_client = connect_to_zkp_server().await?;

    // Inititialise the ZKP Prover
    zkp_prover::init();

    // todo - unwrap
    let secret = BigInt::parse_bytes(password.as_bytes(), 10).unwrap();
    let (y1, y2) = zkp_prover::gen_public(secret.clone().into());

    println!("y1 = {y1:?}");

    let request = tonic::Request::new(RegisterRequest {
        user: user.clone(),
        y1: y1.to_string(),
        y2: y2.to_string(),
    });

    // todo - handle tonic Status error codes
    let response = auth_client.register(request).await?;
    println!("{response:?}");

    // add user to the map of registered users
    REGISTERED_USERS.lock().unwrap().insert(user, secret);

    Ok(ZkpClientRegistrationStatus::Registered)
}

/// Attempt to authenticate the user with the gRPC server
pub async fn login(
    user: String,
    password: String,
) -> Result<ZkpClientAuthenticationStatus, Box<dyn std::error::Error>> {
    if !REGISTERED_USERS.lock().unwrap().contains_key(&user) {
        return Ok(ZkpClientAuthenticationStatus::UnregisteredUser);
    }

    let mut auth_client = connect_to_zkp_server().await?;

    // inititailse the ZKP Prover
    zkp_prover::init();

    // Commitment
    // todo: unwrap - custom error message (?)
    let password = BigInt::parse_bytes(password.as_bytes(), 10).unwrap();

    let k = zkp_prover::gen_random_with_n_bits::<128>();
    let (r1, r2) = zkp_prover::gen_random(k.clone());

    // Challenge request
    let challenge_response = auth_client
        .create_authentication_challenge(tonic::Request::new(AuthenticationChallengeRequest {
            user: user.clone(),
            r1: r1.to_string(),
            r2: r2.to_string(),
        }))
        .await?;

    println!("challenge response: {challenge_response:?}");

    let challenge_response = challenge_response.into_inner();
    let (auth_id, c) = (
        challenge_response.auth_id,
        BigInt::parse_bytes(challenge_response.c.as_bytes(), 10).unwrap(),
    );

    // Challenge answer
    let secret = REGISTERED_USERS.lock().unwrap().get(&user).unwrap().clone();

    // Authentication status
    match auth_client
        .verify_authentication(tonic::Request::new(AuthenticationAnswerRequest {
            auth_id,
            s: zkp_prover::challenge_answer(c, k, password).to_string(),
        }))
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            println!("answer_response = {response:?}");
            Ok(ZkpClientAuthenticationStatus::Authenticated)
        }
        Err(status) => {
            eprintln!("{status:?}");

            Ok(ZkpClientAuthenticationStatus::NotAuthenticated)
        }
    }
}
