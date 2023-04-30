use tracing::{debug, info};

use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Mutex;

use num_bigint::BigInt;
use tonic::transport::Channel;

use zkp_auth::auth_client::AuthClient;
use zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};

use crate::{ZkpClientAuthenticationStatus, ZkpClientRegistrationStatus};

// The Auth Client state - a hashset of the users currently registered with the system.
// In production, this would be a database instead.
lazy_static! {
    /// Maintains a set of the users registered via the client - this helps with fast
    /// lookups to check if the user has been registered or not.
    static ref REGISTERED_USERS: Mutex<HashSet<String>> = {
        let m = Mutex::new(HashSet::new());
        m
    };
}

/// The ZKP Chaum-Pedersen Prover
mod zkp_prover {
    use num_bigint::{BigInt, RandomBits};
    use num_traits::Signed;
    use once_cell::sync::OnceCell;
    use rand::Rng;
    use tracing::debug;

    // p, g, and h according to the Chaum-Pedersen protocl (as pert Smart)
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
    pub fn init() {
        P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32))
            .unwrap(); // 2^255 - 19
        G.set(BigInt::from(5u32)).unwrap();
        H.set(BigInt::from(3u32)).unwrap();
    }

    /// Generate the public data for the Chaum-Pedersen protocol - (y1, y2)
    pub fn gen_public(x: &BigInt) -> (BigInt, BigInt) {
        (get_g().modpow(&x, get_p()), get_h().modpow(&x, get_p()))
    }

    /// Generate the `k` for generating the challenge request parameters, (r1, r2)
    pub fn gen_random(k: &BigInt) -> (BigInt, BigInt) {
        debug!("k = {:?}", k);
        (get_g().modpow(&k, get_p()), get_h().modpow(&k, get_p()))
    }

    /// Generate `s`, the challenge answer (s = k - c * x)
    pub fn challenge_answer(c: BigInt, k: BigInt, x: BigInt) -> BigInt {
        debug!("c = {c:?}, k = {k:?}, x = {x:?}");
        k.clone() - c * x
    }
}

/// The wrapper module for the Auth protocol buffer definition (proto/zkp_auth.protoh)
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

/// Connect to the Auth Server
pub async fn connect_to_zkp_server() -> Result<AuthClient<Channel>, Box<dyn std::error::Error>> {
    info!("Connecting to the Auth Server");

    // In production, this would be read off of configuration files (encrypted)
    const DOCKER_ADDR: &'static str = "zkp_server";
    const NON_DOCKER_ADDR: &'static str = "0.0.0.0";

    let zkp_server_addr = std::env::var("DOCKER_MODE").map_or(NON_DOCKER_ADDR, |_| DOCKER_ADDR);
    let auth_client = AuthClient::connect(format!("http://{}:9999", zkp_server_addr)).await?;

    Ok(auth_client)
}

/// Register the user with the Auth Server
pub async fn register(
    user: String,
    password: String,
) -> Result<ZkpClientRegistrationStatus, Box<dyn std::error::Error>> {
    info!("Preparing to register with the Auth Server");

    if REGISTERED_USERS.lock().unwrap().contains(&user) {
        return Ok(ZkpClientRegistrationStatus::AlreadyRegistered);
    }

    let mut auth_client = connect_to_zkp_server().await?;

    // Initialise the ZKP Prover
    zkp_prover::init();

    let secret = BigInt::parse_bytes(password.as_bytes(), 10).unwrap();
    let (y1, y2) = zkp_prover::gen_public(&secret.clone());

    debug!("y1 = {y1:?}, y2 = {y2:?}");

    let request = tonic::Request::new(RegisterRequest {
        user: user.clone(),
        y1: y1.to_string(),
        y2: y2.to_string(),
    });

    auth_client.register(request).await?;

    // add user to the set of registered users
    REGISTERED_USERS.lock().unwrap().insert(user);

    info!("User registered");

    Ok(ZkpClientRegistrationStatus::Registered)
}

/// Attempt to authenticate the user with the Auth Server
pub async fn login(
    user: String,
    password: String,
) -> Result<ZkpClientAuthenticationStatus, Box<dyn std::error::Error>> {
    info!("Preparing to log on to the Auth Server");

    if !REGISTERED_USERS.lock().unwrap().contains(&user) {
        return Ok(ZkpClientAuthenticationStatus::UnregisteredUser);
    }

    let mut auth_client = connect_to_zkp_server().await?;

    // Commitment
    let password = BigInt::parse_bytes(password.as_bytes(), 10).unwrap();

    let k = zkp_prover::gen_random_with_n_bits::<128>();
    let (r1, r2) = zkp_prover::gen_random(&k);

    // Challenge request
    let challenge_response = auth_client
        .create_authentication_challenge(tonic::Request::new(AuthenticationChallengeRequest {
            user: user.clone(),
            r1: r1.to_string(),
            r2: r2.to_string(),
        }))
        .await?;

    debug!("challenge response: {challenge_response:?}");

    let challenge_response = challenge_response.into_inner();
    let (auth_id, c) = (
        challenge_response.auth_id,
        BigInt::parse_bytes(challenge_response.c.as_bytes(), 10).unwrap(),
    );

    // Challenge answer
    // Authentication status
    match auth_client
        .verify_authentication(tonic::Request::new(AuthenticationAnswerRequest {
            auth_id,
            s: zkp_prover::challenge_answer(c, k, password).to_string(),
        }))
        .await
    {
        Ok(response) => {
            info!("User {user:?} authenticated");

            let response = response.into_inner();
            Ok(ZkpClientAuthenticationStatus::Authenticated {
                session_id: response.session_id,
            })
        }

        Err(status) => {
            info!("User  {user:?} not authenticated");
            Ok(ZkpClientAuthenticationStatus::NotAuthenticated {
                status: status.message().to_string(),
            })
        }
    }
}
