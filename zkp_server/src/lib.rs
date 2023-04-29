use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use num_bigint::{BigInt, RandomBits};
use num_integer::Integer;
use num_traits::{identities::Zero, One, Signed};
use tonic::{transport::Server, Code, Request, Response, Status};

use crate::zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

pub mod verifier {
    use num_bigint::{BigInt, RandomBits};
    use num_integer::Integer;
    use num_traits::{identities::Zero, One, Signed};
    use once_cell::sync::OnceCell;
    use rand::Rng;

    #[derive(Default)]
    pub struct Verifier;

    impl Verifier {
        pub fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32)) // 2^255 - 19
                .map_err(|_| format!("Could not set prime P"))?;
            println!("P = {}", get_p());
            G.set(BigInt::from(5u32))
                .map_err(|_| format!("Could not set generator G"))?;
            H.set(BigInt::from(3u32))
                .map_err(|_| format!("Could not set generator H"))?;

            Ok(())
        }

        pub fn request_challenge(&mut self, r1: BigInt, r2: BigInt) -> BigInt {
            gen_random_with_n_bits::<64>() // TODO - change this to 128 (or more)
        }

        pub fn verify(
            &mut self,
            s: BigInt,
            c: BigInt,
            y1: BigInt,
            y2: BigInt,
            r1: BigInt,
            r2: BigInt,
        ) -> bool {
            println!("s = {s:?}");

            let (val1, val2) = if s < BigInt::zero() {
                let v1 = get_g().modpow(&-s.clone(), get_p());
                let v2 = get_h().modpow(&-s, get_p());

                (
                    get_extended_euclidean(v1, get_p().clone()),
                    get_extended_euclidean(v2, get_p().clone()),
                )
            } else {
                (get_g().modpow(&s, get_p()), get_h().modpow(&s, get_p()))
            };

            let (val3, val4) = if c < BigInt::zero() {
                let v1 = y1.modpow(&c, get_p());
                let v2 = y2.modpow(&c, get_p());

                (
                    get_extended_euclidean(v1, get_p().clone()),
                    get_extended_euclidean(v2, get_p().clone()),
                )
            } else {
                (y1.modpow(&c, get_p()), y2.modpow(&c, get_p()))
            };

            let r1_prime = (val1 * val3).mod_floor(get_p());
            let r2_prime = (val2 * val4).mod_floor(get_p());

            println!("r1 = {:?}, r2 = {:?}", r1, r2);
            println!("r1_prime = {r1_prime:?}, r2_prime = {r2_prime:?}");

            r1 == r1_prime && r2 == r2_prime
        }
    }

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

    fn gen_random_with_n_bits<const N: u64>() -> BigInt {
        let mut rng = rand::thread_rng();
        rng.sample::<BigInt, _>(RandomBits::new(N)).abs()
    }

    // source:https://medium.com/asecuritysite-when-bob-met-alice/to-the-builders-of-our-future-meet-the-chaum-pedersen-non-interactive-zero-knowledge-proof-method-9846dee47fbc
    fn get_extended_euclidean(b: BigInt, phi: BigInt) -> BigInt {
        let mut u = vec![BigInt::one(), BigInt::zero(), phi.clone()];
        let mut v = vec![BigInt::zero(), BigInt::one(), b];

        while v[2] != BigInt::zero() {
            let q = u[2].clone() / v[2].clone();
            let temp1 = u[0].clone() - q.clone() * v[0].clone();
            let temp2 = u[1].clone() - q.clone() * v[1].clone();
            let temp3 = u[2].clone() - q.clone() * v[2].clone();
            u[0] = v[0].clone();
            u[1] = v[1].clone();
            u[2] = v[2].clone();
            v[0] = temp1;
            v[1] = temp2;
            v[2] = temp3;
        }

        if u[1] < BigInt::zero() {
            u[1].clone() + phi
        } else {
            u[1].clone()
        }
    }
}

// Verifier state
type UserVerifierState = (BigInt, BigInt);

// REGISTERED USERS
lazy_static! {
    static ref REGISTERED_USERS: Mutex<HashMap<String, UserVerifierState>> = {
        let mut m = Mutex::new(HashMap::new());
        m
    };
}

/// The interface module for the Auth protocol buffer definition
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tonic::async_trait]
impl Auth for verifier::Verifier {
    /// Register the user
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Got a register request: {request:?}");

        let request = request.into_inner();

        // if the call came from a different client, such as grocul, for instance
        if REGISTERED_USERS.lock().unwrap().contains_key(&request.user) {
            return Ok(Response::new(zkp_auth::RegisterResponse {}));
        }

        let y1 = BigInt::parse_bytes(request.y1.as_bytes(), 10)
            .ok_or(Status::new(Code::InvalidArgument, "failed to extract y1"))?;

        let y2 = BigInt::parse_bytes(request.y2.as_bytes(), 10)
            .ok_or(Status::new(Code::InvalidArgument, "failed to extract y2"))?;

        REGISTERED_USERS
            .lock()
            .unwrap()
            .insert(request.user, (y1, y2));

        println!(
            "[Server] REGISTERED_USERS = {:?}",
            REGISTERED_USERS.lock().unwrap()
        );

        Ok(Response::new(zkp_auth::RegisterResponse {}))
    }

    /// Create an authentication challenge for the ZKP Prover
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Got an authentication challenge request: {request:?}");

        let reply = zkp_auth::AuthenticationChallengeResponse {
            auth_id: "fake auth string".into(),
            c: "12345".to_owned(),
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
