use num_bigint::{BigInt, RandomBits};
use num_integer::Integer;
use num_traits::{identities::Zero, One, Signed};
use rand::Rng;

use std::collections::HashMap;

use once_cell::sync::OnceCell;
use tonic::{transport::Server, Request, Response, Status};

use crate::zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

type AuthId = i64;

static mut VERIFIED_USERS: OnceCell<HashMap<String, AuthId>> = OnceCell::new();

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

#[derive(Default)]
pub struct Verifier {
    y1: BigInt,
    y2: BigInt,
    r1: BigInt,
    r2: BigInt,
    c: BigInt,
}

impl Verifier {
    pub fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32))
            .map_err(|_| format!("Could not set prime P"))?;
        println!("P = {}", get_p());
        G.set(BigInt::from(5u32))
            .map_err(|_| format!("Could not set generator G"))?;
        H.set(BigInt::from(3u32))
            .map_err(|_| format!("Could not set generator H"))?;

        Ok(())
    }

    pub fn register(&mut self, y1: BigInt, y2: BigInt) {
        println!("y1 = {y1:?}, y2 = {y2:?}");
        self.y1 = y1;
        self.y2 = y2;
    }

    pub fn request_challenge(&mut self, r1: BigInt, r2: BigInt) -> BigInt {
        self.r1 = r1;
        self.r2 = r2;

        self.c = gen_random_with_n_bits::<128>();
        self.c.clone()
    }

    pub fn verify(&mut self, s: BigInt) -> bool {
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

        let (val3, val4) = if self.c < BigInt::zero() {
            let v1 = self.y1.modpow(&self.c, get_p());
            let v2 = self.y2.modpow(&self.c, get_p());

            (
                get_extended_euclidean(v1, get_p().clone()),
                get_extended_euclidean(v2, get_p().clone()),
            )
        } else {
            (
                self.y1.modpow(&self.c, get_p()),
                self.y2.modpow(&self.c, get_p()),
            )
        };

        let r1_prime = (val1 * val3).mod_floor(get_p());
        let r2_prime = (val2 * val4).mod_floor(get_p());

        println!("r1 = {:?}, r2 = {:?}", self.r1, self.r2);
        println!("r1_prime = {r1_prime:?}, r2_prime = {r2_prime:?}");

        self.r1 == r1_prime && self.r2 == r2_prime
    }
}

#[tonic::async_trait]
impl Auth for Verifier {
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
