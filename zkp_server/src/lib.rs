use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use num_bigint::BigInt;
use tonic::{Code, Request, Response, Status};
use tracing::{debug, info};

use crate::zkp_auth::{
    auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse,
};

pub mod zkp_verifier {
    use num_bigint::{BigInt, RandomBits};
    use num_integer::Integer;
    use num_traits::{identities::Zero, One, Signed};
    use once_cell::sync::OnceCell;
    use rand::Rng;
    use tracing::debug;

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

    // source: https://medium.com/asecuritysite-when-bob-met-alice/to-the-builders-of-our-future-meet-the-chaum-pedersen-non-interactive-zero-knowledge-proof-method-9846dee47fbc
    fn get_extended_euclidean(b: &BigInt, phi: &BigInt) -> BigInt {
        let mut u = vec![BigInt::one(), BigInt::zero(), phi.clone()];
        let mut v = vec![BigInt::zero(), BigInt::one(), b.clone()];

        while v[2] != BigInt::zero() {
            let q = &u[2] / &v[2];
            let temp1 = &u[0] - &q * &v[0];
            let temp2 = &u[1] - &q * &v[1];
            let temp3 = &u[2] - &q * &v[2];

            u[0] = std::mem::take(&mut v[0]);
            u[1] = std::mem::take(&mut v[1]);
            u[2] = std::mem::take(&mut v[2]);
            v[0] = temp1;
            v[1] = temp2;
            v[2] = temp3;
        }

        if u[1] < BigInt::zero() {
            &u[1] + phi
        } else {
            std::mem::take(&mut u[1])
        }
    }

    /// Initialise the ZKP Verifier
    pub fn init() {
        P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32))
            .unwrap();
        G.set(BigInt::from(5u32)).unwrap();
        H.set(BigInt::from(3u32)).unwrap();
    }

    /// The `c` in the Chaum-Pedersen protocol (as per Smart)
    pub fn request_challenge() -> BigInt {
        gen_random_with_n_bits::<128>()
    }

    /// Verify that the same password/secret as was used during the generation of (y1, y2), the
    /// public data, is being used to generate the challenge response (from the client). This
    /// verifies that the entered password is correct (or not).
    pub fn verify(
        s: &BigInt,
        c: &BigInt,
        y1: &BigInt,
        y2: &BigInt,
        r1: &BigInt,
        r2: &BigInt,
    ) -> bool {
        debug!("s = {s:?}, c = {c:?}, y1: {y1:?}, y2: {y2:?}, r1 =  {r1:?}, r2: {r2:?}");

        let (val1, val2) = if *s < BigInt::zero() {
            let v1 = get_g().modpow(&-s, get_p());
            let v2 = get_h().modpow(&-s, get_p());

            (
                get_extended_euclidean(&v1, &get_p()),
                get_extended_euclidean(&v2, &get_p()),
            )
        } else {
            (get_g().modpow(&s, get_p()), get_h().modpow(&s, get_p()))
        };

        let (val3, val4) = if *c < BigInt::zero() {
            let v1 = y1.modpow(&c, &get_p());
            let v2 = y2.modpow(&c, &get_p());

            (
                get_extended_euclidean(&v1, &get_p()),
                get_extended_euclidean(&v2, &get_p()),
            )
        } else {
            (y1.modpow(&c, get_p()), y2.modpow(&c, get_p()))
        };

        let r1_prime = (val1 * val3).mod_floor(get_p());
        let r2_prime = (val2 * val4).mod_floor(get_p());

        debug!("r1 = {:?}, r2 = {:?}", r1, r2);
        debug!("r1_prime = {r1_prime:?}, r2_prime = {r2_prime:?}");

        *r1 == r1_prime && *r2 == r2_prime
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_init() {
            init();

            assert_eq!(*get_p(), BigInt::from(2u32).pow(255) - BigInt::from(19u32));
            assert_eq!(*get_g(), BigInt::from(5u32));
            assert_eq!(*get_h(), BigInt::from(3u32));
        }
    }
}

/// Verifier state
#[derive(Debug, Default, Clone)]
struct VerifierUserState {
    y1: BigInt,
    y2: BigInt,
    r1: Option<BigInt>,
    r2: Option<BigInt>,
    c: Option<BigInt>,
}

// Registered Users
// In production, this would be a database instead.
lazy_static! {
    /// maps the users against the state needed for the Chaum-Pedersen protocol - this
    /// is needed since gRPC is stateless, and we need the state to persist across
    /// the request steps.
    static ref REGISTERED_USERS: Mutex<HashMap<String, VerifierUserState>> = {
        let m = Mutex::new(HashMap::new());
        m
    };

    /// Maps the `auth_id` generated by the server (and which is sent to the client), so that we
    /// can match it in the challenge verification step.
    static ref AUTH_ID_USER_MAP: Mutex<HashMap<BigInt, String>> = {
        let m = Mutex::new(HashMap::new());
        m
    };
}

/// Wrapper module for the Auth protocol buffer definition
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

/// Wrapper struct for interacting with the gRPC code generated by tonic
#[derive(Debug, Default)]
pub struct Verifier {}

#[tonic::async_trait]
impl Auth for Verifier {
    /// Register the user with the system
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        info!("[Auth Server] Got a register request: {request:?}");
        debug!("[Auth Server] register payload = {request:?}");

        let request = request.into_inner();

        // if the call came from a different client, such as grpcurl, for instance
        if REGISTERED_USERS.lock().unwrap().contains_key(&request.user) {
            return Ok(Response::new(zkp_auth::RegisterResponse {}));
        }

        let y1 = BigInt::parse_bytes(request.y1.as_bytes(), 10)
            .ok_or(Status::new(Code::InvalidArgument, "failed to extract y1"))?;

        let y2 = BigInt::parse_bytes(request.y2.as_bytes(), 10)
            .ok_or(Status::new(Code::InvalidArgument, "failed to extract y2"))?;

        REGISTERED_USERS.lock().unwrap().insert(
            request.user,
            VerifierUserState {
                y1,
                y2,
                ..VerifierUserState::default()
            },
        );

        // initialise the verifier
        zkp_verifier::init();

        Ok(Response::new(zkp_auth::RegisterResponse {}))
    }

    /// Create an authentication challenge for the ZKP Prover
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        info!("[Auth Server] Got an authentication challenge request");
        debug!("[Auth Server] authentication challenge request payload: {request:?}");

        let request = request.into_inner();
        let (user, r1, r2) = (
            request.user,
            BigInt::parse_bytes(request.r1.as_bytes(), 10).unwrap(),
            BigInt::parse_bytes(request.r2.as_bytes(), 10).unwrap(),
        );

        // ensure that the user has been registered
        if !REGISTERED_USERS.lock().unwrap().contains_key(&user) {
            return Err(Status::new(Code::NotFound, "user is not registered"));
        }

        let auth_id = zkp_verifier::gen_random_with_n_bits::<128>();
        let challenge = zkp_verifier::request_challenge();

        let reply = zkp_auth::AuthenticationChallengeResponse {
            auth_id: auth_id.clone().to_string(),
            c: challenge.clone().to_string(),
        };

        // Update user state
        REGISTERED_USERS
            .lock()
            .unwrap()
            .entry(user.clone())
            .and_modify(|state| {
                state.c = Some(challenge);
                state.r1 = Some(r1);
                state.r2 = Some(r2)
            });

        // map the auth_id to the user - override to always have the latest mapping
        AUTH_ID_USER_MAP.lock().unwrap().insert(auth_id, user);

        Ok(Response::new(reply))
    }

    /// Verify the authentication challenge received from the ZKP Prover
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        info!("[Auth Server] Got an authentication answer request");
        debug!("[Auth Server] authentication answer payload: {request:?}");

        let request = request.into_inner();
        let (auth_id, s) = (
            BigInt::parse_bytes(request.auth_id.as_bytes(), 10).unwrap(),
            BigInt::parse_bytes(request.s.as_bytes(), 10).unwrap(),
        );

        // verifys: BigInt, c: BigInt, y1: BigInt, y2: BigInt, r1: BigInt, r2: BigInt
        let user_for_auth_id = AUTH_ID_USER_MAP
            .lock()
            .unwrap()
            .get(&auth_id)
            .clone()
            .unwrap()
            .clone();

        let user_state = REGISTERED_USERS
            .lock()
            .unwrap()
            .get(&user_for_auth_id)
            .clone()
            .unwrap()
            .clone();

        let (y1, y2, r1, r2, c) = (
            user_state.y1.clone(),
            user_state.y2.clone(),
            user_state.r1.clone().unwrap().clone(),
            user_state.r2.clone().unwrap().clone(),
            user_state.c.clone().unwrap().clone(),
        );

        if zkp_verifier::verify(&s, &c, &y1, &y2, &r1, &r2) {
            Ok(Response::new(zkp_auth::AuthenticationAnswerResponse {
                session_id: zkp_verifier::gen_random_with_n_bits::<128>().to_string(),
            }))
        } else {
            Err(Status::new(
                Code::Unauthenticated,
                "user authentication failed",
            ))
        }
    }
}
