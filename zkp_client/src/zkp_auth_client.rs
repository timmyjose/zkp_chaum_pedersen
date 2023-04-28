use num_bigint::BigInt;
use num_traits::Zero;

use zkp_auth::auth_client::AuthClient;
use zkp_auth::{RegisterRequest, RegisterResponse};

/// The ZKP Chaum-Pedersen prover
mod prover {
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

    fn gen_random_with_n_bits<const N: u64>() -> BigInt {
        let mut rng = rand::thread_rng();
        rng.sample::<BigInt, _>(RandomBits::new(N)).abs()
    }

    #[derive(Default)]
    pub(crate) struct Prover {
        x: BigInt,
        k: BigInt,
    }

    impl Prover {
        pub async fn init(&mut self, x: BigInt) -> Result<(), Box<dyn std::error::Error>> {
            P.set(BigInt::from(2u32).pow(255) - BigInt::from(19u32))
                .map_err(|_| format!("Could not set prime P"))?;
            println!("P = {}", get_p());
            G.set(BigInt::from(5u32))
                .map_err(|_| format!("Could not set generator G"))?;
            H.set(BigInt::from(3u32))
                .map_err(|_| format!("Could not set generator H"))?;
            self.x = x;

            Ok(())
        }

        pub fn gen_public(&mut self) -> (BigInt, BigInt) {
            (
                get_g().modpow(&self.x, get_p()),
                get_h().modpow(&self.x, get_p()),
            )
        }

        pub fn gen_random(&mut self) -> (BigInt, BigInt) {
            self.k = gen_random_with_n_bits::<128>();
            println!("k = {:?}", self.k);
            (
                get_g().modpow(&self.k, get_p()),
                get_h().modpow(&self.k, get_p()),
            )
        }

        pub fn challenge_answer(&mut self, c: BigInt) -> BigInt {
            println!("c = {c:?}");
            self.k.clone() - c * self.x.clone()
        }
    }
}

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

/// The ZKP Chaum-Pedersen client protocol
///
/// Chaum Perdersen Proof Protocol algorithm:
///
/// Select p = 2^255 - 19 (Curve25519, 128 bits)
///
/// Select generators g = 5, h = 3.
///
/// Prover generates (y1, y2) = (g ^ x mod p, h ^ x mod p), where 'x' is the secret value.
///
/// Public knowledge - (y1, y2, p) shared between prover and verifier.
///
/// Prover generates a random value k (in the range [0, p - 1]).
///
/// Prover sends (r1, r2) = (g ^ k mod p, h ^ k mod p) to the Verifier.
///
/// Verifier notes these values and generates a random value k (in the range [0, p - 1]).
/// Sends this to the Prover.
///
/// Prover then sends across value s = (k - c * x) mod p. Sends this to the Verifier.
///
/// Verifier computers (r1', r2') = ((g ^ s . y1 ^ c) mod p, (h ^ s . y2 ^ c) mod p).
/// If (r1, r2) == (r1', r2') then verified else not verified.
///
///
pub async fn authenticate() -> Result<(), Box<dyn std::error::Error>> {
    let mut auth_client = AuthClient::connect("http://zkp_server:9999").await?;

    let mut prover = prover::Prover::default();
    prover.init(BigInt::zero()).await?;

    let request = tonic::Request::new(RegisterRequest {
        user: "dummy user".into(),
        y1: 54321,
        y2: 54321,
    });

    let response = auth_client.register(request).await?;
    println!("{response:?}");

    Ok(())
}
