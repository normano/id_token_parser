use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::{rng, Rng};
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde::{Deserialize, Serialize};

use super::GoogleTokenParser;

pub const KID: &str = "some-kid";
pub const CLIENT_ID: &str = "some-client-id";
pub const EMAIL: &str = "alex@kviring.com";
pub const SUB: &str = "11112222333344445555";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
  pub email: String,
  pub aud: String,
  pub iss: String,
  pub sub: String,
  pub exp: u64,
}

impl TokenClaims {
  pub fn new() -> Self {
    TokenClaims::new_with_expire(Duration::from_secs(10))
  }

  pub fn new_with_expire(expire: Duration) -> Self {
    Self {
      email: EMAIL.to_owned(),
      aud: CLIENT_ID.to_owned(),
      exp: SystemTime::now()
        .add(expire)
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs(),
      iss: "https://accounts.google.com".to_owned(),
      sub: SUB.to_owned(),
    }
  }

  pub fn new_expired() -> Self {
    let mut result = TokenClaims::new();
    result.exp = 0;
    result
  }
}

fn get_mock_google_pubkey_route(server: &MockServer,) -> (String, String) {
  let random_number: u32 = rand::rng().random_range(0..10000);

  let route = format!("/cert/{}", random_number);
  return (format!("{}{}", server.base_url(), route), route);
}

pub fn setup(server: &MockServer, claims: &TokenClaims) -> (String, GoogleTokenParser) {

  let mut header = Header::new(Algorithm::RS256);
  header.kid = Some(KID.to_owned());
  header.typ = Some("JWT".to_owned());

  let bits = 2048;
  let private_key = RsaPrivateKey::new(&mut rng(), bits).expect("failed to generate a key");
  let der = private_key.to_pkcs1_der().unwrap();
  let key = EncodingKey::from_rsa_der(der.to_bytes().as_slice());
  let token = jsonwebtoken::encode::<TokenClaims>(&header, &claims, &key).unwrap();

  let public_key = private_key.to_public_key();
  let n = BASE64_URL_SAFE_NO_PAD.encode(public_key.n().to_be_bytes());
  let e = BASE64_URL_SAFE_NO_PAD.encode(public_key.e().to_be_bytes_trimmed_vartime());

  let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, KID);

  let pub_key_route = get_mock_google_pubkey_route(server);
  server.mock(|when, then| {
    when.method(httpmock::Method::GET).path(pub_key_route.1);

    then.status(200)
      .header(
          "cache-control",
          "public, max-age=24920, must-revalidate, no-transform",
      )
      .header("Content-Type", "application/json; charset=UTF-8")
      .body(resp);
  });

  let mut parser = GoogleTokenParser::new(&pub_key_route.0);
  parser.add_client_id(CLIENT_ID);
  
  (
    token,
    parser,
  )
}
