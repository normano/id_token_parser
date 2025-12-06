#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::perf)]
#![deny(clippy::nursery)]
#![deny(clippy::match_like_matches_macro)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod client;
mod data;
mod error;
mod keys;

pub use data::{Claims, ClaimsServer2Server};
pub use error::Error;

use data::{KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS_URL};
use error::Result;
use jsonwebtoken::{self, decode, decode_header, DecodingKey, TokenData, Validation};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

use crate::apple::keys::ApplePublicKeyProvider;

pub struct AppleTokenParser {
  key_provider: Mutex<ApplePublicKeyProvider>,
}

impl AppleTokenParser {
  pub fn new(base_url: &str) -> Self {
    Self {
      key_provider: Mutex::new(ApplePublicKeyProvider::new(base_url)),
    }
  }

  pub fn default() -> Self {
    return Self::new(APPLE_PUB_KEYS_URL);
  }

  #[instrument(skip(self, token))]
  pub async fn parse(&self, client_id: String, token: String, ignore_expire: bool) -> Result<TokenData<Claims>> {
    let token_data = self.decode::<Claims>(client_id.clone(), token, ignore_expire).await?;

    //TODO: can this be validated already in `decode_token`?
    if token_data.claims.iss != APPLE_ISSUER {
      return Err(Error::IssClaimMismatch);
    }

    if token_data.claims.aud != client_id {
      return Err(Error::ClientIdMismatch);
    }
    Ok(token_data)
  }

  /// decode token with no validation
  #[instrument(skip(self, token))]
  pub async fn decode<T: DeserializeOwned>(&self, client_id: String, token: String, ignore_expire: bool) -> Result<TokenData<T>> {
    let header = decode_header(token.as_str())?;

    let kid = match header.kid {
      Some(k) => k,
      None => return Err(Error::KidNotFound),
    };
    info!(?kid, "Extracted kid from token header");

    let mut provider = self.key_provider.lock().await;
    let decoding_key = provider.get_key(&kid).await?;

    let aud = &[client_id];
    let mut validation = Validation::new(header.alg);
    validation.set_audience(aud.as_slice());
    validation.validate_exp = !ignore_expire;
    validation.validate_aud = false;

    let token_data = decode::<T>(token.as_str(), &decoding_key, &validation).map_err(|err| {
      info!(?err, "JWT decoding failed");
      err
    })?;

    Ok(token_data)
  }
}

/// allows to check whether the `validate` result was errored because of an expired signature
#[must_use]
pub fn is_expired(validate_result: &Result<TokenData<Claims>>) -> bool {
  if let Err(Error::Jwt(error)) = validate_result {
    return matches!(error.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature);
  }

  false
}

#[cfg(test)]
mod tests {
  use std::time::{SystemTime, UNIX_EPOCH};

  use super::*;
  use base64::prelude::*;
  use httpmock::{Method::GET, MockServer};
  use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
  use once_cell::sync::Lazy;
  use rand::{Rng, SeedableRng, rng, rngs::StdRng};
  use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey};
  use serde::{Deserialize, Serialize};
  use tracing::{info, level_filters::LevelFilter};

  static MOCK_SERVER: Lazy<MockServer> = Lazy::new(|| {
    let server = MockServer::start();
    server
  });

  // Helper to initialize the logger for tests
  fn init_subscriber() {
    let _ = tracing_subscriber::fmt()
      .with_max_level(LevelFilter::TRACE)
      .with_test_writer()
      .try_init();
  }

  fn get_mock_apple_pubkey_route() -> (String, String) {
    let random_number: u32 = rand::rng().random_range(0..10000);

    let route = format!("/apple/keys/{}", random_number);
    return (format!("{}{}", MOCK_SERVER.base_url(), route), route);
  }

  #[derive(Serialize, Deserialize)]
  struct AppleKeysResponse {
    keys: Vec<KeyComponents>,
  }

  fn create_sample_token(client_id: &str, issuer: &str, exp: i64) -> (String, KeyComponents) {
    // Step 1: Generate RSA private key (for testing purposes)
    let mut rng = StdRng::from_rng(&mut rng());
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let encoding_key = EncodingKey::from_rsa_der(&private_key.to_pkcs1_der().unwrap().as_bytes());

    // Step 2: Create claims for the token
    let my_claims = Claims {
      aud: client_id.to_string(),
      iss: issuer.to_string(),
      exp,
      auth_time: 0,
      email: None,
      email_verified: None,
      iat: 0,
      sub: "".to_string(),
    };

    let header = {
      let mut inner = Header::new(Algorithm::RS256);
      inner.kid = Some("test_kid".to_string());
      inner
    };

    // Step 3: Encode the token using the DER-based key
    let token = encode(&header, &my_claims, &encoding_key).unwrap();

    // Step 4: Extract public components for the JWK. This part was correct before.
    let public_key = private_key.to_public_key();
    let key_comps = KeyComponents {
      kid: "test_kid".to_string(),
      n: BASE64_URL_SAFE_NO_PAD.encode(public_key.n().to_be_bytes()),
      e: BASE64_URL_SAFE_NO_PAD.encode(public_key.e().to_be_bytes_trimmed_vartime()),
      alg: "RS256".to_string(),
      kty: "RSA".to_string(),
      r#use: "sig".to_string(),
    };

    (token, key_comps)
  }

  fn get_current_timestamp() -> usize {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("Time went backwards")
      .as_secs() as usize
  }

  #[tokio::test]
  async fn test_validate_success() {
    init_subscriber();
    let client_id = "test-client-id";
    let (token, key_components) = create_sample_token(
      client_id,
      APPLE_ISSUER,
      (get_current_timestamp() + 3600).try_into().unwrap(),
    );

    let keys_route = get_mock_apple_pubkey_route();
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then.status(200).json_body_obj(&AppleKeysResponse {
        keys: vec![key_components],
      });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);
    let result = apple_signin.parse(client_id.to_string(), token, false).await;

    assert!(result.is_ok(), "Validation failed with: {:?}", result.err());
    let token_data = result.unwrap();
    assert_eq!(token_data.claims.aud, client_id);
    assert_eq!(token_data.claims.iss, APPLE_ISSUER);
  }

  #[tokio::test]
  async fn test_validate_wrong_issuer() {
    init_subscriber();
    let client_id = "test-client-id";
    let wrong_issuer = "wrong-issuer";
    let (token, key_components) = create_sample_token(
      client_id,
      wrong_issuer,
      (get_current_timestamp() + 3600).try_into().unwrap(),
    );

    let keys_route = get_mock_apple_pubkey_route();
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then.status(200).json_body_obj(&AppleKeysResponse {
        keys: vec![key_components],
      });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);
    let result = apple_signin.parse(client_id.to_string(), token, false).await;

    // Assert that validation fails due to IssClaimMismatch
    assert!(
      matches!(result, Err(Error::IssClaimMismatch)),
      "Expected IssClaimMismatch, but got {:?}",
      result
    );
  }

  #[tokio::test]
  async fn test_validate_wrong_client_id() {
    init_subscriber();
    let client_id = "wrong-client-id";
    let (token, key_components) = create_sample_token(
      client_id,
      APPLE_ISSUER,
      (get_current_timestamp() + 3600).try_into().unwrap(),
    );

    let keys_route = get_mock_apple_pubkey_route();
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then.status(200).json_body_obj(&AppleKeysResponse {
        keys: vec![key_components],
      });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);
    let correct_client_id = "correct-client-id";
    let result = apple_signin.parse(correct_client_id.to_string(), token, false).await;

    // Assert that validation fails due to ClientIdMismatch
    assert!(
      matches!(result, Err(Error::ClientIdMismatch)),
      "Expected ClientIdMismatch, but got {:?}",
      result
    );
  }

  #[tokio::test]
  async fn test_validate_expired_token() {
    init_subscriber();
    let client_id = "test-client-id";
    let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, 1);

    let keys_route = get_mock_apple_pubkey_route();
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then.status(200).json_body_obj(&AppleKeysResponse {
        keys: vec![key_components],
      });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);
    let result = apple_signin.parse(client_id.to_string(), token, false).await;

    // Assert that validation fails due to the token being expired
    assert!(
      is_expired(&result),
      "Expected ExpiredSignature error, but got {:?}",
      result
    );
  }

  #[tokio::test]
  async fn test_validate_ignore_expired_token() {
    init_subscriber();
    info!("Starting test: test_validate_ignore_expired_token");

    let client_id = "test-client-id";
    // create_sample_token will also produce logs if instrumented
    let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, 1);

    // 2. Log the token and key details for inspection.
    debug!(%token, ?key_components, "Generated expired token and key components");

    let keys_route = get_mock_apple_pubkey_route();

    // 3. Log the mock server configuration.
    info!(mock_url = %keys_route.0, "Setting up mock JWKS endpoint");
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then.status(200).json_body_obj(&AppleKeysResponse {
        keys: vec![key_components],
      });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);

    // The `parse` method itself should be instrumented to see its internal flow.
    let result = apple_signin.parse(client_id.to_string(), token, true).await;

    // 4. Log the final result before the assertion. This is crucial for debugging.
    info!(?result, "Received result from parsing with ignore_expire=true");

    // Assert that validation succeeds when `ignore_expire` is true.
    // The message will provide detailed error info if the assertion fails.
    assert!(
      result.is_ok(),
      "Validation should succeed when ignoring expiration, but it failed with: {:?}",
      result.err()
    );
  }

  #[ignore]
  #[tokio::test]
  async fn test_server_to_server_payload() {
    init_subscriber();
    let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidG93bi5waWVjZS5hcHAiLCJleHAiOjE2NTM3MjU1MjYsImlhdCI6MTY1MzYzOTEyNiwic3ViIjoiMDAwNDIyLjJkMWNlODE2Njk2ZTRkYTBiMjhhOTk3ZmJkYTBiYzU5LjA5MzEiLCJhdF9oYXNoIjoidVFGWTBVMmdjTkhBRzlacjluZ0hGdyIsImVtYWlsIjoidXN3dXJpa2lqaUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhdXRoX3RpbWUiOjE2NTM2MzkxMDEsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.i3Dp01s6RGc5NBu97Vw-VdvNi6ejilME1m1e-27Lv2P7nKUPUos2HJb888oiQRroC7E3zihDAL53FbsFp7kgGDVTt9R68YKdaM-Nwl97ywUP9ehVk1KuUd9rd4cHEN8Cms7YnJErSMIOmj3mMjg6ISEGQHrOPVtG9fk_9HqK7mcyxtnsAM9K-CxGbwzgVqJBgQK45qBq-lNPYnOJOKO6DQfOA86X0csYZ2wqFlc89Z3APOkL_Q_Y69ERq1YHyRg4IfW9puTURhjWRNpW_7Qt4RhP4ewWRKsJ1fr_E64bbpnLFyepJLBHYePNiEbfZfd0k_crdSS4_fuzHWHFsDqddg";

    let keys_route = get_mock_apple_pubkey_route();
    // MOCK_SERVER.mock(|when, then| {
    //   when.method(GET)
    // 		.path(&keys_route.1);
    //   then.status(200)
    // 		.json_body_obj(&AppleKeysResponse {
    // 				keys: vec![key_components],
    // 		});
    // });

    let client_id = "town.piece.app";
    let apple_signin = AppleTokenParser::new(&keys_route.0);
    let result = apple_signin
      .decode::<ClaimsServer2Server>(client_id.to_string(), token.to_string(), true)
      .await
      .unwrap();

    assert_eq!(result.claims.aud, client_id);
    assert_eq!(result.claims.events.sub, "000422.2d1ce816696e4da0b28a997fbda0bc59.0931");

    println!("{:?}", result);
  }

  #[tokio::test]
  async fn test_validate_success_with_cache() {
    init_subscriber();
    let client_id = "test-client-id";
    let (token, key_components) = create_sample_token(
      client_id,
      APPLE_ISSUER,
      (get_current_timestamp() + 3600).try_into().unwrap(),
    );

    let keys_route = get_mock_apple_pubkey_route();

    // Mock server expects only ONE call because caching should work
    MOCK_SERVER.mock(|when, then| {
      when.method(GET).path(&keys_route.1);
      then
        .status(200)
        .header("cache-control", "max-age=3600")
        .json_body_obj(&AppleKeysResponse {
          keys: vec![key_components],
        });
    });

    let apple_signin = AppleTokenParser::new(&keys_route.0);

    // First call triggers network
    let result1 = apple_signin.parse(client_id.to_string(), token.clone(), false).await;
    assert!(result1.is_ok());

    // Second call should hit cache
    let result2 = apple_signin.parse(client_id.to_string(), token, false).await;
    assert!(result2.is_ok());
  }
}
