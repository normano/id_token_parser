#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::perf)]
#![deny(clippy::nursery)]
#![deny(clippy::match_like_matches_macro)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

mod data;
mod error;

pub use data::{Claims, ClaimsServer2Server};
pub use error::Error;

use data::{KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS_URL};
use error::Result;
use jsonwebtoken::{
	self, decode, decode_header, DecodingKey, TokenData, Validation,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub struct AppleTokenParser {
	client: Client,
	base_url: String,
}

impl AppleTokenParser {
	pub fn new(base_url: &str) -> Self {
		Self {
			client: Client::new(),
			base_url: base_url.to_string(),
		}
	}

	pub fn default() -> Self {
		return Self::new(APPLE_PUB_KEYS_URL);
	}

	pub async fn parse(
		&self,
		client_id: String,
		token: String,
		ignore_expire: bool,
	) -> Result<TokenData<Claims>> {
		let token_data =
			self.decode::<Claims>(token, ignore_expire).await?;

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
	pub async fn decode<T: DeserializeOwned>(
		&self,
		token: String,
		ignore_expire: bool,
	) -> Result<TokenData<T>> {
		let header = decode_header(token.as_str())?;

		// println!("header: {:?}", header);
		let kid = match header.kid {
			Some(k) => k,
			None => return Err(Error::KidNotFound),
		};

		let pubkeys = self.fetch_apple_keys().await?;

		// println!("pubkeys: {:?}", pubkeys);
		let pubkey = match pubkeys.get(&kid) {
			Some(key) => key,
			None => return Err(Error::KeyNotFound),
		};

		let mut val = Validation::new(header.alg);
		val.validate_exp = !ignore_expire;
		let decoding_key =
			&DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e)?;

		let token_data = decode::<T>(token.as_str(), decoding_key, &val)
			.map_err(|err| {
				println!("this is error : {err:?}");
				err
			})?;

		Ok(token_data)
	}

	async fn fetch_apple_keys(&self) -> Result<HashMap<String, KeyComponents>> {
		let resp = self.client.get(&self.base_url)
				.send()
				.await
				.map_err(|e| Error::ClientError(e.to_string()))?;

		let buf = resp.bytes()
			.await
			.map_err(|e| Error::ClientError(e.to_string()))?;

		let mut resp: HashMap<String, Vec<KeyComponents>> = serde_json::from_slice(&buf)?;

		resp.remove("keys").map_or(Err(Error::AppleKeys), |res| {
			Ok(res
					.into_iter()
					.map(|val| (val.kid.clone(), val))
					.collect::<HashMap<String, KeyComponents>>()
			)
		})
	}
}

/// allows to check whether the `validate` result was errored because of an expired signature
#[must_use]
pub fn is_expired(
	validate_result: &Result<TokenData<Claims>>,
) -> bool {
	if let Err(Error::Jwt(error)) = validate_result {
		return matches!(
			error.kind(),
			jsonwebtoken::errors::ErrorKind::ExpiredSignature
		);
	}

	false
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use super::*;
	use base64::prelude::*;
	use httpmock::{Method::GET, MockServer};
	use once_cell::sync::Lazy;
	use rand::{rngs::OsRng, Rng};
	use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding, traits::PublicKeyParts, RsaPrivateKey};
	use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
	use serde::{Deserialize, Serialize}; // Assuming you're using jsonwebtoken crate

	static MOCK_SERVER: Lazy<MockServer> = Lazy::new(|| {
    let server = MockServer::start();
    server
	});

	fn get_mock_apple_pubkey_route() -> (String, String) {
    let random_number: u32 = rand::thread_rng().gen_range(0..10000);

		let route = format!("/apple/keys/{}", random_number);
    return (format!("{}{}", MOCK_SERVER.base_url(), route), route);
	}
	
	#[derive(Serialize, Deserialize)]
	struct AppleKeysResponse {
			keys: Vec<KeyComponents>,
	}
	
	fn create_sample_token(client_id: &str, issuer: &str, exp: i64) -> (String, KeyComponents) {
    // Step 1: Generate RSA private key (for testing purposes)
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate a key");

    // Step 2: Create claims for the token
    let my_claims = Claims {
			aud: client_id.to_string(),
			iss: issuer.to_string(),
			exp,  // expiration timestamp
			auth_time: 0,
			email: None,
			email_verified: None,
			iat: 0,
			sub: "".to_string()
    };

		let header = {
			let mut inner = Header::new(Algorithm::RS256);
			inner.kid = Some("test_kid".to_string());
			inner
		};
		
		let key = EncodingKey::from_rsa_pem(&private_key.to_pkcs1_pem(LineEnding::default()).unwrap().as_bytes()).expect("Invalid key");
    let token = encode(
        &header,
        &my_claims,
        &key,
    ).unwrap();

		let pub_key = private_key.to_public_key();

		let key_comps = KeyComponents {
			kid: "test_kid".to_string(),
			n: BASE64_URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be()),
			e: BASE64_URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be()),
			alg: "RS256".to_string(),
			kty: "RSA".to_string(),
			r#use :"sig".to_string()
		};

		return (token, key_comps);
	}

	fn get_current_timestamp() -> usize {
		SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() as usize
	}

	#[tokio::test]
	async fn test_validate_success() {
			let client_id = "test-client-id";
			let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, (get_current_timestamp() + 3600).try_into().unwrap());

			let keys_route = get_mock_apple_pubkey_route();
			MOCK_SERVER.mock(|when, then| {
        when.method(GET)
					.path(&keys_route.1);
        then.status(200)
					.json_body_obj(&AppleKeysResponse {
							keys: vec![key_components],
					});
    	});

			let apple_signin = AppleTokenParser::new(&keys_route.0);
			let result = apple_signin.parse(client_id.to_string(), token, false).await;
			
			assert!(result.is_ok());
			let token_data = result.unwrap();
			assert_eq!(token_data.claims.aud, client_id);
			assert_eq!(token_data.claims.iss, APPLE_ISSUER);
	}

	#[tokio::test]
	async fn test_validate_wrong_issuer() {
			let client_id = "test-client-id";
			let wrong_issuer = "wrong-issuer";
			let (token, key_components) = create_sample_token(client_id, wrong_issuer, (get_current_timestamp() + 3600).try_into().unwrap());

			let keys_route = get_mock_apple_pubkey_route();
			MOCK_SERVER.mock(|when, then| {
        when.method(GET)
					.path(&keys_route.1);
        then.status(200)
					.json_body_obj(&AppleKeysResponse {
							keys: vec![key_components],
					});
    	});

			let apple_signin = AppleTokenParser::new(&keys_route.0);
			let result = apple_signin.parse(client_id.to_string(), token, false).await;

			// Assert that validation fails due to IssClaimMismatch
			assert!(matches!(result, Err(Error::IssClaimMismatch)));
	}

	#[tokio::test]
	async fn test_validate_wrong_client_id() {
			let client_id = "wrong-client-id";
			let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, (get_current_timestamp() + 3600).try_into().unwrap());

			let keys_route = get_mock_apple_pubkey_route();
			MOCK_SERVER.mock(|when, then| {
        when.method(GET)
					.path(&keys_route.1);
        then.status(200)
					.json_body_obj(&AppleKeysResponse {
							keys: vec![key_components],
					});
    	});

			let apple_signin = AppleTokenParser::new(&keys_route.0);
			let correct_client_id = "correct-client-id";
			let result = apple_signin.parse(correct_client_id.to_string(), token, false).await;

			// Assert that validation fails due to ClientIdMismatch
			assert!(matches!(result, Err(Error::ClientIdMismatch)));
	}

	#[tokio::test]
	async fn test_validate_expired_token() {
			let client_id = "test-client-id";
			let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, 1);

			let keys_route = get_mock_apple_pubkey_route();
			MOCK_SERVER.mock(|when, then| {
        when.method(GET)
					.path(&keys_route.1);
        then.status(200)
					.json_body_obj(&AppleKeysResponse {
							keys: vec![key_components],
					});
    	});

			let apple_signin = AppleTokenParser::new(&keys_route.0);
			let result = apple_signin.parse(client_id.to_string(), token, false).await;

			// Assert that validation fails due to the token being expired (Error depends on your implementation of `decode_token`)
			// Assuming `decode_token` returns an error for expired tokens
			assert!(matches!(result, Err(Error::Jwt(_))));
	}

	#[tokio::test]
	async fn test_validate_ignore_expired_token() {
			let client_id = "test-client-id";
			let (token, key_components) = create_sample_token(client_id, APPLE_ISSUER, 1);

			let keys_route = get_mock_apple_pubkey_route();
			MOCK_SERVER.mock(|when, then| {
        when.method(GET)
					.path(&keys_route.1);
        then.status(200)
					.json_body_obj(&AppleKeysResponse {
							keys: vec![key_components],
					});
    	});

			let apple_signin = AppleTokenParser::new(&keys_route.0);
			let result = apple_signin.parse(client_id.to_string(), token, true).await;

			// Assert that validation succeeds when `ignore_expire` is true
			assert!(result.is_ok());
	}

	#[ignore]
	#[tokio::test]
	async fn test_server_to_server_payload() {
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

			let apple_signin = AppleTokenParser::new(&keys_route.0);
		let result = apple_signin.decode::<ClaimsServer2Server>(
			token.to_string(),
			true,
		)
		.await
		.unwrap();

		assert_eq!(result.claims.aud, "town.piece.app");
		assert_eq!(
			result.claims.events.sub,
			"000422.2d1ce816696e4da0b28a997fbda0bc59.0931"
		);

		println!("{:?}", result);
	}
}