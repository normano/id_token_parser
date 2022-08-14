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

use data::{KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS};
use error::Result;
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::{
	self, decode, decode_header, DecodingKey, TokenData, Validation,
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

async fn fetch_apple_keys() -> Result<HashMap<String, KeyComponents>>
{
	let https = HttpsConnector::new();
	let client = Client::builder().build::<_, hyper::Body>(https);

	let req = Request::builder()
		.method("GET")
		.uri(APPLE_PUB_KEYS)
		.body(Body::from(""))?;

	let resp = client.request(req).await?;
	let buf = body::to_bytes(resp).await?;

	let mut resp: HashMap<String, Vec<KeyComponents>> =
		serde_json::from_slice(&buf)?;

	resp.remove("keys").map_or(Err(Error::AppleKeys), |res| {
		Ok(res
			.into_iter()
			.map(|val| (val.kid.clone(), val))
			.collect::<HashMap<String, KeyComponents>>())
	})
}

/// decoe token with optional expiry validation
pub async fn decode_token<T: DeserializeOwned>(
	token: String,
	ignore_expire: bool,
) -> Result<TokenData<T>> {
	let header = decode_header(token.as_str())?;

	let kid = match header.kid {
		Some(k) => k,
		None => return Err(Error::KidNotFound),
	};

	let pubkeys = fetch_apple_keys().await?;

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

pub async fn validate(
	client_id: String,
	token: String,
	ignore_expire: bool,
) -> Result<TokenData<Claims>> {
	let token_data =
		decode_token::<Claims>(token, ignore_expire).await?;

	//TODO: can this be validated alread in `decode_token`?
	if token_data.claims.iss != APPLE_ISSUER {
		return Err(Error::IssClaimMismatch);
	}

	if token_data.claims.aud != client_id {
		return Err(Error::ClientIdMismatch);
	}
	Ok(token_data)
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
	use super::{
		decode_token, is_expired, validate, ClaimsServer2Server,
		Error,
	};

	#[tokio::test]
	async fn validate_test() -> std::result::Result<(), Error> {
		let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidG93bi5waWVjZS5hcHAiLCJleHAiOjE2NTM3MjU1MjYsImlhdCI6MTY1MzYzOTEyNiwic3ViIjoiMDAwNDIyLjJkMWNlODE2Njk2ZTRkYTBiMjhhOTk3ZmJkYTBiYzU5LjA5MzEiLCJhdF9oYXNoIjoidVFGWTBVMmdjTkhBRzlacjluZ0hGdyIsImVtYWlsIjoidXN3dXJpa2lqaUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhdXRoX3RpbWUiOjE2NTM2MzkxMDEsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.i3Dp01s6RGc5NBu97Vw-VdvNi6ejilME1m1e-27Lv2P7nKUPUos2HJb888oiQRroC7E3zihDAL53FbsFp7kgGDVTt9R68YKdaM-Nwl97ywUP9ehVk1KuUd9rd4cHEN8Cms7YnJErSMIOmj3mMjg6ISEGQHrOPVtG9fk_9HqK7mcyxtnsAM9K-CxGbwzgVqJBgQK45qBq-lNPYnOJOKO6DQfOA86X0csYZ2wqFlc89Z3APOkL_Q_Y69ERq1YHyRg4IfW9puTURhjWRNpW_7Qt4RhP4ewWRKsJ1fr_E64bbpnLFyepJLBHYePNiEbfZfd0k_crdSS4_fuzHWHFsDqddg";

		let _result = validate(
			"town.piece.app".to_string(),
			token.to_string(),
			true,
		)
		.await?;

		Ok(())
	}

	#[ignore]
	#[tokio::test]
	async fn validate_expired() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzA4Mjc4MzAsImlhdCI6MTYzMDc0MTQzMCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiI0QjZKWTU4TmstVUJsY3dMa2VLc2lnIiwiYXV0aF90aW1lIjoxNjMwNzQxNDMwLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.iW0xk__fPD0mlh9UU-vh9VnR8yekWq64sl5re5d7UmDJxb1Fzk1Kca-hkA_Ka1LhSmKADdFW0DYEZhckqh49DgFtFdx6hM9t7guK3yrvBglhF5LAyb8NR028npxioLTTIgP_aR6Bpy5AyLQrU-yYEx2WTPYV5ln9n8vW154gZKRyl2KBlj9fS11BL_X1UFbFrL21GG_iPbB4qt5ywwTPoJ-diGN5JQzP5fk4yU4e4YmHhxJrT0NTTux2mB3lGJLa6YN-JYe_BuVV9J-sg_2r_ugTOUp3xQpfntu8xgQrY5W0oPxAPM4sibNLsye2kgPYYxfRYowc0JIjOcOd_JHDbQ";

		let res = validate(
			"com.gameroasters.stack4".into(),
			token.to_string(),
			false,
		)
		.await;

		assert!(is_expired(&res));
	}

	#[ignore]
	#[tokio::test]
	async fn test_server_to_server_payload() {
		let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidG93bi5waWVjZS5hcHAiLCJleHAiOjE2NTM3MjU1MjYsImlhdCI6MTY1MzYzOTEyNiwic3ViIjoiMDAwNDIyLjJkMWNlODE2Njk2ZTRkYTBiMjhhOTk3ZmJkYTBiYzU5LjA5MzEiLCJhdF9oYXNoIjoidVFGWTBVMmdjTkhBRzlacjluZ0hGdyIsImVtYWlsIjoidXN3dXJpa2lqaUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhdXRoX3RpbWUiOjE2NTM2MzkxMDEsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.i3Dp01s6RGc5NBu97Vw-VdvNi6ejilME1m1e-27Lv2P7nKUPUos2HJb888oiQRroC7E3zihDAL53FbsFp7kgGDVTt9R68YKdaM-Nwl97ywUP9ehVk1KuUd9rd4cHEN8Cms7YnJErSMIOmj3mMjg6ISEGQHrOPVtG9fk_9HqK7mcyxtnsAM9K-CxGbwzgVqJBgQK45qBq-lNPYnOJOKO6DQfOA86X0csYZ2wqFlc89Z3APOkL_Q_Y69ERq1YHyRg4IfW9puTURhjWRNpW_7Qt4RhP4ewWRKsJ1fr_E64bbpnLFyepJLBHYePNiEbfZfd0k_crdSS4_fuzHWHFsDqddg";

		let result = decode_token::<ClaimsServer2Server>(
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