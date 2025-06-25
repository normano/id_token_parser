use std::collections::HashMap;
use std::time::{Instant, Duration};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::errors::Error;
use reqwest::Client;
use reqwest::header::CACHE_CONTROL;
use serde::Deserialize;
use thiserror::Error;

#[derive(Deserialize, Clone)]
pub struct GoogleKeys {
  keys: Vec<GoogleKey>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoogleKey {
  kid: String,
  n: String,
  e: String,
}

#[derive(Error, Debug)]
pub enum GoogleKeyProviderError {
  #[error("key not found")]
  KeyNotFound,
  #[error("network error {0}")]
  FetchError(String),
  #[error("parse error {0}")]
  ParseError(String),
  #[error("create key error {0}")]
  CreateKeyError(Error),
}

#[derive(Debug)]
pub struct GooglePublicKeyProvider {
  url: String,
  keys: HashMap<String, GoogleKey>,
  expiration_time: Option<Instant>,
}

impl GooglePublicKeyProvider {
  pub fn new(public_key_url: &str) -> Self {
    Self {
      url: public_key_url.to_owned(),
      keys: Default::default(),
      expiration_time: None,
    }
  }

  pub async fn reload(&mut self) -> Result<(), GoogleKeyProviderError> {
    let client = Client::new();

    // Send GET request using reqwest
    let res = client.get(&self.url).send().await;

    match res {
      Ok(r) => {
          let expiration_time = Self::parse_expiration_time(r.headers());

          let buf = r.bytes().await;
          if buf.is_err() {
              return Err(GoogleKeyProviderError::ParseError(format!("{:?}", buf.unwrap_err())));
          }

          let buf = buf.unwrap();
          match serde_json::from_slice::<GoogleKeys>(&buf) {
              Ok(google_keys) => {
                  self.keys.clear();
                  for key in google_keys.keys.into_iter() {
                      self.keys.insert(key.kid.clone(), key);
                  }
                  self.expiration_time = expiration_time;
                  Ok(())
              }
              Err(e) => Err(GoogleKeyProviderError::ParseError(format!("{:?}", e))),
          }
      }
      Err(e) => Err(GoogleKeyProviderError::FetchError(format!("{:?}", e))),
    }
  }

  fn parse_expiration_time(headers: &reqwest::header::HeaderMap) -> Option<Instant> {
    if let Some(cache_control_value) = headers.get(CACHE_CONTROL) {
      let cache_control_str = cache_control_value.to_str().ok()?;
      if let Some(max_age) = Self::parse_max_age(cache_control_str) {
          return Some(Instant::now() + Duration::from_secs(max_age));
      }
    }
    None
  }

  fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control
      .split(',')
      .find_map(|directive| {
        let directive = directive.trim();
        if directive.starts_with("max-age=") {
            directive[8..].parse::<u64>().ok()
        } else {
            None
        }
      })
  }

  pub fn is_expire(&self) -> bool {
    if let Some(expire) = self.expiration_time {
      Instant::now() > expire
    } else {
      false
    }
  }

  pub async fn get_key(
      &mut self,
      kid: &str,
  ) -> Result<DecodingKey, GoogleKeyProviderError> {
    if self.expiration_time.is_none() || self.is_expire() {
      self.reload().await?
    }
    match self.keys.get(&kid.to_owned()) {
      None => Result::Err(GoogleKeyProviderError::KeyNotFound),
      Some(key) => {
        DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
          .map_err(|e| GoogleKeyProviderError::CreateKeyError(e))
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use httpmock::MockServer;
  use once_cell::sync::Lazy;
use rand::Rng;

  use super::{GoogleKeyProviderError, GooglePublicKeyProvider};

  static MOCK_SERVER: Lazy<MockServer> = Lazy::new(|| {
    let server = MockServer::start();
    server
  });
  
  fn get_mock_google_pubkey_route() -> (String, String) {
    let random_number: u32 = rand::rng().random_range(0..10000);
  
    let route = format!("/{}", random_number);
    return (format!("{}{}", MOCK_SERVER.base_url(), route), route);
  }

  #[tokio::test]
  async fn should_parse_keys() {
    let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
    let e = "AQAB";
    let kid = "some-kid";
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

    let pub_key_route = get_mock_google_pubkey_route();
    let _server_mock = MOCK_SERVER.mock(|when, then| {
      when.method(httpmock::Method::GET).path(&pub_key_route.1);

      then.status(200)
        .header(
            "cache-control",
            "public, max-age=24920, must-revalidate, no-transform",
        )
        .header("Content-Type", "application/json; charset=UTF-8")
        .body(resp);
    });
    let mut provider = GooglePublicKeyProvider::new(&pub_key_route.0);

    assert!(matches!(provider.get_key(kid).await, Result::Ok(_)));
    assert!(matches!(
      provider.get_key("missing-key").await,
      Result::Err(_)
    ));
  }

  #[tokio::test]
  async fn should_expire_and_reload() {
    let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
    let e = "AQAB";
    let kid = "some-kid";
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

    let pub_key_route = get_mock_google_pubkey_route();
    let mut server_mock = MOCK_SERVER.mock(|when, then| {
      when.method(httpmock::Method::GET).path(&pub_key_route.1);
      then.status(200)
        .header(
            "cache-control",
            "public, max-age=3, must-revalidate, no-transform",
        )
        .header("Content-Type", "application/json; charset=UTF-8")
        .body("{\"keys\":[]}");
    });

    let mut provider = GooglePublicKeyProvider::new(&pub_key_route.0);
    let key_result = provider.get_key(kid).await;
    assert!(matches!(
      key_result,
      Result::Err(GoogleKeyProviderError::KeyNotFound)
    ));

    server_mock.delete();
    let _server_mock = MOCK_SERVER.mock(|when, then| {
      when.method(httpmock::Method::GET).path(&pub_key_route.1);
      then.status(200)
        .header(
            "cache-control",
            "public, max-age=3, must-revalidate, no-transform",
        )
        .header("Content-Type", "application/json; charset=UTF-8")
        .body(resp);
    });

    std::thread::sleep(Duration::from_secs(4));
    let key_result = provider.get_key(kid).await;
    assert!(matches!(key_result, Result::Ok(_)));
  }
}
