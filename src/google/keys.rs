use std::collections::HashMap;
use std::time::Instant;

use headers::Header;
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::errors::Error;
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
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let req = Request::builder()
      .method("GET")
      .uri(&self.url)
      .body(Body::from(""));
    
    if req.is_err() {
      let e = req.unwrap_err();
      return Result::Err(GoogleKeyProviderError::FetchError(format!("{:?}", e)));
    }

    match client.request(req.unwrap()).await {
      Ok(r) => {
        let expiration_time = GooglePublicKeyProvider::parse_expiration_time(&r.headers());
        let buf = body::to_bytes(r).await;

        if buf.is_err() {
          let e = buf.unwrap_err();
          return Result::Err(GoogleKeyProviderError::ParseError(format!("{:?}", e)));
        }

        match serde_json::from_slice::<GoogleKeys>(&buf.unwrap()) {
          Ok(google_keys) => {
              self.keys.clear();
              for key in google_keys.keys.into_iter() {
                  self.keys.insert(key.kid.clone(), key);
              }
              self.expiration_time = expiration_time;
              Result::Ok(())
          }
          Err(e) => Result::Err(GoogleKeyProviderError::ParseError(format!("{:?}", e))),
        }
      }
      Err(e) => Result::Err(GoogleKeyProviderError::FetchError(format!("{:?}", e))),
    }
  }

  fn parse_expiration_time(header_map: &hyper::HeaderMap) -> Option<Instant> {
    match headers::CacheControl::decode(&mut header_map.get_all(hyper::header::CACHE_CONTROL).iter()) {
      Ok(header) => match header.max_age() {
        None => None,
        Some(max_age) => Some(Instant::now() + max_age),
      },
      Err(_) => None,
    }
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

  use super::{GoogleKeyProviderError, GooglePublicKeyProvider};

  #[tokio::test]
  async fn should_parse_keys() {
    let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
    let e = "AQAB";
    let kid = "some-kid";
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

    let server = MockServer::start();
    let _server_mock = server.mock(|when, then| {
      when.method(httpmock::Method::GET).path("/");

      then.status(200)
        .header(
            "cache-control",
            "public, max-age=24920, must-revalidate, no-transform",
        )
        .header("Content-Type", "application/json; charset=UTF-8")
        .body(resp);
    });
    let mut provider = GooglePublicKeyProvider::new(server.url("/").as_str());

    assert!(matches!(provider.get_key(kid).await, Result::Ok(_)));
    assert!(matches!(
      provider.get_key("missing-key").await,
      Result::Err(_)
    ));
  }

  #[tokio::test]
  async fn should_expire_and_reload() {
    let server = MockServer::start();
    let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
    let e = "AQAB";
    let kid = "some-kid";
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

    let mut server_mock = server.mock(|when, then| {
      when.method(httpmock::Method::GET).path("/");
      then.status(200)
        .header(
            "cache-control",
            "public, max-age=3, must-revalidate, no-transform",
        )
        .header("Content-Type", "application/json; charset=UTF-8")
        .body("{\"keys\":[]}");
    });

    let mut provider = GooglePublicKeyProvider::new(server.url("/").as_str());
    let key_result = provider.get_key(kid).await;
    assert!(matches!(
      key_result,
      Result::Err(GoogleKeyProviderError::KeyNotFound)
    ));

    server_mock.delete();
    let _server_mock = server.mock(|when, then| {
      when.method(httpmock::Method::GET).path("/");
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
