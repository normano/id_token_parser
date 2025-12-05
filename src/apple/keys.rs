use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::errors::Error;
use jsonwebtoken::DecodingKey;
use reqwest::header::CACHE_CONTROL;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

use super::data::KeyComponents;

#[derive(Deserialize, Clone)]
pub struct AppleKeysResponse {
  keys: Vec<KeyComponents>,
}

#[derive(Error, Debug)]
pub enum AppleKeyProviderError {
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
pub struct ApplePublicKeyProvider {
  url: String,
  keys: HashMap<String, KeyComponents>,
  expiration_time: Option<Instant>,
  client: Client,
}

impl ApplePublicKeyProvider {
  pub fn new(public_key_url: &str) -> Self {
    Self {
      url: public_key_url.to_owned(),
      keys: Default::default(),
      expiration_time: None,
      client: Client::new(),
    }
  }

  pub async fn reload(&mut self) -> Result<(), AppleKeyProviderError> {
    // Send GET request using reqwest
    let res = self.client.get(&self.url).send().await;

    match res {
      Ok(r) => {
        let expiration_time = Self::parse_expiration_time(r.headers());

        let buf = r.bytes().await;
        if buf.is_err() {
          return Err(AppleKeyProviderError::ParseError(format!("{:?}", buf.unwrap_err())));
        }

        let buf = buf.unwrap();
        match serde_json::from_slice::<AppleKeysResponse>(&buf) {
          Ok(apple_keys) => {
            self.keys.clear();
            for key in apple_keys.keys.into_iter() {
              self.keys.insert(key.kid.clone(), key);
            }
            self.expiration_time = expiration_time;
            Ok(())
          }
          Err(e) => Err(AppleKeyProviderError::ParseError(format!("{:?}", e))),
        }
      }
      Err(e) => Err(AppleKeyProviderError::FetchError(format!("{:?}", e))),
    }
  }

  fn parse_expiration_time(headers: &reqwest::header::HeaderMap) -> Option<Instant> {
    if let Some(cache_control_value) = headers.get(CACHE_CONTROL) {
      let cache_control_str = cache_control_value.to_str().ok()?;
      if let Some(max_age) = Self::parse_max_age(cache_control_str) {
        return Some(Instant::now() + Duration::from_secs(max_age));
      }
    }
    // Default fallback if no header is present (e.g. 1 hour)
    Some(Instant::now() + Duration::from_secs(3600))
  }

  fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control.split(',').find_map(|directive| {
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
      true
    }
  }

  pub async fn get_key(&mut self, kid: &str) -> Result<DecodingKey, AppleKeyProviderError> {
    if self.expiration_time.is_none() || self.is_expire() {
      self.reload().await?
    }

    // If key is not found, force one reload in case of rotation, unless we just reloaded.
    if !self.keys.contains_key(kid) {
      // Simple heuristic: if we expired, we already reloaded above.
      // If we weren't expired but key is missing, reload now.
      if !self.is_expire() {
        self.reload().await?;
      }
    }

    match self.keys.get(kid) {
      None => Result::Err(AppleKeyProviderError::KeyNotFound),
      Some(key) => DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
        .map_err(|e| AppleKeyProviderError::CreateKeyError(e)),
    }
  }
}
