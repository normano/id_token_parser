use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::error::{Error, Result};

// --- Models ---

#[derive(Debug, Deserialize)]
pub struct AppleClientUser {
  pub name: Option<AppleName>,
  pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppleName {
  #[serde(rename = "firstName")]
  pub first_name: Option<String>,
  #[serde(rename = "lastName")]
  pub last_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppleTokenResponse {
  #[serde(rename = "id_token")]
  pub id_token: String,
  #[serde(rename = "access_token")]
  pub access_token: String,
  #[serde(rename = "expires_in")]
  pub expires_in: i64,
  #[serde(rename = "refresh_token")]
  pub refresh_token: Option<String>,
  #[serde(rename = "token_type")]
  pub token_type: String,
}

#[derive(Serialize)]
struct ClientSecretClaims<'a> {
  iss: &'a str,
  iat: u64,
  exp: u64,
  aud: &'a str,
  sub: &'a str,
}

#[derive(Clone)]
struct CachedSecret {
  token: String,
  expires_at: u64,
}

// --- Generator (Stateful / Credentials) ---

pub struct AppleClientSecretGenerator {
  key_id: String,
  team_id: String,
  encoding_key: EncodingKey,
  // Cache: client_id -> CachedSecret
  cache: RwLock<HashMap<String, CachedSecret>>,
  // Configuration for how long generated tokens last
  token_validity_duration: Duration,
}

impl AppleClientSecretGenerator {
  /// Creates a new generator.
  /// `private_key_pem` should be the contents of the .p8 file.
  pub fn new(key_id: String, team_id: String, private_key_pem: &[u8]) -> Result<Self> {
    let encoding_key = EncodingKey::from_ec_pem(private_key_pem)?;
    Ok(Self {
      key_id,
      team_id,
      encoding_key,
      cache: RwLock::new(HashMap::new()),
      // Default to 24 hours (Apple allows up to 6 months)
      token_validity_duration: Duration::from_secs(86400),
    })
  }

  /// Sets the validity duration for generated tokens (max 15777000 seconds / ~6 months).
  pub fn with_token_validity(mut self, duration: Duration) -> Self {
    self.token_validity_duration = duration;
    self
  }

  /// Returns a valid client_secret (JWT) for the given client_id.
  /// Uses cached value if valid, otherwise generates and signs a new one.
  pub fn generate(&self, client_id: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 1. Check Read Lock for valid cache
    {
      let cache = self.cache.read();
      if let Some(cached) = cache.get(client_id) {
        // Buffer of 60 seconds to avoid edge cases
        if cached.expires_at > now + 60 {
          return Ok(cached.token.clone());
        }
      }
    }

    // 2. Cache Miss or Expired -> Acquire Write Lock
    let mut cache = self.cache.write();

    // Double-check (another thread might have updated it while we waited for write lock)
    if let Some(cached) = cache.get(client_id) {
      if cached.expires_at > now + 60 {
        return Ok(cached.token.clone());
      }
    }

    // 3. Generate New Secret
    let expiration = now + self.token_validity_duration.as_secs();
    let claims = ClientSecretClaims {
      iss: &self.team_id,
      iat: now,
      exp: expiration,
      aud: "https://appleid.apple.com",
      sub: client_id,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(self.key_id.clone());

    let token = encode(&header, &claims, &self.encoding_key).map_err(Error::from)?;

    // 4. Update Cache
    cache.insert(
      client_id.to_string(),
      CachedSecret {
        token: token.clone(),
        expires_at: expiration,
      },
    );

    Ok(token)
  }
}

/// https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple
pub struct AppleSignIn {
  client_id: String,
  // Optional: Only needed if performing Code Exchange
  redirect_uri: Option<String>,
  // Optional: Only needed if signing requests (Revoke/Exchange)
  generator: Option<AppleClientSecretGenerator>,
  http_client: Client,
}

impl AppleSignIn {
  const APPLE_AUTH_URL: &'static str = "https://appleid.apple.com/auth/token";
  const APPLE_REVOKE_URL: &'static str = "https://appleid.apple.com/auth/revoke";

  pub fn new(client_id: String) -> Self {
    Self {
      client_id,
      redirect_uri: None,
      generator: None,
      http_client: Client::new(),
    }
  }

  /// Configures the client with credentials for signing requests.
  pub fn with_credentials(mut self, redirect_uri: Option<String>, generator: AppleClientSecretGenerator) -> Self {
    self.redirect_uri = redirect_uri;
    self.generator = Some(generator);
    self
  }

  pub fn parse_client_user(json: &str) -> Result<AppleClientUser> {
    serde_json::from_str(json).map_err(Error::from)
  }

  pub async fn validate_authorization_code(&self, code: &str) -> Result<AppleTokenResponse> {
    let generator = self
      .generator
      .as_ref()
      .ok_or(Error::ClientError("Missing credentials for auth code exchange".into()))?;

    let client_id = &self.client_id;
    let client_secret = generator.generate(client_id)?;

    let mut params = vec![
      ("client_id", client_id.as_str()),
      ("client_secret", &client_secret),
      ("code", code),
      ("grant_type", "authorization_code"),
    ];

        if let Some(uri) = &self.redirect_uri {
      params.push(("redirect_uri", uri));
    }

    let res = self
      .http_client
      .post(Self::APPLE_AUTH_URL)
      .form(&params)
      .send()
      .await
      .map_err(|e| Error::ClientError(e.to_string()))?;

    if !res.status().is_success() {
      let body = res.text().await.unwrap_or_default();
      return Err(Error::ClientError(format!("Apple Auth Failed: {}", body)));
    }

    res
      .json::<AppleTokenResponse>()
      .await
      .map_err(|e| Error::ClientError(e.to_string()))
  }

  pub async fn revoke_token(
    &self,
    client_id: &str,
    token_to_revoke: &str, // access_token or refresh_token
    generator: &AppleClientSecretGenerator,
  ) -> Result<()> {
    let client_secret = generator.generate(client_id)?;

    let params = [
      ("client_id", client_id),
      ("client_secret", &client_secret),
      ("token", token_to_revoke),
      // type_hint is optional, Apple auto-detects
    ];

    let res = self
      .http_client
      .post(Self::APPLE_REVOKE_URL)
      .form(&params)
      .send()
      .await
      .map_err(|e| Error::ClientError(e.to_string()))?;

    if !res.status().is_success() {
      let body = res.text().await.unwrap_or_default();
      return Err(Error::ClientError(format!("Apple Revoke Failed: {}", body)));
    }

    Ok(())
  }
}
