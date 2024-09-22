use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleTokenClaims {
  pub aud: String,
  pub iss: String,
  pub exp: u64,
  pub email: String,
  pub sub: String,
  pub email_verified: bool,
  pub name: String,
}