//! Convenience types for lib specific error handling

use thiserror::Error;
use super::keys::AppleKeyProviderError;

#[derive(Error, Debug)]
pub enum Error {
  #[error("Header algorithm unspecified")]
  HeaderAlgorithmUnspecified,
  #[error("Apple Keys Error")]
  AppleKeys,
  #[error("Key ID not found")]
  KidNotFound,
  #[error("Key not found")]
  KeyNotFound,
  #[error("Iss claim mismatch")]
  IssClaimMismatch,
  #[error("Client ID mismatch")]
  ClientIdMismatch,
  #[error(transparent)]
  Jwt(#[from] jsonwebtoken::errors::Error),
  #[error("Key provider error: {0}")]
  KeyProvider(#[from] AppleKeyProviderError),
  #[error("serde_json error: {0}")]
  SerdeJson(#[from] serde_json::Error),
  #[error("Client error: {0}")]
  ClientError(String), // Generalized error for any HTTP client
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;
