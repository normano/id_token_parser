# API Reference: `id_token_parser`

### Introduction

The `id_token_parser` library is a utility for parsing and validating JSON Web Tokens (JWTs) from Google and Apple's identity services. It handles the fetching of public cryptographic keys required for signature verification and provides a straightforward API to validate tokens and extract their claims.

The library is organized into two primary modules, each corresponding to a provider:

*   **`id_token_parser::google`**: Contains the `GoogleTokenParser` for validating Google ID tokens.
*   **`id_token_parser::apple`**: Contains the `AppleTokenParser` for validating "Sign in with Apple" ID tokens.

Each module has its own dedicated parser, data structures for claims, and error types, ensuring a clear separation of concerns between the providers.

***

## Module `id_token_parser::google`

This module provides the necessary tools to parse and validate Google ID tokens.

### Main Types and Their Public Methods

#### struct `GoogleTokenParser`

The primary entry point for parsing and validating Google ID tokens. It manages public key fetching and caching based on Google's specified `Cache-Control` headers.

##### Constructors

**`new`**

```rust
pub fn new(public_key_url: &str) -> Self
```

Creates a new `GoogleTokenParser` instance that will fetch public keys from the specified URL.

*   **`public_key_url`**: The URL to Google's public certificate endpoint (JWKS). For production, use `GoogleTokenParser::GOOGLE_CERT_URL`.

**`default`**

```rust
pub fn default() -> Self
```

Creates a new `GoogleTokenParser` using the default Google public certificate URL. This is equivalent to calling `new(GoogleTokenParser::GOOGLE_CERT_URL)`.

##### Configuration Methods

**`add_client_id`**

```rust
pub fn add_client_id(&mut self, client_id: &str)
```

Adds a single client ID to the list of allowed audiences for token validation.

*   **`client_id`**: The Google client ID (audience) that is expected in the token's `aud` claim.

**`add_client_ids`**

```rust
pub fn add_client_ids(&mut self, client_ids: Vec<String>)
```

Appends a vector of client IDs to the list of allowed audiences for token validation.

*   **`client_ids`**: A vector of Google client IDs (audiences) to be considered valid.

##### Core Operations

**`parse`**

```rust
pub async fn parse(&self, token: &str) -> Result<id_token_parser::google::data::GoogleTokenClaims, ParserError>
```

Parses and validates a Google ID token string, returning the extracted claims upon success. This is a convenient wrapper around the `decode` method.

*   **`token`**: The raw Google ID token string to validate.

**`decode`**

```rust
pub async fn decode<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T, ParserError>
```

A generic method to parse and validate a token string into a custom claims type. It performs all necessary validations, including signature, issuer, audience, and expiration.

*   **`T`**: The type to deserialize the token's claims into. It must implement `serde::de::DeserializeOwned`.
*   **`token`**: The raw Google ID token string to validate.

### Public Data Structures

#### struct `google::data::GoogleTokenClaims`

Represents the standard claims found in a Google ID token.

*   **`aud: String`**: The audience of the token (your app's client ID).
*   **`iss: String`**: The token issuer, which must be `https://accounts.google.com` or `accounts.google.com`.
*   **`exp: u64`**: The expiration time of the token as a UNIX timestamp.
*   **`email: String`**: The user's email address.
*   **`sub: String`**: The user's unique Google ID.
*   **`email_verified: bool`**: `true` if Google has verified the user's email address.
*   **`name: String`**: The user's full name.

### Error Handling

#### enum `google::ParserError`

The error type returned from `GoogleTokenParser` operations.

*   **`WrongHeader`**: The JWT header is malformed or could not be decoded.
*   **`UnknownKid`**: The JWT header does not contain a Key ID (`kid`) field.
*   **`KeyProvider(GoogleKeyProviderError)`**: An error occurred while fetching or parsing Google's public keys. `GoogleKeyProviderError` is an internal type.
*   **`WrongToken(jsonwebtoken::errors::Error)`**: An error occurred during JWT validation (e.g., invalid signature, expired token, incorrect issuer/audience).

### Public Constants

*   `pub const GOOGLE_CERT_URL: &'static str`
    The official URL for Google's OAuth2 public certificates. Value: `https://www.googleapis.com/oauth2/v3/certs`.

***

## Module `id_token_parser::apple`

This module provides the necessary tools for validating "Sign in with Apple" ID tokens.

### Main Types and Their Public Methods

#### struct `AppleTokenParser`

The primary entry point for parsing and validating Apple ID tokens. It manages fetching Apple's public keys for signature verification.

##### Constructors

**`new`**

```rust
pub fn new(base_url: &str) -> Self
```

Creates a new `AppleTokenParser` that will fetch public keys from the specified URL.

*   **`base_url`**: The URL to Apple's public key endpoint (JWKS).

**`default`**

```rust
pub fn default() -> Self
```

Creates a new `AppleTokenParser` using Apple's default public key URL (`https://appleid.apple.com/auth/keys`).

##### Core Operations

**`parse`**

```rust
pub async fn parse(
    &self,
    client_id: String,
    token: String,
    ignore_expire: bool,
) -> Result<jsonwebtoken::TokenData<Claims>, Error>
```

Performs full validation of an Apple ID token, including signature, issuer, audience, and expiration (optional).

*   **`client_id`**: The app's client ID (e.g., `com.my.app` or a service ID) that is expected in the token's `aud` claim.
*   **`token`**: The raw Apple ID token string to validate.
*   **`ignore_expire`**: If `true`, the token's expiration (`exp` claim) will not be validated.

**`decode`**

```rust
pub async fn decode<T: serde::de::DeserializeOwned>(
    &self,
    token: String,
    ignore_expire: bool,
) -> Result<jsonwebtoken::TokenData<T>, Error>
```

Decodes the token and verifies its signature against Apple's public keys. It does not validate issuer or audience claims.

*   **`T`**: The type to deserialize the token's claims into. It must implement `serde::de::DeserializeOwned`.
*   **`token`**: The raw Apple ID token string to decode.
*   **`ignore_expire`**: If `true`, the token's expiration will not be validated.

### Public Functions

#### `is_expired`

```rust
pub fn is_expired(validate_result: &Result<jsonwebtoken::TokenData<Claims>, Error>) -> bool
```

A helper function to check if a `Result` from a validation operation failed specifically because of an expired signature.

*   **`validate_result`**: A reference to the `Result` returned by `AppleTokenParser::parse`.

### Public Data Structures

#### struct `apple::Claims`

Represents the claims from a standard user authentication ID token.

*   **`iss: String`**: The issuer, which must be `https://appleid.apple.com`.
*   **`aud: String`**: The audience (your app's client ID).
*   **`exp: i64`**: The expiration time as a UNIX timestamp.
*   **`iat: i64`**: The time the token was issued as a UNIX timestamp.
*   **`sub: String`**: The user's unique identifier for your team.
*   **`email: Option<String>`**: The user's email address.
*   **`email_verified: Option<String>`**: A string (`"true"` or `"false"`) indicating if the email is verified.
*   **`auth_time: i64`**: The time the user was authenticated.

#### struct `apple::ClaimsServer2Server`

Represents the payload of a server-to-server notification token from Apple.

*   **`iss: String`**: The issuer.
*   **`aud: String`**: The audience (your app's bundle ID).
*   **`exp: i32`**: The expiration time as a UNIX timestamp.
*   **`iat: i32`**: The time the token was issued as a UNIX timestamp.
*   **`jti: String`**: A unique identifier for the token.
*   **`events: id_token_parser::apple::data::ClaimsServer2ServerEvent`**: The nested event payload containing details about the server-to-server notification.

#### struct `apple::data::ClaimsServer2ServerEvent`

The nested event data within a `ClaimsServer2Server` token.

*   **`event_type: String`**: The type of event (e.g., `consent-revoked`).
*   **`sub: String`**: The user's unique identifier.
*   **`event_time: i64`**: The time the event occurred as a UNIX timestamp.
*   **`email: Option<String>`**: The user's email address.
*   **`is_private_email: Option<String>`**: A string (`"true"` or `"false"`) indicating if the email is a private relay address.

### Error Handling

#### enum `apple::Error`

The error type returned from `AppleTokenParser` operations.

*   **`HeaderAlgorithmUnspecified`**: The JWT header does not specify an algorithm.
*   **`AppleKeys`**: An error occurred while parsing the key set from Apple's endpoint.
*   **`KidNotFound`**: The JWT header is missing the Key ID (`kid`).
*   **`KeyNotFound`**: A public key matching the token's `kid` was not found.
*   **`IssClaimMismatch`**: The token's `iss` claim does not match the expected Apple issuer.
*   **`ClientIdMismatch`**: The token's `aud` claim does not match the provided client ID.
*   **`Jwt(jsonwebtoken::errors::Error)`**: An error from the underlying `jsonwebtoken` crate (e.g., invalid signature, expired token).
*   **`SerdeJson(serde_json::Error)`**: A JSON serialization or deserialization error occurred.
*   **`ClientError(String)`**: An error occurred in the HTTP client while fetching keys.

#### type `apple::Result<T>`

A convenience type alias for results from this module.

```rust
pub type Result<T> = std::result::Result<T, Error>;
```