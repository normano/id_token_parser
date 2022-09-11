# Parse and validate Google JWT tokens


```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub email: String,
    pub aud: String,
    pub iss: String,
    pub exp: u64,
}

async fn main() {
    let parser = Parser::new();
    parser.add_client_id("some-google-web-client-id");
    let claims = parser.parse::<TokenClaims>("some-token").await.unwrap();
}
```