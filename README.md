# ID Token Parser

Parse and validate third party JWT tokens.
- Used for Apple and Google Sign In


```rust
use id_token_parse::{google, apple};

async fn main() {
    let gparser = google::GoogleTokenParser::default();
    gparser.add_client_id("some-google-client-id");
    let claims = gparser.parse("some-token").await.unwrap();
    println!("Google Token: {:?}", claims);

    let aparser = apple::AppleTokenParser::default();
    let claims = aparser.parse("some-apple-client-id", "some-token", false).await.unwrap();
    println!("Apple Token: {:?}", claims);
}
```