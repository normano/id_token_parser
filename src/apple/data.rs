use crate::util::deserialize_bool_or_string;

use serde::{Deserialize, Deserializer, Serialize};

pub const APPLE_PUB_KEYS_URL: &str = "https://appleid.apple.com/auth/keys";
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyComponents {
  pub kty: String,   // "RSA"
  pub kid: String,   // "eXaunmL"
  pub r#use: String, // "sig"
  pub alg: String,   // "RS256"
  pub n: String,     // "4dGQ7bQK8LgILOdL..."
  pub e: String,     // "AQAB"
}

// Info https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token
// The identity token contains the following claims:
//
// iss - The issuer registered claim identifies the principal that issues the identity token. Because Apple generates the token, the value is https://appleid.apple.com.
//
// sub - The subject registered claim identifies the principal that’s the subject of the identity token. Because this token is for your app, the value is the unique identifier for the user.
// 
// This identifier:
//         Consists of a unique, stable string, and serves as the primary identifier of the user
//
//         Uses the same identifier across all of the apps in the development team associated with your Apple Developer account
//
//         Differs for the same user across different development teams, and can’t identify a user across development teams
//
//         Doesn’t change if the user stops using Sign in with Apple with your app and later starts using it again You typically store this token alongside the user’s primary key in your database.
//
// aud - The audience registered claim identifies the recipient of the identity token. Because the token is for your app, the value is the client_id from your developer account.
//
// iat - The issued at registered claim indicates the time that Apple issues the identity token, in the number of seconds since the Unix epoch in UTC.
//
// exp - The expiration time registered claim identifies the time that the identity token expires, in the number of seconds since the Unix epoch in UTC. The value must be greater than the current date and time when verifying the token.
//
// nonce - A string for associating a client session with the identity token. This value mitigates replay attacks and is present only if you pass it in the authorization request.
//
// nonce_supported - A Boolean value that indicates whether the transaction is on a platform that supports anti-replay values. If you send an anti-replay value in the authorization request, but don’t see the anti-replay value claim in the identity token, check this claim to determine how to proceed. If this claim returns true, treat nonce as mandatory and fail the transaction; otherwise, you can proceed treating the anti-replay value as optional.
//
// email - A string value that represents the user’s email address. The email address is either the user’s real email address or the proxy address, depending on their private email relay service. This value may be empty for Sign in with Apple at Work & School users. For example, younger students may not have an email address. Don’t use this value as an identifier of the user. For a unique identifier for the user refer to the sub value.
//
// email_verified - A string or Boolean value that indicates whether the service verifies the email. The value can either be a string ("true" or "false") or a Boolean (true or false). The system may not verify email addresses for Sign in with Apple at Work & School users, and this claim is "false" or false for those users.
//
// is_private_email -  A string or Boolean value that indicates whether the email that the user shares is the proxy address. The value can either be a string ("true" or "false") or a Boolean (true or false).
//
// real_user_status - An Integer value that indicates whether the user appears to be a real person. Use the value of this claim to mitigate fraud. The possible values are: 0 (or Unsupported), 1 (or Unknown), 2 (or LikelyReal). For more information, see ASUserDetectionStatus. This claim is present only in iOS 14 and later, macOS 11 and later, watchOS 7 and later, tvOS 14 and later. The claim isn’t present or supported for web-based apps.
//
// transfer_sub - A string value that represents the transfer identifier for migrating users to your team. This claim is present only during the 60-day transfer period after you transfer an app. For more information, see Bringing new apps and users into your team.
//
// org_id - A string that represents the user’s organization. This value is only returned for Managed Apple Accounts in Apple School Manager (ASM) or Apple Business Manager (ABM).
//
// scopes - This value is only returned for Managed Apple Accounts in Apple School Manager (ASM) and represents the requested level of access. Valid values are edu.classes.read and edu.users.read. For more information, see Roster API.
#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppleTokenClaims {
  pub iss: String,
  pub aud: String,
  pub exp: i64,
  pub iat: i64,
  pub sub: String,
  
  #[serde(default)]
  pub nonce: Option<String>,
  #[serde(default)]
  pub nonce_supported: Option<bool>,
  pub email: Option<String>,
  #[serde(default, deserialize_with = "deserialize_bool_or_string")]
  pub email_verified: Option<bool>,
  #[serde(default, deserialize_with = "deserialize_bool_or_string")]
  pub is_private_email: Option<bool>,
  #[serde(default)]
  pub real_user_status: Option<i64>,
  #[serde(default)]
  pub transfer_sub: Option<String>,
  #[serde(default)]
  pub org_id: Option<String>,
  #[serde(default)]
  pub scopes: Option<String>,
}

/// see <https://developer.apple.com/documentation/sign_in_with_apple/processing_changes_for_sign_in_with_apple_accounts>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2Server {
  pub iss: String,
  pub aud: String,
  pub exp: i32,
  pub iat: i32,
  pub jti: String,
  /// Note that this is documented different to how it is sent.
  /// see https://developer.apple.com/forums/thread/655485
  #[serde(deserialize_with = "deserialize_events")]
  pub events: ClaimsServer2ServerEvent,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2ServerEvent {
  #[serde(rename = "type")]
  pub event_type: String,
  pub sub: String,
  pub event_time: i64,
  pub email: Option<String>,
  pub is_private_email: Option<String>,
}

// The signature of a deserialize_with function must follow the pattern:
//
//    fn deserialize<'de, D>(D) -> Result<T, D::Error>
//    where
//        D: Deserializer<'de>
//
// although it may also be generic over the output types T.
pub fn deserialize_events<'de, D>(deserializer: D) -> Result<ClaimsServer2ServerEvent, D::Error>
where
  D: Deserializer<'de>,
{
  let s = String::deserialize(deserializer)?;
  let events: ClaimsServer2ServerEvent = serde_json::from_str(s.as_str()).map_err(serde::de::Error::custom)?;
  Ok(events)
}
