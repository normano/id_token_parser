use core::fmt;

use serde::{Deserializer, de::{self, Visitor}};

pub fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
  D: Deserializer<'de>,
{
  struct BoolOrString;

  impl<'de> Visitor<'de> for BoolOrString {
    type Value = Option<bool>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
      formatter.write_str("a boolean or a string containing 'true' or 'false'")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
      Ok(Some(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
      E: de::Error,
    {
      match value {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(E::custom(format!("invalid boolean string: {}", value))),
      }
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
      Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
      Ok(None)
    }
  }

  deserializer.deserialize_any(BoolOrString)
}
