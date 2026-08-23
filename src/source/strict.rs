use std::fmt;

use indexmap::IndexMap;
use serde::Deserializer;
use serde::de::{
    self, DeserializeSeed, EnumAccess, Error as _, MapAccess, SeqAccess, VariantAccess, Visitor,
};

use super::{Node, NodePath, Scalar, SourceError};
use crate::config::SourceFormat;

pub(super) struct NodeSeed {
    format: SourceFormat,
    path: NodePath,
}

impl NodeSeed {
    pub(super) fn root(format: SourceFormat) -> Self {
        Self {
            format,
            path: NodePath::root(),
        }
    }

    fn at(format: SourceFormat, path: NodePath) -> Self {
        Self { format, path }
    }
}

impl<'de> DeserializeSeed<'de> for NodeSeed {
    type Value = Node;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NodeVisitor {
            format: self.format,
            path: self.path,
        })
    }
}

struct NodeVisitor {
    format: SourceFormat,
    path: NodePath,
}

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a structured scalar, sequence, or string-keyed mapping")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::Integer(value.to_string())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::Integer(value.to_string())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("non-finite floats are not supported"));
        }
        Ok(Node::Scalar(Scalar::Float(value.to_string())))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Node::Scalar(Scalar::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Node::Scalar(Scalar::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(NodeSeed::at(
            self.format,
            self.path.child_index(values.len()),
        ))? {
            values.push(value);
        }
        Ok(Node::Sequence(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = IndexMap::with_capacity(mapping.size_hint().unwrap_or(0));
        while let Some(key) = mapping.next_key::<String>()? {
            if self.format == SourceFormat::Json
                && key == "$serde_json::private::Number"
                && values.is_empty()
            {
                let number = mapping.next_value::<String>()?;
                if mapping.next_key::<String>()?.is_some() {
                    return Err(A::Error::custom("invalid JSON number representation"));
                }
                return Ok(Node::Scalar(number_scalar(&number)));
            }
            let path = self.path.child_key(&key);
            if values.contains_key(&key) {
                return Err(A::Error::custom(
                    SourceError::DuplicateKey {
                        format: self.format,
                        path,
                    }
                    .to_string(),
                ));
            }
            let value = mapping.next_value_seed(NodeSeed::at(self.format, path))?;
            values.insert(key, value);
        }
        Ok(Node::Mapping(values))
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (tag, variant) = data.variant::<String>()?;
        let value = variant.newtype_variant_seed(NodeSeed::at(self.format, self.path))?;
        Ok(Node::Tagged {
            tag,
            value: Box::new(value),
        })
    }
}

fn number_scalar(value: &str) -> Scalar {
    if value.contains(['.', 'e', 'E']) {
        Scalar::Float(value.to_owned())
    } else {
        Scalar::Integer(value.to_owned())
    }
}
