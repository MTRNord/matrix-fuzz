use std::{collections::HashMap, path::Path};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiFile {
    pub swagger: String,
    pub info: Info,
    pub host: String,
    pub schemes: Vec<String>,
    pub base_path: String,
    pub consumes: Option<Vec<String>>,
    pub produces: Option<Vec<String>>,
    pub security_definitions: Option<SecurityDefinitions>,
    pub paths: HashMap<String, OpenapiPath>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub title: String,
    pub version: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityDefinitions {
    #[serde(rename = "$ref")]
    pub reference: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenapiPath {
    pub get: Option<Request>,
    pub post: Option<Request>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub summary: String,
    pub description: Option<String>,
    pub operation_id: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub responses: HashMap<u64, OpenapiResponse>,
    pub tags: Option<Vec<String>>,
    pub parameters: Option<Vec<Parameter>>,
    pub security: Option<Vec<HashMap<String, serde_json::Value>>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenapiResponse {
    pub description: String,
    pub examples: Option<HashMap<String, serde_json::Value>>,
    #[serde(with = "serde_yaml::with::singleton_map", default)]
    pub schema: Option<Schema>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Schema {
    Ref(RefSchema),
    Array(ArraySchema),
    Object(ObjectSchema),
    String(StringSchema),
    Integer(IntegerSchema),
    Boolean(BooleanSchema),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectSchema {
    pub properties: HashMap<String, Schema>,
    #[serde(with = "serde_yaml::with::singleton_map", default)]
    // Kinda awkward but there is no way to say type must be "object"
    #[serde(rename = "type")]
    pub schema_type: String,
    pub exanple: Option<serde_json::Value>,
    pub description: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArraySchema {
    #[serde(with = "serde_yaml::with::singleton_map", default)]
    pub items: Vec<Schema>,
    // Kinda awkward but there is no way to say type must be "array"
    #[serde(rename = "type")]
    pub schema_type: String,
    pub description: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefSchema {
    #[serde(rename = "$ref")]
    pub reference: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringSchema {
    // Kinda awkward but there is no way to say type must be "string"
    #[serde(rename = "type")]
    pub schema_type: String,
    pub description: Option<String>,
    #[serde(rename = "x-example")]
    pub x_example: Option<serde_json::Value>,
    #[serde(rename = "x-changedInMatrixVersion")]
    pub x_changed_in_matrix_version: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegerSchema {
    // Kinda awkward but there is no way to say type must be "integer"
    #[serde(rename = "type")]
    pub schema_type: String,
    pub description: Option<String>,
    #[serde(rename = "x-example")]
    pub x_example: Option<serde_json::Value>,
    #[serde(rename = "x-changedInMatrixVersion")]
    pub x_changed_in_matrix_version: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BooleanSchema {
    // Kinda awkward but there is no way to say type must be "boolean"
    #[serde(rename = "type")]
    pub schema_type: String,
    pub description: Option<String>,
    #[serde(rename = "x-example")]
    pub x_example: Option<serde_json::Value>,
    #[serde(rename = "x-changedInMatrixVersion")]
    pub x_changed_in_matrix_version: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub in_: String,
    pub description: Option<String>,
    pub required: Option<bool>,
    #[serde(with = "serde_yaml::with::singleton_map", default)]
    pub schema: Option<Schema>,
    #[serde(rename = "x-example")]
    pub x_example: Option<serde_json::Value>,
    #[serde(rename = "x-changedInMatrixVersion")]
    pub x_changed_in_matrix_version: Option<serde_json::Value>,
}

pub fn parse<P: AsRef<Path>>(path: P) -> OpenApiFile {
    let file = std::fs::File::open(path).unwrap();
    let reader = std::io::BufReader::new(file);
    serde_yaml::from_reader(reader).unwrap()
}
