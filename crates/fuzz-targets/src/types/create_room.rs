use fuzzcheck::{DefaultMutator, Mutator};
use fuzzcheck_serde_json_generator::json_value_mutator;
use serde::{Deserialize, Serialize};
use serde_json::Value;

type ValueMutator = impl Mutator<Value>;

fn creation_content_skip(value: &Value) -> bool {
    value.is_string()
        || value.is_i64()
        || value.is_boolean()
        || value.is_array()
        || value.is_null()
        || value.is_u64()
}

fn room_version_skip(value: &Option<String>) -> bool {
    if value.is_none() {
        return true;
    }
    if let Some(ref value) = value {
        if value.is_empty() {
            return true;
        }
    }
    false
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, DefaultMutator)]
pub struct CreateRoomMagicJSON {
    #[serde(skip_serializing_if = "creation_content_skip")]
    #[field_mutator(ValueMutator = { json_value_mutator() })]
    pub creation_content: Value,
    //#[serde(skip_serializing_if = "Option::is_none")]
    // Required for more fuzzing results
    pub initial_state: Vec<StateEventJSON>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite: Option<Vec<String>>,
    // Due to https://github.com/matrix-org/synapse/issues/13512
    //#[serde(skip_serializing_if = "Option::is_none")]
    //pub invite_3pid: Option<Vec<Invite3pid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_direct: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    // Disabled to have more fuzz results
    //#[serde(skip_serializing_if = "Option::is_none")]
    //pub room_alias_name: Option<String>,
    // Disabled to have more fuzz results
    //#[serde(skip_serializing_if = "room_version_skip")]
    //pub room_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, DefaultMutator, Default)]
pub struct Invite3pid {
    pub address: String,
    pub id_access_token: String,
    pub id_server: String,
    pub medium: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, DefaultMutator)]
pub struct StateEventJSON {
    #[field_mutator(ValueMutator = {json_value_mutator()})]
    pub content: Value,
    #[serde(rename = "type")]
    pub _type: String,
    pub state_key: String,
}
