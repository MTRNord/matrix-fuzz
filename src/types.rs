use fuzzcheck::DefaultMutator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginGet {
    pub flows: Vec<Flow>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flow {
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginPost {
    pub user_id: String,
    pub access_token: String,
    pub home_server: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct CreateRoomMagicJSON {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_content: Option<HashMap<String, String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

// FIXME: This is stupid hacky.
impl From<&CreateRoomMagic> for CreateRoomMagicJSON {
    fn from(item: &CreateRoomMagic) -> Self {
        let mut creation_content = HashMap::new();
        if let Some(mut creation_content_keys) = item.creation_content_keys.clone() {
            if let Some(mut creation_content_values) = item.creation_content_values.clone() {
                if creation_content_keys.len() > creation_content_values.len() {
                    creation_content_keys.truncate(creation_content_values.len());
                } else {
                    creation_content_values.truncate(creation_content_keys.len());
                }
                for (key, value) in creation_content_keys
                    .iter()
                    .zip(creation_content_values.iter())
                {
                    creation_content.insert(key.to_string(), value.to_string());
                }
            }
        }

        CreateRoomMagicJSON {
            invite: item.invite.clone(),
            is_direct: item.is_direct,
            name: item.name.clone(),
            preset: item.preset.clone(),
            room_alias_name: item.room_alias_name.clone(),
            room_version: item.room_version.clone(),
            topic: item.topic.clone(),
            visibility: item.visibility.clone(),
            creation_content: if item.creation_content_keys.is_none()
                || item.creation_content_values.is_none()
            {
                None
            } else {
                Some(creation_content)
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, DefaultMutator)]
pub struct CreateRoomMagic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_content_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_content_values: Option<Vec<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_version: Option<String>,
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
