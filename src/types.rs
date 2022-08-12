pub mod create_room;

use serde::{Deserialize, Serialize};

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
