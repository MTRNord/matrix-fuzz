#![feature(no_coverage)]
#![feature(type_alias_impl_trait)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use crate::types::{Flow, LoginGet, LoginPost};
use once_cell::sync::OnceCell;
use std::collections::HashMap;

pub mod secrets;
pub mod types;

#[no_coverage]
pub fn access_token() -> &'static String {
    static INSTANCE: OnceCell<String> = OnceCell::new();
    INSTANCE.get_or_init(login)
}

#[no_coverage]
pub fn client() -> &'static reqwest::blocking::Client {
    static INSTANCE: OnceCell<reqwest::blocking::Client> = OnceCell::new();
    INSTANCE.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .connect_timeout(Some(std::time::Duration::from_secs(30)))
            .user_agent("synapse-fuzzer")
            .gzip(true)
            .build()
            .unwrap()
    })
}

#[no_coverage]
fn login() -> String {
    let client = crate::client();
    let res: LoginGet = client
        .get("http://localhost:8008/_matrix/client/v3/login")
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(res.flows.contains(&Flow {
        type_: "m.login.password".to_string(),
    }));

    let mut map = HashMap::new();
    map.insert("type", "m.login.password");
    map.insert("user", secrets::USERNAME);
    map.insert("password", secrets::PASSWORD);
    let res: LoginPost = client
        .post("http://localhost:8008/_matrix/client/v3/login")
        .json(&map)
        .send()
        .unwrap()
        .json()
        .unwrap();

    res.access_token
}

#[cfg(all(test, not(fuzzing)))]
mod tests {
    use reqwest::header::{HeaderValue, CONTENT_TYPE};

    use crate::types::create_room::CreateRoomMagicJSON;

    #[test]
    #[no_coverage]
    fn connection_test() {
        let client = crate::client();
        let resp = client
            .get("http://localhost:8008/_matrix/key/v2/server")
            .send()
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[test]
    #[no_coverage]
    fn null_in_room() {
        let content = CreateRoomMagicJSON {
            name: Some("a".to_string()),
            room_alias_name: Some("\0".to_string()),
            visibility: Some("a".to_string()),
            is_direct: Some(false),
            topic: Some("c".to_string()),
            ..Default::default()
        };
        let access_token = crate::access_token();
        let client = crate::client();
        let resp = client
            .post("http://localhost:8008/_matrix/client/v3/createRoom")
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&content)
            .send()
            .unwrap();

        assert!(!resp.status().is_success());
        assert!(resp.text().unwrap().contains("Internal server error"));
    }

    #[test]
    #[no_coverage]
    fn weird_req() {
        let content = std::fs::read_to_string("./weird_ones/af84a60a1b7997b4.json").unwrap();
        let access_token = crate::access_token();
        let client = crate::client();
        let resp = client
            .post("http://localhost:8008/_matrix/client/v3/createRoom")
            .header("Authorization", format!("Bearer {}", access_token))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(content)
            .send();
        assert!(resp.is_err())
    }
}

#[cfg(all(fuzzing, test))]
mod tests {
    use crate::types::{create_room::CreateRoomMagicJSON, LoginPostReq};

    fn login(data: &LoginPostReq) -> bool {
        let mut json_data = data.clone();
        // We hardcode the type for better fuzzing
        cfg_if::cfg_if! {
            if #[cfg(feature = "token_auth")] {
                json_data._type = "com.devture.shared_secret_auth".to_string();
            } else {
                json_data._type = "m.login.password".to_string();
            }
        }
        if json_data.user.is_some() {
            json_data.user = Some(crate::secrets::USERNAME.to_string());
        }
        if let Some(identifier) = &mut json_data.identifier {
            identifier.user = crate::secrets::USERNAME.to_string();
            identifier._type = "m.id.user".to_string();
        }

        if let Some(user) = &json_data.user {
            if user.contains('\0') {
                json_data.user = Some(user.replace('\0', ""));
            }
        }
        if let Some(medium) = &json_data.medium {
            if medium.contains('\0') {
                json_data.medium = Some(medium.replace('\0', ""));
            }
        }
        if let Some(address) = &json_data.address {
            if address.contains('\0') {
                json_data.address = Some(address.replace('\0', ""));
            }
        }
        if let Some(user) = &json_data.user {
            if user.contains('\0') {
                json_data.user = Some(user.replace('\0', ""));
            }
        }
        /*if let Some(password) = &json_data.password {
            if password.contains('\0' {
                json_data.password = Some(password.replace('\0', ""));
            }
        }*/

        let client = crate::client();
        let resp = client
            .post("http://localhost:8008/_matrix/client/v3/login")
            .json(&json_data)
            .send();
        if let Ok(resp) = resp {
            let status = resp.status();
            if !status.is_success() {
                /*if status == 400 {
                    return true;
                }*/
                let content = resp.text();
                if let Ok(ref content) = content {
                    if content.contains("Unknown login type")
                        || content.contains("Invalid login submission")
                        || content.contains("Invalid username or password")
                    {
                        return true;
                    }
                }
                println!("Status: {:?}", status);
                println!("Content: {:?}", content);
            }
        }
        false
    }

    #[test]
    fn fuzz_login() {
        let client = crate::client();
        let resp = client
            .get("http://localhost:8008/_matrix/key/v2/server")
            .send()
            .unwrap();
        if !resp.status().is_success() {
            panic!("Failed to connect");
        }

        let result = fuzzcheck::fuzz_test(login)
            .default_options()
            .stop_after_first_test_failure(true)
            .launch();
        assert!(!result.found_test_failure);
    }

    fn create_room(data: &CreateRoomMagicJSON) -> bool {
        let mut json_data = data.clone();
        for mut state in &mut json_data.initial_state {
            if state.content.is_array()
                || state.content.is_boolean()
                || state.content.is_null()
                || state.content.is_string()
            {
                state.content = serde_json::Value::Object(serde_json::Map::new());
            }
        }

        // FIXME: We probably should set it to null and not do a false positive
        // HACK due to https://github.com/matrix-org/synapse/issues/13510
        if let Some(room_alias_name) = &json_data.room_alias_name {
            if room_alias_name.contains('\0') {
                json_data.room_alias_name = Some(room_alias_name.replace('\0', ""));
            }
        }
        // HACK due to NUL in type or state_key
        json_data
            .initial_state
            .retain(|state| !(state._type.contains('\0') || state.state_key.contains('\0')));

        /*// HACK due to https://github.com/matrix-org/synapse/issues/13511
        if let Some(pids) = &data.invite_3pid {
            for pid in pids {
                if pid.address.is_empty() {
                    return true;
                }
            }
        }*/

        // TODO: Login once and reuse the access token
        let access_token = crate::access_token();
        let client = crate::client();
        let resp = client
            .post("http://localhost:8008/_matrix/client/v3/createRoom")
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&json_data)
            .send();
        if let Ok(resp) = resp {
            let status = resp.status();
            if !status.is_success() {
                //println!("Status: {:?}", status);
                let content = resp.text();
                if let Ok(ref content) = content {
                    if content.contains("M_ROOM_IN_USE")
                        || content.contains("Invalid characters in room alias")
                        || content.contains("':' is not permitted in the room alias name. Please note this expects a local part — 'wombat', not '#wombat:example.com'.")
                        || content.contains("M_UNSUPPORTED_ROOM_VERSION") 
                        || content.contains("Invalid user_id") 
                        || content.contains("is not a valid preset") 
                        || content.contains("You are not allowed to set others state") 
                        || content.contains("JSON integer out of range")
                    {
                        return true;
                    }
                }
                println!("Content: {:?}", content);

                return false;
            }
        }
        true
    }

    #[test]
    fn fuzz_create_room() {
        let client = crate::client();
        let resp = client
            .get("http://localhost:8008/_matrix/key/v2/server")
            .send()
            .unwrap();
        if !resp.status().is_success() {
            panic!("Failed to connect");
        }

        let result = fuzzcheck::fuzz_test(create_room)
            .default_options()
            .stop_after_first_test_failure(true)
            .launch();
        assert!(!result.found_test_failure);
    }
}
