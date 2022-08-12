#![feature(no_coverage)]
#![feature(type_alias_impl_trait)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;

use once_cell::sync::OnceCell;

use crate::types::{Flow, LoginGet, LoginPost};

mod secrets;
mod types;

fn access_token() -> &'static String {
    static INSTANCE: OnceCell<String> = OnceCell::new();
    INSTANCE.get_or_init(login)
}
fn client() -> &'static reqwest::blocking::Client {
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

    use crate::types::CreateRoomMagic;

    #[test]
    fn connection_test() {
        let client = crate::client();
        let resp = client
            .get("http://localhost:8008/_matrix/key/v2/server")
            .send()
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[test]
    fn null_in_room() {
        let content = CreateRoomMagic {
            name: Some("a".to_string()),
            room_alias_name: Some("\0".to_string()),
            visibility: Some("a".to_string()),
            is_direct: Some(false),
            topic: Some("c".to_string()),
            ..Default::default()
        };
        println!("{}", serde_json::to_string(&content).unwrap());
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
    use crate::types::CreateRoomMagic;

    fn create_room(data: &CreateRoomMagic) -> bool {
        // FIXME: We probably should set it to null and not do a false positive
        // HACK due to https://github.com/matrix-org/synapse/issues/13510
        if let Some(room_alias_name) = &data.room_alias_name {
            if room_alias_name.contains("\0") {
                return true;
            }
        }
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
            .json(data)
            .send();
        if let Ok(resp) = resp {
            let status = resp.status().clone();
            if !status.is_success() {
                //println!("Status: {:?}", status);
                let content = resp.text();
                if let Ok(ref content) = content {
                    if content.contains("M_ROOM_IN_USE")
                    || content.contains("Invalid characters in room alias")
                    || content.contains("':' is not permitted in the room alias name. Please note this expects a local part — 'wombat', not '#wombat:example.com'.")
                    || content.contains("M_UNSUPPORTED_ROOM_VERSION") || content.contains("Invalid user_id") || content.contains("is not a valid preset")
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
