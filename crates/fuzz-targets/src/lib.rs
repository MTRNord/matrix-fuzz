#![feature(type_alias_impl_trait)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]
#![feature(impl_trait_in_assoc_type)]
#![feature(coverage_attribute)]

use codegen::generate_fuzz_targets;

generate_fuzz_targets!("https://spec.matrix.org/v1.8/client-server-api/api.json");

// #[cfg(all(fuzzing, test))]
// mod tests {
//     use crate::types::{create_room::CreateRoomMagicJSON, LoginPostReq};
//     use std::env;

//     fn login(data: &LoginPostReq) -> bool {
//         let mut json_data = data.clone();
//         // We hardcode the type for better fuzzing
//         cfg_if::cfg_if! {
//             if #[cfg(feature = "token_auth")] {
//                 json_data._type = "com.devture.shared_secret_auth".to_string();
//             } else {
//                 json_data._type = "m.login.password".to_string();
//             }
//         }

//         let username = match env::var("MATRIX_USERNAME") {
//             Ok(v) => v,
//             Err(e) => panic!("$MATRIX_USERNAME is not set ({})", e),
//         };

//         if json_data.user.is_some() {
//             json_data.user = Some(username.clone());
//         }
//         if let Some(identifier) = &mut json_data.identifier {
//             identifier.user = username;
//             identifier._type = "m.id.user".to_string();
//         }

//         if let Some(user) = &json_data.user {
//             if user.contains('\0') {
//                 json_data.user = Some(user.replace('\0', ""));
//             }
//         }
//         if let Some(medium) = &json_data.medium {
//             if medium.contains('\0') {
//                 json_data.medium = Some(medium.replace('\0', ""));
//             }
//         }
//         if let Some(address) = &json_data.address {
//             if address.contains('\0') {
//                 json_data.address = Some(address.replace('\0', ""));
//             }
//         }
//         if let Some(user) = &json_data.user {
//             if user.contains('\0') {
//                 json_data.user = Some(user.replace('\0', ""));
//             }
//         }
//         /*if let Some(password) = &json_data.password {
//             if password.contains('\0' {
//                 json_data.password = Some(password.replace('\0', ""));
//             }
//         }*/
//         let client = crate::client();
//         let server = match env::var("MATRIX_SERVER") {
//             Ok(v) => v,
//             Err(_) => "http://localhost:8008".to_string(),
//         };
//         let resp = client
//             .post(format!("{}/_matrix/client/v3/login", server))
//             .json(&json_data)
//             .send();
//         if let Ok(resp) = resp {
//             let status = resp.status();
//             if !status.is_success() {
//                 /*if status == 400 {
//                     return true;
//                 }*/
//                 let content = resp.text();
//                 if let Ok(ref content) = content {
//                     if content.contains("Unknown login type")
//                         || content.contains("Invalid login submission")
//                         || content.contains("Invalid username or password")
//                     {
//                         return true;
//                     }
//                 }
//                 println!("Status: {:?}", status);
//                 println!("Content: {:?}", content);
//             }
//         }
//         false
//     }

//     #[test]
//     fn fuzz_login() {
//         let client = crate::client();
//         let server = match env::var("MATRIX_SERVER") {
//             Ok(v) => v,
//             Err(_) => "http://localhost:8008".to_string(),
//         };
//         let resp = client
//             .get(format!("{}/_matrix/key/v2/server", server))
//             .send()
//             .unwrap();
//         if !resp.status().is_success() {
//             panic!("Failed to connect");
//         }

//         let result = fuzzcheck::fuzz_test(login)
//             .default_options()
//             .stop_after_first_test_failure(true)
//             .launch();
//         assert!(!result.found_test_failure);
//     }

//     fn create_room(data: &CreateRoomMagicJSON) -> bool {
//         let mut json_data = data.clone();
//         for mut state in &mut json_data.initial_state {
//             if state.content.is_array()
//                 || state.content.is_boolean()
//                 || state.content.is_null()
//                 || state.content.is_string()
//                 || state.content.is_u64()
//             {
//                 state.content = serde_json::Value::Object(serde_json::Map::new());
//             }
//         }

//         // HACK due to https://github.com/matrix-org/synapse/issues/13510
//         /*if let Some(room_alias_name) = &json_data.room_alias_name {
//             if room_alias_name.contains('\0') {
//                 json_data.room_alias_name = Some(room_alias_name.replace('\0', ""));
//             }
//         }*/
//         // HACK due to NUL in type or state_key
//         for state in json_data.initial_state.iter_mut() {
//             state._type = state._type.replace('\0', "");
//             state.state_key = state.state_key.replace('\0', "");
//         }

//         /*// HACK due to https://github.com/matrix-org/synapse/issues/13511
//         if let Some(pids) = &data.invite_3pid {
//             for pid in pids {
//                 if pid.address.is_empty() {
//                     return true;
//                 }
//             }
//         }*/
//         // TODO: Login once and reuse the access token
//         let access_token = crate::access_token();
//         let client = crate::client();
//         let server = match env::var("MATRIX_SERVER") {
//             Ok(v) => v,
//             Err(_) => "http://localhost:8008".to_string(),
//         };
//         let resp = client
//             .post(format!("{}/_matrix/client/v3/createRoom", server))
//             .header("Authorization", format!("Bearer {}", access_token))
//             .json(&json_data)
//             .send();
//         if let Ok(resp) = resp {
//             let status = resp.status();
//             if !status.is_success() {
//                 //println!("Status: {:?}", status);
//                 let content = resp.text();
//                 if let Ok(ref content) = content {
//                     if content.contains("M_ROOM_IN_USE")
//                         || content.contains("Invalid characters in room alias")
//                         || content.contains("':' is not permitted in the room alias name. Please note this expects a local part — 'wombat', not '#wombat:example.com'.")
//                         || content.contains("M_UNSUPPORTED_ROOM_VERSION")
//                         || content.contains("Invalid user_id")
//                         || content.contains("is not a valid preset")
//                         || content.contains("You are not allowed to set others state")
//                         || content.contains("JSON integer out of range")
//                         || content.contains(" too large")
//                     {
//                         return true;
//                     }
//                 }
//                 println!("Content: {:?}", content);

//                 return false;
//             }
//         }
//         true
//     }

//     #[test]
//     fn fuzz_create_room() {
//         let client = crate::client();
//         let server = match env::var("MATRIX_SERVER") {
//             Ok(v) => v,
//             Err(_) => "http://localhost:8008".to_string(),
//         };
//         let resp = client
//             .get(format!("{}/_matrix/key/v2/server", server))
//             .send()
//             .unwrap();
//         if !resp.status().is_success() {
//             panic!("Failed to connect");
//         }

//         let result = fuzzcheck::fuzz_test(create_room)
//             .default_options()
//             .stop_after_first_test_failure(true)
//             .launch();
//         assert!(!result.found_test_failure);
//     }
// }
