#![allow(non_snake_case)]
use matrix_fuzz::{client, secrets::ACCESS_TOKEN, types::create_room::CreateRoomMagicJSON};

fn main() {
    afl::fuzz_nohook!(|data: CreateRoomMagicJSON| {
        let mut data = data;
        // HACK due to https://github.com/matrix-org/synapse/issues/13510
        if let Some(room_alias_name) = &data.room_alias_name {
            if room_alias_name.contains('\0') {
                data.room_alias_name = None;
            }
        }

        // HACK due to NUL in type or state_key
        if let Some(initial_state) = &mut data.initial_state {
            initial_state
                .retain(|state| !(state._type.contains('\0') || state.state_key.contains('\0')));
            // for state in initial_state {
            //     if state._type.contains('\0') {
            //         return;
            //     }
            //     if state.state_key.contains('\0') {
            //         return;
            //     }
            // }
        }

        /*// HACK due to https://github.com/matrix-org/synapse/issues/13511
        if let Some(pids) = &data.invite_3pid {
            for pid in pids {
                if pid.address.is_empty() {
                    return;
                }
            }
        }*/

        // TODO: Login once and reuse the access token
        let access_token = ACCESS_TOKEN;
        let client = client();
        let resp = client
            .post("http://localhost:8008/_matrix/client/v3/createRoom")
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&data)
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
                    {
                        return;
                    }
                }

                panic!("Content: {:?}", content);
            }
        }
    });
}
