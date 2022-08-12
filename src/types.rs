use fuzzcheck::{
    mutators::{grammar::*, map::MapMutator, option::OptionMutator},
    DefaultMutator, Mutator,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::rc::{Rc, Weak};

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
pub struct CreateRoomMagic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_content: Option<Map<String, Value>>,
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

fuzzcheck::make_mutator! {
    name: CreateRoomMagicMutator,
    default: true,
    type:
        pub struct CreateRoomMagic {
            #[field_mutator(OptionMutator<Map<String,Value>, JSONMutator> = { OptionMutator::new(json_object_mutator()) } )]
            pub creation_content: Option<Map<String,Value>>,
            pub invite: Option<Vec<String>>,
            // Due to https://github.com/matrix-org/synapse/issues/13512
            //pub invite_3pid: Option<Vec<Invite3pid>>,
            pub is_direct: Option<bool>,
            pub name: Option<String>,
            pub preset: Option<String>,
            pub room_alias_name: Option<String>,
            pub room_version: Option<String>,
            pub topic: Option<String>,
            pub visibility: Option<String>,
        }
}

#[derive(Clone, Serialize, Deserialize, Debug, DefaultMutator, Default)]
pub struct Invite3pid {
    pub address: String,
    pub id_access_token: String,
    pub id_server: String,
    pub medium: String,
}
fn null() -> Rc<Grammar> {
    regex("null")
}

fn boolean() -> Rc<Grammar> {
    regex("true|false")
}

fn text() -> Rc<Grammar> {
    concatenation([
        literal('"'),
        regex("([\u{0020}-\u{0021}]|[\u{0023}-\u{7f}]|.)+"),
        literal('"'),
    ])
    //concatenation([literal('"'), regex("([\u{0}-\u{7f}]|.)+"), literal('"')])
}

fn number() -> Rc<Grammar> {
    regex("[0-9]+")
}

fn json_object_entry(rule: &Weak<Grammar>) -> Rc<Grammar> {
    concatenation([text(), literal(':'), json_value(rule, None)])
}

fn json_array(outer_rule: &Weak<Grammar>) -> Rc<Grammar> {
    recursive(|rule| {
        concatenation([
            literal('['),
            json_value(outer_rule, Some(rule)),
            repetition(
                concatenation([literal(','), json_value(outer_rule, Some(rule))]),
                1..,
            ),
            literal(']'),
        ])
    })
}

fn json_value(object_rule: &Weak<Grammar>, array_rule: Option<&Weak<Grammar>>) -> Rc<Grammar> {
    if let Some(array_rule) = array_rule {
        alternation([
            recurse(object_rule),
            recurse(array_rule),
            text(),
            number(),
            null(),
            boolean(),
        ])
    } else {
        alternation([
            recurse(object_rule),
            json_array(object_rule),
            text(),
            number(),
            null(),
            boolean(),
        ])
    }
}

fn json_object() -> Rc<Grammar> {
    recursive(|rule| {
        concatenation([
            literal('{'),
            json_object_entry(rule),
            repetition(concatenation([literal(','), json_object_entry(rule)]), 1..),
            literal('}'),
        ])
    })
}

type JSONMutator = impl Mutator<Map<String, Value>>;

fn json_object_mutator() -> JSONMutator {
    MapMutator::new(
        grammar_based_ast_mutator(json_object()),
        |_string: &Map<String, Value>| {
            // FIXME: This is a hack
            Some(serde_json::from_str::<AST>(r#"{"Sequence":[{"Token":"{"},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"񶲼"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"["},{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"\u0006"}]},{"Token":"\""}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"{"},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"J"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Sequence":[{"Token":"{"},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"󓯠"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"6"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"|"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"["},{"Sequence":[{"Sequence":[{"Token":"["},{"Sequence":[{"Token":"n"},{"Token":"u"},{"Token":"l"},{"Token":"l"}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"["},{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"󻘛"}]},{"Token":"\""}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"["},{"Sequence":[{"Sequence":[{"Token":"{"},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"𪪍"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"t"},{"Token":"r"},{"Token":"u"},{"Token":"e"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"\u0001"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"4"}]}]}]}]},{"Token":"}"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"{"},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"񿊌"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"f"},{"Token":"a"},{"Token":"l"},{"Token":"s"},{"Token":"e"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"m"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"8"}]}]}]}]},{"Token":"}"}]}]}]}]},{"Token":"]"}]}]}]}]},{"Token":"]"}]}]}]}]},{"Token":"]"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Token":"n"},{"Token":"u"},{"Token":"l"},{"Token":"l"}]}]}]},{"Token":"]"}]}]}]}]},{"Token":"}"}]}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"}"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"𬗲"}]},{"Token":"\""}]}]}]}]},{"Token":"}"}]}]}]}]},{"Token":"]"}]}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"񡷸"}]},{"Token":"\""}]},{"Token":":"},{"Sequence":[{"Token":"["},{"Sequence":[{"Token":"\""},{"Sequence":[{"Token":"򔾂"}]},{"Token":"\""}]},{"Sequence":[{"Sequence":[{"Token":","},{"Sequence":[{"Token":"0"}]}]}]},{"Token":"]"}]}]}]}]},{"Token":"}"}]}"#).unwrap())
            /*match serde_json::from_str::<AST>(string) {
                Ok(ast) => Some(ast),
                Err(e) => {
                    println!("Error: {:?}", e);

                    None
                }
            }*/
        },
        |ast| {
            let string = ast.to_string();
            //println!("{}", string);
            serde_json::from_str::<Map<String, Value>>(&string).unwrap()
        },
        |_, cplx| cplx,
    )
}
