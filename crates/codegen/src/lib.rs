#![feature(path_file_prefix)]

use std::path::Path;

use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, LitStr};
use walkdir::WalkDir;

#[proc_macro]
pub fn generate_fuzz_targets(input: TokenStream) -> TokenStream {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let spec_path = parse_macro_input!(input as LitStr);
    let full_path = Path::new(&manifest_dir).join(spec_path.value());

    let mut tests: Vec<_> = Vec::new();

    for entry in WalkDir::new(full_path) {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    if let Some(extension) = entry.path().extension() {
                        if extension == "yaml" {
                            let module_name = entry.path().file_prefix();
                            if let Some(module_name) = module_name {
                                let module_name = module_name.to_string_lossy().to_string();
                                // TODO: Parse module for paths and then generate function names from it
                                let function_path = String::from("dummy");
                                let function_ident = format_ident!(
                                    "{}_{}",
                                    module_name.to_case(Case::Snake),
                                    function_path.to_case(Case::Snake)
                                );
                                let fuzz_function_ident = format_ident!("fuzz_{}", function_ident);

                                // Generate test code from here
                                tests.push(quote! {
                                    // TODO: Generate test code with name #function_ident
                                    fn #function_ident() {
                                        //blub
                                    }

                                    #[test]
                                    fn #fuzz_function_ident() {
                                        let client = crate::client();
                                        let server = match std::env::var("MATRIX_SERVER") {
                                            Ok(v) => v,
                                            Err(_) => "http://localhost:8008".to_string(),
                                        };
                                        // Healthcheck for matrix servers
                                        let resp = client
                                            // TODO: Set path from module
                                            .get(format!("{}/_matrix/key/v2/server", server))
                                            .send()
                                            .unwrap();
                                        if !resp.status().is_success() {
                                            panic!("Failed to connect");
                                        }

                                        let result = fuzzcheck::fuzz_test(#function_ident)
                                            .default_options()
                                            .stop_after_first_test_failure(true)
                                            .launch();
                                        assert!(!result.found_test_failure);
                                    }
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                panic!("Error while walking spec folder: {e:?}")
            }
        }
    }
    let expanded = quote! {
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct LoginGet {
            pub flows: Vec<Flow>,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
        struct Flow {
            #[serde(rename = "type")]
            pub type_: String,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct LoginPost {
            pub user_id: String,
            pub access_token: String,
            pub home_server: String,
        }

        #[no_coverage]
        fn login() -> String {
            let server = match std::env::var("MATRIX_SERVER") {
                Ok(v) => v,
                Err(_) => "http://localhost:8008".to_string(),
            };
            let username = match std::env::var("MATRIX_USERNAME") {
                Ok(v) => v,
                Err(e) => panic!("$MATRIX_USERNAME is not set ({})", e),
            };
            let password = match std::env::var("MATRIX_PASSWORD") {
                Ok(v) => v,
                Err(e) => panic!("$MATRIX_PASSWORD is not set ({})", e),
            };
            let client = crate::client();
            let res: LoginGet = client
                .get(format!("{}/_matrix/client/v3/login", server))
                .send()
                .unwrap()
                .json()
                .unwrap();
            assert!(res.flows.contains(&Flow {
                type_: "m.login.password".to_string(),
            }));

            let mut map = std::collections::HashMap::new();
            map.insert("type", "m.login.password");
            map.insert("user", &username);
            map.insert("password", &password);
            let res: LoginPost = client
                .post(format!("{}/_matrix/client/v3/login", server))
                .json(&map)
                .send()
                .unwrap()
                .json()
                .unwrap();

            res.access_token
        }

        #[no_coverage]
        pub fn access_token() -> &'static String {
            static INSTANCE: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();
            INSTANCE.get_or_init(login)
        }

        #[no_coverage]
        pub fn client() -> &'static reqwest::blocking::Client {
            static INSTANCE: once_cell::sync::OnceCell<reqwest::blocking::Client> = once_cell::sync::OnceCell::new();
            INSTANCE.get_or_init(|| {
                reqwest::blocking::Client::builder()
                    .connect_timeout(Some(std::time::Duration::from_secs(30)))
                    .user_agent("synapse-fuzzer")
                    .gzip(true)
                    .build()
                    .unwrap()
            })
        }

        #[cfg(test)]
        mod tests {
            #(#tests)*
        }

    };

    TokenStream::from(expanded)
}
