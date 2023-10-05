use convert_case::{Case, Casing};
use okapi::{
    openapi3::{OpenApi, RefOr},
    schemars::schema::Schema,
};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{parse_macro_input, LitStr};

fn load_ref<T: for<'de> serde::de::Deserialize<'de> + Clone>(ref_or_object: &RefOr<T>) -> T {
    match ref_or_object {
        RefOr::Ref(_) => {
            panic!("This would indicate a broken ref")
        }
        RefOr::Object(obj) => obj.clone(),
    }
}

#[proc_macro]
pub fn generate_fuzz_targets(input: TokenStream) -> TokenStream {
    let spec_url = parse_macro_input!(input as LitStr).value();

    let mut structs: Vec<_> = Vec::new();
    let mut tests: Vec<_> = Vec::new();

    let parsed: OpenApi = reqwest::blocking::get(spec_url)
        .expect("Unable to get spec api")
        .json()
        .expect("Unable to parse spec as openapi json");
    for (path, path_description) in parsed.paths {
        if let Some(request) = path_description.get {
            let function_path = request.operation_id.unwrap();
            let function_ident = format_ident!("{}", function_path.to_case(Case::Snake));
            let fuzz_function_ident = format_ident!("fuzz_{}", function_ident);

            // TODO: Find an replace path arguments with random data.
            let request_body = if let Some(security) = request.security {
                if let Some(security) = security.first() {
                    if security.contains_key("accessToken") {
                        quote! {
                            let access_token = crate::access_token();
                            let resp = client
                                .get(format!("{}{}", server, #path))
                                .header("Authorization", format!("Bearer {}", access_token))
                                .send();
                        }
                    } else {
                        quote! {
                            let resp = client
                                .get(format!("{}{}", server, #path))
                                .send();
                        }
                    }
                } else {
                    quote! {
                        let resp = client
                            .get(format!("{}{}", server, #path))
                            .send();
                    }
                }
            } else {
                quote! {
                    let resp = client
                        .get(format!("{}{}", server, #path))
                        .send();
                }
            };

            let mut possible_error_codes = Vec::new();
            let responses = request.responses.responses;
            for (code, _) in responses {
                let int_code: u16 = code.parse().unwrap();
                possible_error_codes.push(quote! {#int_code,});
            }

            // Generate test code from here
            tests.push(quote! {
                // TODO: Make the fuzz input specific to the path. As in if there are multiple values use a tuple
                fn #function_ident(fuzz_input: &::std::string::String) -> bool {
                    let mut json_data = fuzz_input.clone();

                    let client = crate::client();
                    let server = match std::env::var("MATRIX_SERVER") {
                        Ok(v) => v,
                        Err(_) => "http://localhost:8008".to_string(),
                    };

                    #request_body

                    let allowed_codes = [
                        #(#possible_error_codes)*
                    ];

                    if let Ok(resp) = resp {
                        let status = resp.status();
                        if !allowed_codes.contains(&status.as_u16()) {
                            let content = resp.text();
                            if let Ok(ref content) = content {
                                // TODO: use mapping file for errors to ignore
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
        } else if let Some(request) = path_description.post {
            let function_path = request.operation_id.unwrap();
            let function_ident = format_ident!("{}", function_path.to_case(Case::Snake));
            let struct_ident_body = format_ident!("{}", function_path.to_case(Case::UpperCamel));
            let fuzz_function_ident = format_ident!("fuzz_{}", function_ident);

            let mut struct_body = Vec::new();
            if let Some(request_body) = request.request_body {
                let obj = load_ref(&request_body);
                if let Some(json_obj) = obj.content.get("application/json") {
                    let schema = json_obj.schema.clone().expect("Missing schema for body");
                    if let Some(properties_obj) = schema.object {
                        let properties = properties_obj.properties;
                        for (key, value) in properties.iter() {
                            let key_ident =
                                format_ident!("{}", key.replace('.', "_").to_case(Case::Snake));
                            if let Schema::Object(_type_definition) = value {
                                struct_body.push(quote! {
                                    #[field_mutator(::fuzzcheck_serde_json_generator::ValueMutator = { json_value_mutator() })]
                                    #key_ident: ::serde_json::Value
                                });
                            }
                        }
                    }
                }
            }

            // Generate body struct
            structs.push(quote! {
                #[derive(::std::fmt::Debug, ::std::clone::Clone, ::serde::Serialize, ::serde::Deserialize, ::fuzzcheck::DefaultMutator)]
                struct #struct_ident_body {
                    #(#struct_body),*
                }
            });

            let path = LitStr::new(&path, Span::call_site());

            // TODO: Make sure we also replace path arguments either with sensible or non sensible stuff
            let request_body = if let Some(security) = request.security {
                if let Some(security) = security.first() {
                    if security.contains_key("accessToken") {
                        quote! {
                            let access_token = crate::access_token();
                            let resp = client
                                .post(format!("{}{}", server, #path))
                                .header("Authorization", format!("Bearer {}", access_token))
                                .json(&json_data)
                                .send();
                        }
                    } else {
                        quote! {
                            let resp = client
                                .post(format!("{}{}", server, #path))
                                .json(&json_data)
                                .send();
                        }
                    }
                } else {
                    quote! {
                        let resp = client
                            .post(format!("{}{}", server, #path))
                            .json(&json_data)
                            .send();
                    }
                }
            } else {
                quote! {
                    let resp = client
                        .post(format!("{}{}", server, #path))
                        .json(&json_data)
                        .send();
                }
            };

            let mut possible_error_codes = Vec::new();
            let responses = request.responses.responses;
            for (code, _) in responses {
                let int_code: u16 = code.parse().unwrap();
                possible_error_codes.push(quote! {#int_code,});
            }

            let function_body = quote! {
                let mut json_data = fuzz_input.clone();

                // TODO: iterate over the fields and automatically remove faulty characters
                //  if let Some(user) = &json_data.user {
                //    if user.contains('\0') {
                //      json_data.user = Some(user.replace('\0', ""));
                //    }
                //  }

                let client = crate::client();
                let server = match std::env::var("MATRIX_SERVER") {
                    Ok(v) => v,
                    Err(_) => "http://localhost:8008".to_string(),
                };

                #request_body

                let allowed_codes = [
                    #(#possible_error_codes)*
                ];

                if let Ok(resp) = resp {
                    let status = resp.status();
                    // TODO: use mapping file for status to ignore/not ignore
                    if !allowed_codes.contains(&status.as_u16()) {
                        let content = resp.text();
                        if let Ok(ref content) = content {
                            // TODO: use mapping file for errors to ignore
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
            };

            let main_function = if let Some(description) = path_description.description {
                let description_literal = LitStr::new(&description, Span::call_site());
                quote! {
                    #[doc = #description_literal]
                    fn #function_ident(fuzz_input: &crate::#struct_ident_body) -> bool {
                        #function_body
                    }
                }
            } else {
                quote! {
                    fn #function_ident(fuzz_input: &crate::#struct_ident_body) -> bool {
                        #function_body
                    }
                }
            };

            // Generate test code from here
            tests.push(quote! {
                #main_function

                #[test]
                fn #fuzz_function_ident() {
                    let client = crate::client();
                    let server = match std::env::var("MATRIX_SERVER") {
                        Ok(v) => v,
                        Err(_) => "http://localhost:8008".to_string(),
                    };
                    // Healthcheck for matrix servers
                    let resp = client
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

    let expanded = quote! {
        use ::fuzzcheck_serde_json_generator::json_value_mutator;

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize)]
        struct LoginGet {
            pub flows: Vec<Flow>,
        }

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize, ::std::cmp::PartialEq, ::std::cmp::Eq)]
        struct Flow {
            #[serde(rename = "type")]
            pub type_: ::std::string::String,
        }

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize)]
        struct LoginPost {
            pub user_id: ::std::string::String,
            pub access_token: ::std::string::String,
            pub home_server: ::std::string::String,
        }

        #[coverage(off)]
        fn login() -> ::std::string::String {
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

        #[coverage(off)]
        pub fn access_token() -> &'static ::std::string::String {
            static INSTANCE: once_cell::sync::OnceCell<::std::string::String> = once_cell::sync::OnceCell::new();
            INSTANCE.get_or_init(login)
        }

        #[coverage(off)]
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


        #(#structs)*

        #[cfg(test)]
        mod tests {
            #(#tests)*
        }
    };

    TokenStream::from(expanded)
}
