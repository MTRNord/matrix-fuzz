#![warn(clippy::missing_const_for_fn)]
use convert_case::{Case, Casing};
use lazy_regex::{regex, regex::Match};
use okapi::{
    openapi3::{OpenApi, Operation, PathItem, RefOr},
    schemars::schema::Schema,
};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote, quote_spanned};
use syn::{parse_macro_input, Ident, LitStr};

fn load_ref<T: for<'de> serde::de::Deserialize<'de> + Clone>(ref_or_object: &RefOr<T>) -> T {
    match ref_or_object {
        RefOr::Ref(_) => {
            panic!("This would indicate a broken ref")
        }
        RefOr::Object(obj) => obj.clone(),
    }
}

fn get_error_codes_for_path(
    function_span: Span,
    request: Operation,
) -> Vec<proc_macro2::TokenStream> {
    let mut possible_error_codes = Vec::new();
    let responses = request.responses.responses;
    for (code, _) in responses {
        let int_code: u16 = code.parse().unwrap();

        possible_error_codes.push(quote_spanned! { function_span => #int_code,});
    }
    possible_error_codes
}

fn extract_path_arguments(path: &str) -> Vec<Match> {
    let path_regex = regex!(r"(?m)\{.*?\}");
    let result = path_regex.captures_iter(path);

    result.map(|captures| captures.get(0).unwrap()).collect()
}

fn generate_get_targets(span: Span, path: String, request: Operation) -> proc_macro2::TokenStream {
    let function_path = request.operation_id.clone().unwrap();
    let function_ident = Ident::new(&function_path.to_case(Case::Snake), Span::call_site());
    let fuzz_function_ident = format_ident!("fuzz_{}", function_ident, span = Span::mixed_site());
    let function_span = function_ident.span();

    let path = path.trim();
    let mut path_code = quote_spanned! {function_span =>.get(format!("{}{}", server, #path))};
    let path_args = extract_path_arguments(path);
    let mut format_string = format!("{{}}{path}");
    let mut format_helpers = Vec::new();
    let mut unknowns: usize = 0;
    let mut unknowns_helper = Vec::new();
    for arg in &path_args {
        let string_match = arg.as_str();
        format_string = format_string.replace(string_match, "{}");
        if string_match.contains("roomId") {
            let function_ident = quote! {crate::create_fresh_room()};
            format_helpers.push(function_ident);
        } else if string_match.contains("userId") {
            let function_ident = quote! {crate::own_user_id()};
            format_helpers.push(function_ident);
        } else {
            let j = syn::Index::from(unknowns);
            // TODO: These are ones that are for sure wrong. We really need to see that we get instead random data from the fuzzer here.
            let function_ident: proc_macro2::TokenStream =
                quote! {crate::truncate_string(&fuzz_input.#j,255).replace(['/','\0'],"")};
            format_helpers.push(function_ident);
            unknowns += 1;
            unknowns_helper.push(quote! {::std::string::String,})
        }
    }
    if !path_args.is_empty() {
        path_code = quote_spanned! {function_span =>.get(format!(#format_string, server, #(#format_helpers),*))};
    }

    fn default_get_request(
        function_span: Span,
        path_code: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        quote_spanned! {function_span =>
            let resp = client
                #path_code
                .send();
        }
    }

    let request_body: proc_macro2::TokenStream = if let Some(ref security) = request.security {
        if let Some(security) = security.first() {
            if security.contains_key("accessToken") {
                quote_spanned! {function_span =>
                    let access_token = crate::access_token();
                    let resp = client
                        #path_code
                        .header("Authorization", format!("Bearer {}", access_token))
                        .send();
                }
            } else {
                default_get_request(function_span, path_code)
            }
        } else {
            default_get_request(function_span, path_code)
        }
    } else {
        default_get_request(function_span, path_code)
    };

    let possible_error_codes = get_error_codes_for_path(function_span, request);

    let function_params = if !unknowns_helper.is_empty() {
        quote! {fuzz_input: &(#(#unknowns_helper)*)}
    } else {
        quote! {_: &::std::vec::Vec<::std::primitive::u8>}
    };

    // Generate test code from here
    quote_spanned! { span=>
        fn #function_ident(#function_params) -> ::std::primitive::bool {
            let client = crate::client();
            let server = match ::std::env::var("MATRIX_SERVER") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
            };

            #request_body

            let allowed_codes = [
                #(#possible_error_codes)*
            ];

            if let ::std::option::Option::Ok(resp) = resp {
                let status = resp.status();
                if allowed_codes.contains(&status.as_u16()) {
                   return true;
                } else {
                    let content = resp.text();
                    if let ::std::option::Option::Ok(ref content) = content {
                        // TODO: use mapping file for errors to ignore
                        if content.contains("Unknown login type")
                            || content.contains("Invalid login submission")
                            || content.contains("Invalid username or password")
                            || content.contains("M_UNRECOGNIZED")
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
            let server = match ::std::env::var("MATRIX_SERVER") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
            };
            // Healthcheck for matrix servers
            let resp = client
                .get(format!("{}/_matrix/key/v2/server", server))
                .send()
                .unwrap();
            if !resp.status().is_success() {
                panic!("Failed to connect");
            }

            let result = ::fuzzcheck::fuzz_test(#function_ident)
                .default_options()
                .stop_after_first_test_failure(true)
                .launch();
            assert!(!result.found_test_failure);
        }
    }
}

fn generate_post_put_targets(
    span: Span,
    path: String,
    path_description: &PathItem,
    structs: &mut Vec<proc_macro2::TokenStream>,
    request: Operation,
    is_put: bool,
) -> proc_macro2::TokenStream {
    let function_path = request.operation_id.clone().unwrap();
    let function_ident = Ident::new(&function_path.to_case(Case::Snake), Span::call_site());
    let struct_ident_body = format_ident!(
        "{}",
        function_path.to_case(Case::UpperCamel),
        span = Span::mixed_site()
    );
    let mut value_insteadof_struct = false;
    let mut no_body = false;
    let struct_span = struct_ident_body.span();
    let fuzz_function_ident = format_ident!("fuzz_{}", function_ident);
    let function_span = function_ident.span();

    let mut struct_body = Vec::new();
    if let Some(ref request_body) = request.request_body {
        let obj = load_ref(request_body);
        if let Some(json_obj) = obj.content.get("application/json") {
            let schema = json_obj.schema.clone().expect("Missing schema for body");
            if let Some(properties_obj) = schema.object {
                let properties = properties_obj.properties;
                if !properties.is_empty() {
                    for (key, value) in properties.iter() {
                        let key_ident = format_ident!(
                            "{}",
                            key.replace('.', "_").to_case(Case::Snake),
                            span = Span::mixed_site()
                        );
                        if let Schema::Object(_type_definition) = value {
                            struct_body.push(quote_spanned! { struct_span =>
                                #key_ident: ::serde_json::Value
                            });
                        }
                    }

                    // Generate body struct
                    structs.push(quote_spanned! { span =>
                        #[derive(::std::fmt::Debug, ::std::clone::Clone, ::serde::Serialize, ::serde::Deserialize, ::fuzzcheck::DefaultMutator, ::arbitrary::Arbitrary)]
                        struct #struct_ident_body {
                            #(#struct_body),*
                        }
                    });
                } else {
                    value_insteadof_struct = true;
                }
            } else {
                value_insteadof_struct = true;
            }
        } else {
            // Mostly a placeholder
            structs.push(quote_spanned! { span =>
                #[derive(::std::fmt::Debug, ::std::clone::Clone, ::serde::Serialize, ::serde::Deserialize, ::fuzzcheck::DefaultMutator)]
                struct #struct_ident_body {
                }
            });
        }
    } else {
        no_body = true;
    }

    let path = path.trim();
    let mut path_code = if is_put {
        quote_spanned! {function_span =>.put(format!("{}{}", server, #path))}
    } else {
        quote_spanned! {function_span =>.post(format!("{}{}", server, #path))}
    };
    let path_args = extract_path_arguments(path);
    let mut format_string = format!("{{}}{path}");
    let mut format_helpers = Vec::new();
    let mut unknowns: usize = 0;
    let mut unknowns_helper = Vec::new();
    for arg in &path_args {
        let string_match = arg.as_str();
        format_string = format_string.replace(string_match, "{}");
        if string_match.contains("roomId") {
            let function_ident = quote! {crate::create_fresh_room()};
            format_helpers.push(function_ident);
        } else if string_match.contains("userId") {
            let function_ident = quote! {crate::own_user_id()};
            format_helpers.push(function_ident);
        } else {
            let i = syn::Index::from(1);
            let j = syn::Index::from(unknowns);
            // TODO: These are ones that are for sure wrong. We really need to see that we get instead random data from the fuzzer here.
            let function_ident =
                quote! {crate::truncate_string(&fuzz_input.#i.#j,255).replace(['/','\0'],"")};
            format_helpers.push(function_ident);
            unknowns += 1;
            unknowns_helper.push(quote! {::std::string::String,})
        }
    }
    if !path_args.is_empty() {
        path_code = if is_put {
            quote_spanned! {function_span =>.put(format!(#format_string, server, #(#format_helpers),*))}
        } else {
            quote_spanned! {function_span =>.post(format!(#format_string, server, #(#format_helpers),*))}
        };
    }

    fn default_post_request(
        function_span: Span,
        path_code: proc_macro2::TokenStream,
        no_body: bool,
    ) -> proc_macro2::TokenStream {
        if !no_body {
            quote_spanned! { function_span =>
                let resp = client
                    #path_code
                    .json(&json_data)
                    .send();
            }
        } else {
            quote_spanned! { function_span =>
                let resp = client
                    #path_code
                    .send();
            }
        }
    }

    let request_body = if let Some(ref security) = request.security {
        if let Some(security) = security.first() {
            if security.contains_key("accessToken") {
                if !no_body {
                    quote_spanned! { function_span =>
                        let access_token = crate::access_token();
                        let resp = client
                            #path_code
                            .header("Authorization", format!("Bearer {}", access_token))
                            .json(&json_data)
                            .send();
                    }
                } else {
                    quote_spanned! { function_span =>
                        let access_token = crate::access_token();
                        let resp = client
                            #path_code
                            .header("Authorization", format!("Bearer {}", access_token))
                            .send();
                    }
                }
            } else {
                default_post_request(function_span, path_code, no_body)
            }
        } else {
            default_post_request(function_span, path_code, no_body)
        }
    } else {
        default_post_request(function_span, path_code, no_body)
    };

    let possible_error_codes = get_error_codes_for_path(function_span, request);

    let i = syn::Index::from(0);
    let json_data_loder = if value_insteadof_struct {
        quote! {
            let mut json_data = fuzz_input.#i.clone();
            // TODO: we really shouldnt do this since this leads to badly generated json
            if !json_data.is_object() {
                return true;
            }
        }
    } else if !no_body {
        quote! {
            let mut json_data = fuzz_input.#i.clone();
        }
    } else {
        quote! {}
    };
    let function_body = quote_spanned! { function_span =>
        #json_data_loder

        // TODO: iterate over the fields and automatically remove faulty characters
        // if let Some(user) = &json_data.user {
        //     if user.contains('\0') {
        //         json_data.user = Some(user.replace('\0', ""));
        //     }
        // }

        let client = crate::client();
        let server = match ::std::env::var("MATRIX_SERVER") {
            ::std::option::Option::Ok(v) => v,
            ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
        };

        #request_body

        let allowed_codes = [
            #(#possible_error_codes)*
        ];

        if let ::std::option::Option::Ok(resp) = resp {
            let status = resp.status();
            if allowed_codes.contains(&status.as_u16()) {
                return true;
            } else {
                let content = resp.text();
                if let ::std::option::Option::Ok(ref content) = content {
                    // TODO: use mapping file for errors to ignore
                    if content.contains("Unknown login type")
                        || content.contains("Invalid login submission")
                        || content.contains("Invalid username or password")
                        || content.contains("M_UNRECOGNIZED")
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

    let input = if value_insteadof_struct {
        quote! {::serde_json::Value,}
    } else if no_body {
        quote! {}
    } else {
        quote! {crate::#struct_ident_body,}
    };

    let function_params = if !unknowns_helper.is_empty() {
        quote! {fuzz_input: &(#input (#(#unknowns_helper)*),)}
    } else if no_body {
        quote! {fuzz_input: &()}
    } else {
        quote! {fuzz_input: &(#input)}
    };

    let main_function = if let Some(description) = &path_description.description {
        let description_literal = LitStr::new(description, Span::mixed_site());
        quote_spanned! { span =>
            #[doc = #description_literal]
            fn #function_ident(#function_params) -> ::std::primitive::bool {
                #function_body
            }
        }
    } else {
        quote_spanned! { span =>
            fn #function_ident(#function_params) -> ::std::primitive::bool {
                #function_body
            }
        }
    };

    // Generate test code from here
    quote_spanned! { span =>
        #main_function

        #[test]
        fn #fuzz_function_ident() {
            let client = crate::client();
            let server = match ::std::env::var("MATRIX_SERVER") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
            };
            // Healthcheck for matrix servers
            let resp = client
                .get(format!("{}/_matrix/key/v2/server", server))
                .send()
                .unwrap();
            if !resp.status().is_success() {
                panic!("Failed to connect");
            }

            let result = ::fuzzcheck::fuzz_test(#function_ident)
                .default_options()
                .stop_after_first_test_failure(true)
                .launch();
            assert!(!result.found_test_failure);
        }
    }
}

fn generate_target(
    tests: &mut Vec<proc_macro2::TokenStream>,
    structs: &mut Vec<proc_macro2::TokenStream>,
    path: String,
    path_description: &PathItem,
    span: Span,
) {
    if let Some(request) = &path_description.get {
        tests.push(generate_get_targets(span, path, request.clone()));
    } else if let Some(request) = &path_description.post {
        tests.push(generate_post_put_targets(
            span,
            path,
            path_description,
            structs,
            request.clone(),
            false,
        ));
    } else if let Some(request) = &path_description.put {
        tests.push(generate_post_put_targets(
            span,
            path,
            path_description,
            structs,
            request.clone(),
            true,
        ));
    }
}

fn base_structure(
    tests: Vec<proc_macro2::TokenStream>,
    structs: Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    quote! {
        #[doc(hidden)]
        pub use ::core;
        #[doc(hidden)]
        pub use ::core::alloc;

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize)]
        struct LoginGet {
            pub flows: ::std::vec::Vec<self::Flow>,
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

        fn truncate_string(s: &::std::primitive::str, max_len: ::std::primitive::usize) -> &::std::primitive::str {
            if max_len >= s.len() {
                return s;
            }
            let mut idx = max_len;
            while !s.is_char_boundary(idx) {
                idx -= 1;
            }
            &s[..idx]
        }

        #[coverage(off)]
        fn login() -> ::std::string::String {
            let server = match ::std::env::var("MATRIX_SERVER") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
            };
            let username = match ::std::env::var("MATRIX_USERNAME") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(e) => panic!("$MATRIX_USERNAME is not set ({})", e),
            };
            let password = match ::std::env::var("MATRIX_PASSWORD") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(e) => panic!("$MATRIX_PASSWORD is not set ({})", e),
            };
            let client = crate::client();
            let res: self::LoginGet = client
                .get(format!("{}/_matrix/client/v3/login", server))
                .send()
                .unwrap()
                .json()
                .unwrap();
            assert!(res.flows.contains(&self::Flow {
                type_: "m.login.password".to_string(),
            }));

            let mut map = ::std::collections::HashMap::new();
            map.insert("type", "m.login.password");
            map.insert("user", &username);
            map.insert("password", &password);
            let res: self::LoginPost = client
                .post(format!("{}/_matrix/client/v3/login", server))
                .json(&map)
                .send()
                .unwrap()
                .json()
                .unwrap();

            res.access_token
        }

        #[coverage(off)]
        fn access_token() -> &'static ::std::string::String {
            static INSTANCE: ::once_cell::sync::OnceCell<::std::string::String> = ::once_cell::sync::OnceCell::new();
            INSTANCE.get_or_init(login)
        }

        #[coverage(off)]
        fn client() -> &'static ::reqwest::blocking::Client {
            static INSTANCE: ::once_cell::sync::OnceCell<::reqwest::blocking::Client> = ::once_cell::sync::OnceCell::new();
            INSTANCE.get_or_init(|| {
                ::reqwest::blocking::Client::builder()
                    .connect_timeout(Some(::std::time::Duration::from_secs(30)))
                    .user_agent("synapse-fuzzer")
                    .gzip(true)
                    .build()
                    .unwrap()
            })
        }

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize)]
        struct RoomCreateHelperBody {
            pub preset: ::std::string::String,
        }

        #[derive(::std::fmt::Debug, serde::Serialize, serde::Deserialize)]
        struct RoomCreateHelperResp {
            pub room_id: ::std::string::String,
        }


        fn own_user_id() -> ::std::string::String {
            match ::std::env::var("MATRIX_USERNAME") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(e) => panic!("$MATRIX_USERNAME is not set ({})", e),
            }
        }

        fn create_fresh_room() -> ::std::string::String {
            let client = crate::client();
            let server = match ::std::env::var("MATRIX_SERVER") {
                ::std::option::Option::Ok(v) => v,
                ::std::option::Option::Err(_) => "http://localhost:8008".to_string(),
            };

            let data = self::RoomCreateHelperBody {
                preset: ::std::string::String::from("private_chat")
            };

            let access_token = crate::access_token();
            let resp: self::RoomCreateHelperResp = client
                .post(format!("{}/_matrix/client/v3/createRoom", server))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&data)
                .send()
                .unwrap()
                .json()
                .unwrap();
            resp.room_id
        }

        #(#structs)*

        #[cfg(test)]
        mod tests {
            #(#tests)*
        }
    }
}

#[proc_macro]
pub fn generate_fuzz_targets(input: TokenStream) -> TokenStream {
    let spec_url_ident = parse_macro_input!(input as LitStr);
    let spec_url = spec_url_ident.value();
    let span = spec_url_ident.span();

    let mut structs = Vec::new();
    let mut tests = Vec::new();

    let parsed: OpenApi = reqwest::blocking::get(spec_url)
        .expect("Unable to get spec api")
        .json()
        .expect("Unable to parse spec as openapi json");
    for (path, ref path_description) in parsed.paths {
        generate_target(&mut tests, &mut structs, path, path_description, span);
    }

    let expanded = base_structure(tests, structs);

    TokenStream::from(expanded)
}
