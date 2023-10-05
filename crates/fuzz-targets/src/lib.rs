#![feature(type_alias_impl_trait)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]
#![feature(impl_trait_in_assoc_type)]
#![feature(coverage_attribute)]
#![warn(clippy::missing_const_for_fn)]

use codegen::generate_fuzz_targets;

generate_fuzz_targets!("https://spec.matrix.org/v1.8/client-server-api/api.json");
