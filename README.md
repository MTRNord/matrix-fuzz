# Matrix Fuzzing

Matrix fuzzing is a dumb fuzzer fuzzing a few matrix endpoints. It requires a HS and a user to exist.

# Project room

[#matrix-fuzz:midnightthoughts.space](https://matrix.to/#/#matrix-fuzz:midnightthoughts.space)

# Current targets

- `/_matrix/client/v3/createRoom` - `tests::tests::fuzz_create_room` - `createRoom`

# Usage of fuzzcheck-rs

1. Create a HS
2. Setup a user
3. Set `MATRIX_USERNAME` and `MATRIX_PASSWORD` to the username and password of the user you want to fuzz as.
4. Install fuzzcheck -> https://github.com/loiclec/fuzzcheck-rs#setup
5. Run `cargo fuzzcheck <target>`
6. Wait until it crashes
7. Verify the error by trying the output json yourself
8. Please make sure to follow https://matrix.org/security-disclosure-policy/ for found errors instead of posting them in public unless you are 100% sure they are not a security issue. If you are in doubt prefer the security disclosure policy.

# Usage of afl.rs

1. Create a HS
1. Setup a user
2. Install afl.rs -> `cargo install afl`
3. Run `cargo afl build`
4. Set `MATRIX_USERNAME` and `MATRIX_PASSWORD` to the username and password of the user you want to fuzz as.
5. Run `cargo afl fuzz -i ./afl/<target>/in -o ./afl/<target>/out ./target/debug/<target>`
6. Wait until it crashes
7. Verification is a little harder. See https://github.com/rust-fuzz/afl.rs/issues/215 on how to reproduce things
8. Please make sure to follow https://matrix.org/security-disclosure-policy/ for found errors instead of posting them in public unless you are 100% sure they are not a security issue. If you are in doubt prefer the security disclosure policy.

# Hall of Explosions (Bugs found)

- https://github.com/matrix-org/synapse/issues/13510
- https://github.com/matrix-org/synapse/issues/13511
- https://github.com/matrix-org/synapse/issues/13512
- https://github.com/matrix-org/synapse/issues/13664

# Known bugs in the fuzzer

The fuzzer generates arbitrary json objects currently very poorly. Resulting in a lot less cases than it should. Its a workaround for now until there is a nicer way.