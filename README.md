# Matrix Fuzzing

Matrix fuzzing is a dumb fuzzer fuzzing a few matrix endpoints. It requires a HS and a user to exist.

# Current targets

- `/_matrix/client/v3/createRoom` - `tests::tests::fuzz_create_room`

# Usage

1. Create a HS
1. Setup a user
1. Add the secrets to src/secrets.rs.

   Example code:

   ```rust
   pub const USERNAME: &str = "@a:localhost";
   pub const PASSWORD: &str = "abc123";
   ```

1. Install fuzzcheck -> https://github.com/loiclec/fuzzcheck-rs#setup
1. Run `cargo fuzzcheck <target>`
1. Wait until it crashes
1. Verify the error by trying the output json yourself
1. Report a bug if it is a non security issue or write an email if it might be. Take a look at your synapse logs as well.

# Hall of Explosions (Bugs found)

- https://github.com/matrix-org/synapse/issues/13510
- https://github.com/matrix-org/synapse/issues/13511
- https://github.com/matrix-org/synapse/issues/13512