# ripemd160_cairo

## About

Cairo 1.0 library for hashing with RIPEMD-160.

## Usage

In your Scarb.toml :
```toml
[dependencies]
ripemd160 = { git = "https://github.com/j1mbo64/ripemd160_cairo.git" }
```

In a .cairo file :
```rust
    // Import the module
    use ripemd160::{RIPEMD160Context, ripemd160_hash, ripemd160_context_as_array};

    fn hash_something() {

        // Message to hash
        let message: ByteArray = "My string to hash";

        // Hash and return the hashed message in a struct
        let context: RIPEMD160Context = ripemd160_hash(@message);

        // Get your hash in a ByteArray
        let hash_bytes: ByteArray = context.into();

        // Get your hash in an u256
        let hash_u256: u256 = ripemd160_hash(@message).into();

        // Get your hash via function (_as_bytes and _as_u256 also working)
        let hash_array: Array<u32> = ripemd160_context_as_array(@context);
```

## Contributing

Tips for gas optimization are welcome.

### Rules for submitting a PR :
  - Follow [Conventionnal Commits](https://www.conventionalcommits.org) rules
  - Ensure all tests pass with `scarb test`
  - Format the code with `scarb fmt`
