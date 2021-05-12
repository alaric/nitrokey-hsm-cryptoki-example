# Example Usage of Nitrokey HSM with Cryptoki Rust Crate

This repository provides a simple example of using the [cryptoki](https://docs.rs/cryptoki/) crate
to extract the public key for an encryption, then decrypt using the [Nitrokey
HSM](https://www.nitrokey.com).

This assumes you've initialized the Nitrokey HSM already, and have [keys
generated](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#generate-key-pair) according to the intstructions. Once that's done you should be able to run in somewhat similarly to, with parameters altered as necessary:

```
cargo run -- --module /usr/lib/opensc-pkcs11.so --pin 123456 --slot 0 --id 10
```

I also documented a couple of the quirks [on this blog
post](https://doublethink.co.uk/getting-started-rust-nitrokey/).
