# husk
Minimal TLS 1.2 implimentation in **100% pure** Rust.

**IT'S NOT SECURE NOW!**

Authentication can't works at all, although you can establish connection, you can't confirm remote identity.

Don't use it in real world.

## Roadmap

### Cipher suites support

- [ ] TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
- [ ] TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
- [ ] TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
- [ ] TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)

**Notes:** All legacy suites won't be supported.

e.g. LEGACY_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcc15)

### Curve support

- [x] P-256 = secp256r1 (0x0017)

### Signature support

- [ ] rsa_pkcs1_sha256 (0x0401)
- [ ] ecdsa_secp256r1_sha256 (0x0403)

## Thanks

[suruga](https://github.com/klutzy/suruga) TLS 1.2 implementation in Rust