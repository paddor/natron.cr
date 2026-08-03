# Natron

Crystal binding to [libsodium](https://libsodium.org). Natron wraps a small
NaCl-compatible surface: Curve25519, XSalsa20-Poly1305, raw Salsa20/ChaCha20
streams, Poly1305, and constant-time byte verification.

## Installation

Add to `shard.yml`:

```yaml
dependencies:
  natron:
    github: paddor/natron.cr
```

Requires libsodium >= 1.0.18 installed system-wide (`apt install libsodium-dev`,
`brew install libsodium`, etc.). `sodium_init` is called automatically
at load time.

## Usage

API mirrors the pure Crystal [Nuckle](https://github.com/paddor/nuckle.cr)
shard for the shared primitives.

```crystal
require "natron"

# Keypair generation
sk = Natron::PrivateKey.generate
pk = sk.public_key

# Public-key authenticated encryption
alice = Natron::PrivateKey.generate
bob   = Natron::PrivateKey.generate
nonce = Natron::Random.random_bytes(24)

box = Natron::Box.new(bob.public_key, alice)
ciphertext = box.encrypt(nonce, "hello".to_slice)

box2 = Natron::Box.new(alice.public_key, bob)
plaintext = box2.decrypt(nonce, ciphertext)
# => "hello"

# Symmetric authenticated encryption
key   = Natron::Random.random_bytes(32)
nonce = Natron::Random.random_bytes(24)
box   = Natron::SecretBox.new(key)

ciphertext = box.encrypt(nonce, "hello".to_slice)
plaintext  = box.decrypt(nonce, ciphertext)
```

Never reuse a nonce with the same key. `Natron::Random.random_bytes(24)` is
the safest default for `Box` and `SecretBox` nonces.

## Primitives

| Primitive | libsodium function |
|---|---|
| `Natron::SecretBox` | `crypto_secretbox_easy` / `_open_easy` |
| `Natron::Box` | `crypto_box_easy` / `_open_easy` (after `beforenm`) |
| `Natron::PrivateKey.generate` | `randombytes_buf` + scalar clamp |
| `PrivateKey#public_key` | `crypto_scalarmult_curve25519_base` |
| `PrivateKey#diffie_hellman` | `crypto_scalarmult_curve25519` |
| `Natron::Internals::Salsa20` | `crypto_core_hsalsa20`, `crypto_stream_xsalsa20_xor` |
| `Natron::Internals::ChaCha20` | `crypto_stream_chacha20_xor` |
| `Natron::Internals::Poly1305` | `crypto_onetimeauth_poly1305` |
| `Natron::Random` | `randombytes_buf` |
| `Natron::Util.verify{16,32,64}` | `sodium_memcmp` |

## Not included

BLAKE3 and ChaCha20-BLAKE3 AEAD are not included. Libsodium does not ship
either. Use [Nuckle](https://github.com/paddor/nuckle.cr) or a dedicated
BLAKE3 binding for those.

## License

ISC
