# Natron

Crystal binding to [libsodium](https://libsodium.org). The production
crypto backend for [omq.cr](../omq.cr); also the reference against which
[nuckle.cr](../nuckle.cr) benchmarks itself.

## Installation

Add to `shard.yml`:

```yaml
dependencies:
  natron:
    github: paddor/natron.cr
```

Requires libsodium ≥ 1.0.18 installed system-wide (`apt install libsodium-dev`,
`brew install libsodium`, etc.). `sodium_init` is called automatically
at load time.

## Usage

API mirrors [nuckle.cr](../nuckle.cr) exactly — swap the module name and
you're done.

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

BLAKE3 and ChaCha20-BLAKE3 AEAD — libsodium doesn't ship either. Use
`nuckle.cr` or a dedicated BLAKE3 binding for those.

## License

ISC
