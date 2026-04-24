require "./natron/version"
require "./natron/errors"
require "./natron/lib_sodium"
require "./natron/random"
require "./natron/util"
require "./natron/public_key"
require "./natron/private_key"
require "./natron/secret_box"
require "./natron/box"
require "./natron/internals/salsa20"
require "./natron/internals/chacha20"
require "./natron/internals/poly1305"
require "./natron/internals/curve25519"

# Crystal binding to libsodium. Drop-in API-compatible with the pure-Crystal
# `nuckle` shard: swap `Nuckle::` for `Natron::` and it Just Works.
module Natron
end
