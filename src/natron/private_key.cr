module Natron
  class PrivateKey
    BYTES = 32

    @bytes : Bytes

    def self.generate : PrivateKey
      new(Random.random_bytes(BYTES))
    end

    def initialize(key : Bytes)
      raise ArgumentError.new("private key must be #{BYTES} bytes (got #{key.size})") unless key.size == BYTES
      @bytes = key.dup
    end

    def bytes : Bytes
      @bytes.dup
    end

    # Derive the corresponding public key via Curve25519 scalar base multiplication.
    def public_key : PublicKey
      buf = Bytes.new(BYTES)
      Sodium.check(
        LibSodium.crypto_scalarmult_curve25519_base(buf.to_unsafe, @bytes.to_unsafe),
        "scalarmult_base"
      )
      PublicKey.new(buf)
    end

    # Raw X25519 Diffie-Hellman shared secret. No HSalsa20 KDF applied.
    # Callers must derive symmetric keys from the result themselves.
    def diffie_hellman(peer : PublicKey) : Bytes
      diffie_hellman(peer.bytes)
    end

    def diffie_hellman(peer : Bytes) : Bytes
      raise ArgumentError.new("peer public key must be #{BYTES} bytes") unless peer.size == BYTES
      buf = Bytes.new(BYTES)
      Sodium.check(
        LibSodium.crypto_scalarmult_curve25519(buf.to_unsafe, @bytes.to_unsafe, peer.to_unsafe),
        "scalarmult"
      )
      buf
    end

    def to_slice : Bytes
      bytes
    end

    def wipe : Nil
      LibSodium.sodium_memzero(@bytes.to_unsafe, @bytes.size)
    end

    def finalize
      wipe
    end
  end
end
