module Natron
  module Internals
    # Salsa20 family via libsodium: HSalsa20, Salsa20, XSalsa20.
    module Salsa20
      SIGMA = "expand 32-byte k".to_slice


      # HSalsa20 KDF: 32-byte key + 16-byte nonce → 32-byte subkey.
      def self.hsalsa20(key : Bytes, nonce : Bytes) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 16 bytes") unless nonce.size == 16
        buf = Bytes.new(32)
        LibSodium.crypto_core_hsalsa20(buf.to_unsafe, nonce.to_unsafe, key.to_unsafe, SIGMA.to_unsafe)
        buf
      end


      # Salsa20 stream XOR (32-byte key, 8-byte nonce).
      def self.salsa20_xor(key : Bytes, nonce : Bytes, message : Bytes) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 8 bytes") unless nonce.size == 8
        buf = Bytes.new(message.size)
        LibSodium.crypto_stream_salsa20_xor(
          buf.to_unsafe, message.to_unsafe, message.size.to_u64,
          nonce.to_unsafe, key.to_unsafe)
        buf
      end


      # XSalsa20 stream XOR (32-byte key, 24-byte nonce).
      def self.xsalsa20_xor(key : Bytes, nonce : Bytes, message : Bytes) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 24 bytes") unless nonce.size == 24
        buf = Bytes.new(message.size)
        LibSodium.crypto_stream_xsalsa20_xor(
          buf.to_unsafe, message.to_unsafe, message.size.to_u64,
          nonce.to_unsafe, key.to_unsafe)
        buf
      end


      # XSalsa20 keystream (zeros XOR'd, so just the keystream bytes).
      def self.xsalsa20_stream(key : Bytes, nonce : Bytes, length : Int) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 24 bytes") unless nonce.size == 24
        buf = Bytes.new(length)
        LibSodium.crypto_stream_xsalsa20(
          buf.to_unsafe, length.to_u64, nonce.to_unsafe, key.to_unsafe)
        buf
      end
    end
  end
end
