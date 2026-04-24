module Natron
  module Internals
    # ChaCha20 (DJB 8-byte nonce variant) via libsodium.
    module ChaCha20
      # XOR message with ChaCha20 keystream. Note: libsodium's
      # `crypto_stream_chacha20_xor` does NOT support a non-zero starting
      # counter — if you need one, use `_xor_ic` (not currently bound).
      def self.xor(key : Bytes, nonce : Bytes, message : Bytes) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 8 bytes") unless nonce.size == 8
        buf = Bytes.new(message.size)
        LibSodium.crypto_stream_chacha20_xor(
          buf.to_unsafe, message.to_unsafe, message.size.to_u64,
          nonce.to_unsafe, key.to_unsafe)
        buf
      end


      def self.stream(key : Bytes, nonce : Bytes, length : Int) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        raise ArgumentError.new("nonce must be 8 bytes") unless nonce.size == 8
        buf = Bytes.new(length)
        LibSodium.crypto_stream_chacha20(
          buf.to_unsafe, length.to_u64, nonce.to_unsafe, key.to_unsafe)
        buf
      end
    end
  end
end
