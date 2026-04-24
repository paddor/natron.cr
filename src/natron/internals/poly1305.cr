module Natron
  module Internals
    module Poly1305
      # Compute Poly1305 MAC using the given 32-byte one-time key.
      def self.mac(key : Bytes, message : Bytes) : Bytes
        raise ArgumentError.new("key must be 32 bytes") unless key.size == 32
        tag = Bytes.new(16)
        LibSodium.crypto_onetimeauth_poly1305(
          tag.to_unsafe, message.to_unsafe, message.size.to_u64, key.to_unsafe)
        tag
      end
    end
  end
end
