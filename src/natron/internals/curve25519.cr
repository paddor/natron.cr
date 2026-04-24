module Natron
  module Internals
    module Curve25519
      BYTES       = 32
      SCALARBYTES = 32


      def self.scalarmult(scalar : Bytes, u : Bytes) : Bytes
        raise ArgumentError.new("scalar must be 32 bytes") unless scalar.size == 32
        raise ArgumentError.new("u must be 32 bytes") unless u.size == 32
        buf = Bytes.new(BYTES)
        if LibSodium.crypto_scalarmult_curve25519(buf.to_unsafe, scalar.to_unsafe, u.to_unsafe) != 0
          raise CryptoError.new("scalarmult failed (low-order point?)")
        end
        buf
      end


      def self.scalarmult_base(scalar : Bytes) : Bytes
        raise ArgumentError.new("scalar must be 32 bytes") unless scalar.size == 32
        buf = Bytes.new(BYTES)
        if LibSodium.crypto_scalarmult_curve25519_base(buf.to_unsafe, scalar.to_unsafe) != 0
          raise CryptoError.new("scalarmult_base failed")
        end
        buf
      end
    end
  end
end
