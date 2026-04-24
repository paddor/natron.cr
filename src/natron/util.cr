module Natron
  module Util
    def self.verify16(a : Bytes, b : Bytes) : Bool
      verify(a, b, 16)
    end


    def self.verify32(a : Bytes, b : Bytes) : Bool
      verify(a, b, 32)
    end


    def self.verify64(a : Bytes, b : Bytes) : Bool
      verify(a, b, 64)
    end


    def self.verify(a : Bytes, b : Bytes, expected_size : Int32? = nil) : Bool
      if exp = expected_size
        return false unless a.size == exp && b.size == exp
      else
        return false unless a.size == b.size
      end
      LibSodium.sodium_memcmp(a.to_unsafe, b.to_unsafe, a.size) == 0
    end
  end
end
