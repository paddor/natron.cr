module Natron
  class PublicKey
    BYTES = 32

    getter bytes : Bytes


    def initialize(key : Bytes)
      raise ArgumentError.new("public key must be #{BYTES} bytes (got #{key.size})") unless key.size == BYTES
      @bytes = key.dup
    end


    def to_slice : Bytes
      @bytes
    end


    def ==(other : PublicKey) : Bool
      Util.verify32(@bytes, other.bytes)
    end


    def ==(other) : Bool
      false
    end
  end
end
