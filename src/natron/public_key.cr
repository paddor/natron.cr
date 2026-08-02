module Natron
  class PublicKey
    BYTES = 32

    @bytes : Bytes

    def initialize(key : Bytes)
      raise ArgumentError.new("public key must be #{BYTES} bytes (got #{key.size})") unless key.size == BYTES
      @bytes = key.dup
    end

    def bytes : Bytes
      @bytes.dup
    end

    def to_slice : Bytes
      bytes
    end

    def ==(other : PublicKey) : Bool
      Util.verify32(@bytes, other.to_slice)
    end

    def ==(other) : Bool
      false
    end
  end
end
