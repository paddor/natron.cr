module Natron
  module Random
    def self.random_bytes(n : Int) : Bytes
      buf = Bytes.new(n)
      LibSodium.randombytes_buf(buf.to_unsafe, buf.size)
      buf
    end
  end
end
