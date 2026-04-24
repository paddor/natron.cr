require "../test_helper"

describe Natron::Util do
  it "verify16 passes on equal 16-byte inputs" do
    a = Bytes.new(16) { |i| i.to_u8 }
    b = Bytes.new(16) { |i| i.to_u8 }
    assert Natron::Util.verify16(a, b)
  end


  it "verify16 fails on single-byte diff" do
    a = Bytes.new(16) { |i| i.to_u8 }
    b = Bytes.new(16) { |i| i.to_u8 }
    b[5] ^= 0x01_u8
    refute Natron::Util.verify16(a, b)
  end


  it "returns false on wrong length" do
    refute Natron::Util.verify16(Bytes.new(15), Bytes.new(16))
    refute Natron::Util.verify32(Bytes.new(32), Bytes.new(31))
  end
end
