require "../test_helper"

describe Natron::PrivateKey do
  it "generates 32-byte keys" do
    sk = Natron::PrivateKey.generate
    assert_equal 32, sk.bytes.size
  end


  it "derives a public key" do
    sk = Natron::PrivateKey.generate
    pk = sk.public_key
    assert_equal 32, pk.bytes.size
  end


  it "is deterministic: same scalar → same public key" do
    sk = Natron::PrivateKey.generate
    pk1 = sk.public_key
    pk2 = Natron::PrivateKey.new(sk.bytes).public_key
    assert pk1 == pk2
  end


  it "Diffie-Hellman: both sides derive the same shared secret" do
    alice = Natron::PrivateKey.generate
    bob   = Natron::PrivateKey.generate
    s1 = alice.diffie_hellman(bob.public_key)
    s2 = bob.diffie_hellman(alice.public_key)
    assert_equal s1.to_a, s2.to_a
  end


  it "rejects wrong-length keys" do
    assert_raises(ArgumentError) { Natron::PrivateKey.new(Bytes.new(31)) }
    assert_raises(ArgumentError) { Natron::PublicKey.new(Bytes.new(33)) }
  end
end


describe Natron::PublicKey do
  it "compares equal when bytes match" do
    bytes = Natron::Random.random_bytes(32)
    assert Natron::PublicKey.new(bytes) == Natron::PublicKey.new(bytes)
  end


  it "compares unequal when bytes differ" do
    refute Natron::PublicKey.new(Natron::Random.random_bytes(32)) ==
           Natron::PublicKey.new(Natron::Random.random_bytes(32))
  end
end
