require "../test_helper"

describe Natron::Box do
  it "roundtrips between two keypairs" do
    alice = Natron::PrivateKey.generate
    bob   = Natron::PrivateKey.generate
    nonce = Natron::Random.random_bytes(24)

    a_box = Natron::Box.new(bob.public_key, alice)
    b_box = Natron::Box.new(alice.public_key, bob)

    pt = "hello".to_slice
    ct = a_box.encrypt(nonce, pt)

    recovered = b_box.decrypt(nonce, ct)
    assert_equal String.new(pt), String.new(recovered)
  end


  it "fails on mismatched keypair" do
    alice = Natron::PrivateKey.generate
    bob   = Natron::PrivateKey.generate
    eve   = Natron::PrivateKey.generate
    nonce = Natron::Random.random_bytes(24)

    a_box = Natron::Box.new(bob.public_key, alice)
    e_box = Natron::Box.new(alice.public_key, eve)
    ct    = a_box.encrypt(nonce, "secret".to_slice)

    assert_raises(Natron::CryptoError) { e_box.decrypt(nonce, ct) }
  end
end
