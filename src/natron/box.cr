module Natron
  # Public-key authenticated encryption: Curve25519-XSalsa20-Poly1305.
  #
  # Precomputes the `beforenm` shared key at construction so repeated
  # encrypt/decrypt calls with the same peer only cost one HSalsa20 + XSalsa20-Poly1305.
  class Box
    NONCEBYTES      = 24
    PUBLICKEYBYTES  = 32
    PRIVATEKEYBYTES = 32
    BEFORENMBYTES   = 32
    MACBYTES        = 16

    @shared : Bytes


    def initialize(public_key, private_key)
      pk = coerce(public_key, PUBLICKEYBYTES, "public key")
      sk = coerce(private_key, PRIVATEKEYBYTES, "private key")

      @shared = Bytes.new(BEFORENMBYTES)
      if LibSodium.crypto_box_beforenm(@shared.to_unsafe, pk.to_unsafe, sk.to_unsafe) != 0
        raise CryptoError.new("crypto_box_beforenm failed")
      end
    end


    def nonce_bytes : Int32
      NONCEBYTES
    end


    def encrypt(nonce : Bytes, plaintext : Bytes) : Bytes
      raise ArgumentError.new("nonce must be #{NONCEBYTES} bytes") unless nonce.size == NONCEBYTES
      buf = Bytes.new(plaintext.size + MACBYTES)
      rc = LibSodium.crypto_box_easy_afternm(
        buf.to_unsafe, plaintext.to_unsafe, plaintext.size.to_u64,
        nonce.to_unsafe, @shared.to_unsafe)
      raise CryptoError.new("encryption failed") if rc != 0
      buf
    end


    def decrypt(nonce : Bytes, ciphertext : Bytes) : Bytes
      raise ArgumentError.new("nonce must be #{NONCEBYTES} bytes") unless nonce.size == NONCEBYTES
      raise CryptoError.new("ciphertext too short") if ciphertext.size < MACBYTES
      buf = Bytes.new(ciphertext.size - MACBYTES)
      rc = LibSodium.crypto_box_open_easy_afternm(
        buf.to_unsafe, ciphertext.to_unsafe, ciphertext.size.to_u64,
        nonce.to_unsafe, @shared.to_unsafe)
      raise CryptoError.new("decryption failed") if rc != 0
      buf
    end


    def box(nonce : Bytes, plaintext : Bytes) : Bytes
      encrypt(nonce, plaintext)
    end


    def open(nonce : Bytes, ciphertext : Bytes) : Bytes
      decrypt(nonce, ciphertext)
    end


    private def coerce(key, expected_size : Int32, name : String) : Bytes
      bytes = case key
              when PublicKey  then key.bytes
              when PrivateKey then key.bytes
              when Bytes      then key
              else raise ArgumentError.new("#{name} must be a PublicKey/PrivateKey or Bytes")
              end
      raise ArgumentError.new("#{name} must be #{expected_size} bytes (got #{bytes.size})") unless bytes.size == expected_size
      bytes
    end
  end
end
