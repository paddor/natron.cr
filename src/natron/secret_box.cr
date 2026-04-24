module Natron
  # Symmetric authenticated encryption: XSalsa20-Poly1305.
  #
  # Wire-compatible with libsodium's `crypto_secretbox_easy` and with
  # Nuckle::SecretBox.
  class SecretBox
    KEYBYTES   = 32
    NONCEBYTES = 24
    MACBYTES   = 16

    @key : Bytes


    def initialize(key : Bytes)
      raise ArgumentError.new("key must be #{KEYBYTES} bytes (got #{key.size})") unless key.size == KEYBYTES
      @key = key.dup
    end


    def nonce_bytes : Int32
      NONCEBYTES
    end


    def key_bytes : Int32
      KEYBYTES
    end


    # Returns MAC(16) || ciphertext.
    def encrypt(nonce : Bytes, plaintext : Bytes) : Bytes
      raise ArgumentError.new("nonce must be #{NONCEBYTES} bytes") unless nonce.size == NONCEBYTES
      buf = Bytes.new(plaintext.size + MACBYTES)
      rc = LibSodium.crypto_secretbox_easy(
        buf.to_unsafe, plaintext.to_unsafe, plaintext.size.to_u64,
        nonce.to_unsafe, @key.to_unsafe)
      raise CryptoError.new("encryption failed") if rc != 0
      buf
    end


    def decrypt(nonce : Bytes, ciphertext : Bytes) : Bytes
      raise ArgumentError.new("nonce must be #{NONCEBYTES} bytes") unless nonce.size == NONCEBYTES
      raise CryptoError.new("ciphertext too short") if ciphertext.size < MACBYTES
      buf = Bytes.new(ciphertext.size - MACBYTES)
      rc = LibSodium.crypto_secretbox_open_easy(
        buf.to_unsafe, ciphertext.to_unsafe, ciphertext.size.to_u64,
        nonce.to_unsafe, @key.to_unsafe)
      raise CryptoError.new("decryption failed") if rc != 0
      buf
    end


    def box(nonce : Bytes, plaintext : Bytes) : Bytes
      encrypt(nonce, plaintext)
    end


    def open(nonce : Bytes, ciphertext : Bytes) : Bytes
      decrypt(nonce, ciphertext)
    end
  end
end
