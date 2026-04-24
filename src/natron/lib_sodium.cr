module Natron
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init : LibC::Int
    fun sodium_memcmp(b1 : UInt8*, b2 : UInt8*, len : LibC::SizeT) : LibC::Int
    fun sodium_memzero(pnt : Void*, len : LibC::SizeT) : Void

    fun randombytes_buf(buf : UInt8*, size : LibC::SizeT) : Void

    # Curve25519 scalar multiplication
    CRYPTO_SCALARMULT_CURVE25519_BYTES        =  32
    CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES  =  32

    fun crypto_scalarmult_curve25519(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
    fun crypto_scalarmult_curve25519_base(q : UInt8*, n : UInt8*) : LibC::Int

    # SecretBox (XSalsa20-Poly1305)
    CRYPTO_SECRETBOX_KEYBYTES    = 32
    CRYPTO_SECRETBOX_NONCEBYTES  = 24
    CRYPTO_SECRETBOX_MACBYTES    = 16

    fun crypto_secretbox_easy(c : UInt8*, m : UInt8*, mlen : UInt64,
                              n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_secretbox_open_easy(m : UInt8*, c : UInt8*, clen : UInt64,
                                   n : UInt8*, k : UInt8*) : LibC::Int

    # Box (Curve25519-XSalsa20-Poly1305)
    CRYPTO_BOX_PUBLICKEYBYTES = 32
    CRYPTO_BOX_SECRETKEYBYTES = 32
    CRYPTO_BOX_NONCEBYTES     = 24
    CRYPTO_BOX_MACBYTES       = 16
    CRYPTO_BOX_BEFORENMBYTES  = 32

    fun crypto_box_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_box_easy(c : UInt8*, m : UInt8*, mlen : UInt64,
                        n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_box_open_easy(m : UInt8*, c : UInt8*, clen : UInt64,
                             n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_box_beforenm(k : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_box_easy_afternm(c : UInt8*, m : UInt8*, mlen : UInt64,
                                n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_box_open_easy_afternm(m : UInt8*, c : UInt8*, clen : UInt64,
                                     n : UInt8*, k : UInt8*) : LibC::Int

    # HSalsa20 (key derivation)
    CRYPTO_CORE_HSALSA20_OUTPUTBYTES    = 32
    CRYPTO_CORE_HSALSA20_INPUTBYTES     = 16
    CRYPTO_CORE_HSALSA20_KEYBYTES       = 32
    CRYPTO_CORE_HSALSA20_CONSTBYTES     = 16

    fun crypto_core_hsalsa20(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int

    # Stream ciphers (raw keystream XOR)
    CRYPTO_STREAM_XSALSA20_KEYBYTES   = 32
    CRYPTO_STREAM_XSALSA20_NONCEBYTES = 24
    CRYPTO_STREAM_SALSA20_KEYBYTES    = 32
    CRYPTO_STREAM_SALSA20_NONCEBYTES  = 8
    CRYPTO_STREAM_CHACHA20_KEYBYTES   = 32
    CRYPTO_STREAM_CHACHA20_NONCEBYTES = 8

    fun crypto_stream_xsalsa20(c : UInt8*, clen : UInt64, n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_stream_xsalsa20_xor(c : UInt8*, m : UInt8*, mlen : UInt64,
                                   n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_stream_salsa20(c : UInt8*, clen : UInt64, n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_stream_salsa20_xor(c : UInt8*, m : UInt8*, mlen : UInt64,
                                  n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_stream_chacha20(c : UInt8*, clen : UInt64, n : UInt8*, k : UInt8*) : LibC::Int
    fun crypto_stream_chacha20_xor(c : UInt8*, m : UInt8*, mlen : UInt64,
                                   n : UInt8*, k : UInt8*) : LibC::Int

    # Poly1305 one-time authenticator
    CRYPTO_ONETIMEAUTH_POLY1305_BYTES    = 16
    CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES = 32

    fun crypto_onetimeauth_poly1305(out : UInt8*, in : UInt8*, inlen : UInt64, k : UInt8*) : LibC::Int
  end

  # Initialize libsodium on load. Idempotent; safe from multiple threads.
  raise "libsodium: sodium_init failed" if LibSodium.sodium_init < 0
end
