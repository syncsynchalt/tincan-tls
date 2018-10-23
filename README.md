# tincan-tls

<img src="https://github.com/syncsynchalt/tincan-tls/raw/master/images/tincan.png"
     alt="Lover's telephone" width="498" height="140" />

This is an implementation of TLS 1.3 written from the various specifications (RFCs, etc).

We only implement enough of the protocol to be able to connect to
a web server and request a page, but the implementation itself should be
robust.

The algorithms are full of known issues such as attackable side channels and should
not be used for real work.  They are also unoptimized and err on the side of clarity.

### Dependencies

This library has no dependencies other than `crypto/rand`.

### Algorithms

The following algorithms were built for this implementation:

* **SHA-256** message digest - [RFC 6234](https://tools.ietf.org/html/rfc6234)
* **HMAC** message authentication codes - [RFC 2104](https://tools.ietf.org/html/rfc2104)
* **AES-128** symmetric cipher - [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
* **curve25519** (a particular elliptic curve) - [RFC 7748](https://tools.ietf.org/html/rfc7748)
* **ECDHE** (Elliptic Curve Diffie-Hellman with Ephemeral keys) - [RFC4492](https://tools.ietf.org/html/rfc4492)
* **GCM** (Galois/Counter Mode) - [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
