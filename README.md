# tincan-tls

<img src="https://github.com/syncsynchalt/tincan-tls/raw/master/images/tincan.png"
     alt="Lover's telephone" width="498" height="140" />

This is a soup-to-nuts implementation of [TLS 1.3](https://tools.ietf.org/html/rfc8446)
created by staring at documents for hours until code came out.  The
single goal was to establish a valid TLS session by any means
possible and trick servers into talking to me.

This code is crude and lumpy and ugly.  This is intentional and
should serve as a warning to others: this code is not usable for
real work.  In particular the crypto code is slow and full of timing
side-channels.  Any attempts to clean things up will be viewed as
an attempt to trick someone else into using this code and will be
rejected.

To win a bet I implemented this with as few dependencies as possible.
The crypto library has only one dependency, `crypto/rand`.  This
caused some code to be particularly un-golangly as I couldn't create
`error` objects.

> Note: The above paragraphs are examples of bad software practices.

### Usage

Build and run with the following:

```
go get github.com/syncsynchalt/tincan-tls/cmd/tincan-client
export PATH=$PATH:~/go/bin
tincan-client host port
```

### Algorithms

The following algorithms were built for this implementation:

* `SHA-256` message digest - [RFC 6234](https://tools.ietf.org/html/rfc6234)
* `HMAC` message authentication codes - [RFC 2104](https://tools.ietf.org/html/rfc2104)
* `AES-128` symmetric cipher - [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
* `curve25519` (a particular elliptic curve) - [RFC 7748](https://tools.ietf.org/html/rfc7748)
* `ECDHE` (Elliptic Curve Diffie-Hellman with Ephemeral keys) - [RFC4492](https://tools.ietf.org/html/rfc4492)
* `GCM` (Galois/Counter Mode) - [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
* `HKDF` (HMAC Key Derivation Function) - [RFC 5869](https://tools.ietf.org/html/rfc5869)
