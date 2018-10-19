# tincan-tls

<img src="https://github.com/syncsynchalt/tincan-tls/raw/master/images/tincan.png"
     alt="Lover's telephone" width="498" height="140" />

This is an implementation of TLS 1.3 written from the various specifications (RFCs, etc).

We only implement enough of the protocol to be able to connect to
a web server and request a page, but the implementation itself should be
robust.

The algorithms are full of known issues such as attackable side channels and should
not be used for real work.  They are also unoptimized and err on the side of clarity.

### Algorithms

The following algorithms were built for this implementation:

* SHA-256
* HMAC
* AES-128
