# tincan-tls

<img src="https://github.com/syncsynchalt/tincan-tls/raw/master/images/tincan.png"
     alt="Lover's telephone" width="498" height="140" />

This is an implementation of TLS 1.3 written from the various specifications (RFCs, etc).

This implementation only implements enough of the protocol to be
able to connect to a web server and request a page.

The algorithms are full of known issues such as timing side channels and should
not be used for real work.
