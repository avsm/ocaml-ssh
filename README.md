This is a library, client and server implementation of the Secure Shell (SSH)
v2 protocol, as specified in RFC 4251 and friends.

This is *unreleased* code, as the following things need to be done before
release:

* Get autoconf framework in place, or Lwt's discover.ml
* Remove MPL code in favour of Bitstring
* Remove use of classes in favour of first-class modules for configuration.
* Remove ounix and replace with Lwt
* Split out Pty stubs into a separate library.
