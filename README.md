# emsha

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/shimmering-clarity/emsha/tree/master.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/shimmering-clarity/emsha/tree/master)

[![image](https://scan.coverity.com/projects/29250/badge.svg)](https://scan.coverity.com/projects/shimmering-clarity-emsha)

This library is an MIT-licensed HMAC-SHA-256 C++11 library designed for
embedded systems. It is built following the JPL [Power of  Ten](http://spinroot.com/gerard/pdf/P10.pdf)
rules. It was written in response to a need for a standalone HMAC-SHA-256
package that could run on several platforms, including several memory-
constrained embedded platforms.

### Getting and Building the Source

The source code is available via
[Git](https://git.wntrmute.dev/sc/emsha/); each version should be git
tagged. There is also a [mirror on Github](https://github.com/shimmering-clarity/emsha).

```
git clone https://git.wntrmute.dev/sc/emsha
```
The current release is
[1.1.1](https://git.wntrmute.dev/sc/emsha/releases/tag/v1.1.0).

The project is built using CMake. Packages are built using the `RelWithDebInfo`
configuration; artifacts are built using the [sc3dev](https://git.wntrmute.dev/sc/sc3dev/)
[build script](https://git.wntrmute.dev/sc/sc3dev/src/branch/master/cmake-build-and-test.sh).


There are two cache variables that might be useful:

- `SET EMSHA_NO_HEXSTRING` disables the provided `hexstring` function;
  while this might be useful in many cases, it also adds extra size to
  the code. For memory-constrained microcontrollers, this might be 
  desirable.
- `SET_EMSHA_NO_HEXLUT` disables the larger lookup table used by
  `hexstring`, which can save around a kilobyte of program space. If
  the `hexstring` function is disabled, this option has no effect.
- `SET_EMSHA_NO_SELFTEST` disables the internal self-tests, which can
  reclaim some additional program space.

### Documentation

Documentation is currently done with Doxygen; documentation is
available [online](https://docs.shimmering-clarity.net/emsha/).

### See also

-   [FIPS 180-4, the Secure Hash Standard](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
-   [FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC)](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf)
-   [RFC 2014, HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
-   [RFC 6234, US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)](https://tools.ietf.org/html/rfc6234)
-   The behaviour of this package was cross-checked using the Go 1.5.1
    linux/amd64 standard library's [crypto/sha256](https://golang.org/src/crypto/sha256/) package.

### Acknowledgements

This library came about after extracting the relevant C code from  RFC 
6234, and needing a C++ version. It draws heavy inspiration from that
code. I also pulled a lot of test vectors from Go's crypto/sha256.
