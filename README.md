Connect tor Tor network with an ESP32 (or other mcu).

The goal in not a perfect anonymity, but to have something lightweight, and the ability to connect to it behind a non forwading port router.

Licence: GPL3

Warning: considere it as no secure, since it is experimental, and does not respects all the rules of Tor anonymity.

What it is not:
- not a tor relay (OR) or a tor directory.
- not a socks proxy.
- mot secure as the real "Tor" implementation. Considere it more as an obfuscation tool than a anonymity tool.


There is already https://github.com/briand-hub/toresp32 which to a tor proxy on a ESP32. I wanted a more lightweiht thing, and more portable.

I started with the code of toresp32, and I rewrited some parts.

Features/changes with toresp32:

- general
-- use at maximum posix functions
-- compiles now on esp-idf (no need of platformio)

- removed socks5 proxy
-- one circuit can have several sockets
-- fixed sendme procedures (?) and check receiving sendme

- tor relays serching
-- rewrite all the "tor relay searching".
-- check signatures of descriptors and consensus

- lib crypto and dependencies
-- removed the dependency to sodium, and used https://www.dlbeer.co.nz/oss/c25519.html from Daniel Beer (public domain) with some modifications
-- all the computations with curve25519 are now done with this c25519 (does not use mbedtls internal things)
-- we still use mbedtls for SHAx and RSA (since it is hw accelerated in ESP32)
-- one shared entropy/random generator for all things

