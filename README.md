# Tor in ESP32

This project is a lightweigth Tor working on a ESP32 (or other mcu). The goal in not to have a perfect anonymity, but to have something lightweight working on a mcu with the ability to connect to a remote MCU (a mcu conneted to internet, but without non-local IP address or port forwarding...), but without using an external server or proprietary/closed-source/priced solutions. 

The code is still in developpement (but it kind of works).

Warning: considere it as no secure, since it is experimental, and does not respect all the rules of Tor anonymity.

There is already https://github.com/briand-hub/toresp32 which to a tor proxy on a ESP32.  I started with the code of toresp32, and I rewrited some parts. I wanted a more lightweight and more portable thing. Moreover, I wanted to have the "rendez-vous" system for the "connet to remote" goal.

### Usage disclaimer and license

This code is open source and protected by GPL v3 license. This project is intended only for educational purposes and any modification, unintended use, illegal use is your own responsibility. This project has no warranty in any sense.

### What it can do:
- use the Tor network to connect to a IP/port
- connect to an hidden service (v3 only), or host a hidden service (v3 only).

### What it is not:
- not a tor relay (OR) or a tor directory.
- not a socks proxy.
- not secure as the real "Tor" implementation. Considere it more as an obfuscation tool than a anonymity tool.

### Features (and changes with toresp32):

- use at maximum posix functions. It compiles/runs fine on linux.
- compiles on esp-idf (no need anymore of platformio).
- hiden services v3 (client and server). Use only "new" standard (V3: ed25519 crypto, sha3...), and not old things (V2 with RSA1024...)
- removed socks5 proxy from toresp32.
- one circuit can have several sockets
- fixed sendme procedures (?) and add check receiving sendme
- rewrote all the "tor relay searching" :
  - dowloads compressed consensus.z (using "miniz"). This need more memory (at least ~40kB of ram), but save a lot of time.
  - store the whole consensus+descritpors in memory (on ESP32, in psram and spiffs)
  - check signatures of descriptors and consensus

- lib crypto and dependencies:
  - removed the dependency to sodium, and used https://www.dlbeer.co.nz/oss/c25519.html from Daniel Beer (public domain) with some modifications
  - all the computations with curve25519 are now done with this c25519 (does not use mbedtls internal things)
  - we still use mbedtls for SHAx and RSA (since it is hw accelerated in ESP32)
  - one shared entropy/random generator for all things

### future features
- For now, it only use IPV4, but ipv6 is not too dificult to add.
- I plan to add a very lightweight "rendevous protocol" to easily connect to a remote mcu without an external server, and whithout using V3 HS desciptors and time periods... Of course, the MCU and the client must to be trusted by the same party.

### Current status on ESP32

For the ESP32, it works "more or less", but there are still some problems:

- Something fails with the SPIFFS (used to store descriptors), and this is still mysterious for me. Sometimes, the SPIFFS says that the filesystem is full (but it seems that it is not). I use fopen (...,"r+") to modify the descriptors cache files, maybe the spiffs don't like this.

- Still have some memory issues. In a previous version, I used too many threads, and sometimes pthread_create failed due to lack of memory for the new stack (and it seems that the ESP32 does not want to use the PSRAM for a stack). I currently rewrote some part to use less threads and more poll(). But there are still memory issues, and race conditions, and the rewriting is not yet finished...

## Usage :

Add #define for EXAMPLE_ESP_WIFI_SSID and  EXAMPLE_ESP_WIFI_PASS to connect to internet.

If it crashes:
- You may need a ESP32 with a PSRAM (even if you use the "low memory mode"...)
- Try to increase stack sizes and put things in psram (in "idf.py menuconfig")...

If you want to make your own "hidden server", the easyest way is to modify "shitty_http_server".

There are two "modes":

- the "low memory mode": it keeps only 64 relays of each type (guard, middle, exit)
- the "standard memory": if keeps all relays nodes. it takes much more memory, and need PSRAM (ESP-wroover for example). Note that you also need (at least) the 8mb flash version. Important info of nodes (ip, fp, id25519, ntor, flags) are stored in the table cache_descs[]. One use the fingerprint (fp) to know where to store the "descriptor". One try the position 'fp[0:1]', and if it is already used, we try fp[1:2]... and so one up to fp[18:19]. Note that if cache_descs[] have size approx two times the number of nodes in the consensus (and we suppose that each fp is "as random"), each try has 50% chances to succed, so this method will fail with probability 2^(-19), which is good for our usage.

To change the mode, look at the file "defines.hpp"

### Codings conventions:

I do not have yet time to make a "clean code". I have a very specific own "coding conventions". Maybe one disturbing thing is the cutting of the code: everyting are in "header files", with no cpp files. I really don't like separating things in hpp/cpp files...

