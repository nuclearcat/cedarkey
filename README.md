# The CedarKey is an implementation of secure storage for ssh keys

This project is mostly intended to protect from "software"(trojans, etc.) extraction of key and to provide more reliable method of storing keys than just keeping it on disk storage. It might be not protected as smartcard against all physical attacks, however in some cases it is more protected, as it's transparent and wont have hidden backdoors as smartcards (like CVE-2017-15361) and uses very simple protocol to reduce probability of software exploits using "corner cases" of protocol, such as, for example ASN.1 prone to have overflows and leaks (MITKRB5-SA-2009-002, MS04-007, CAN-2003-0545 and much more), due implementation complexity.

And most important feature i aim to keep firmware size small as possible, as result you can have hardware dongle that can keep 3+ RSA4096(DER encoding) on 64k flash, or whopping 30 keys in 128k flash. As alternative you can take a look to gnuk(https://www.fsij.org/category/gnuk.html), but it generates 110592 bytes firmware (current git snapshot), while Blue Pill have only 64k flash (officially).

# Q&A
* Q: What is Blinker feature?
* A: On key sign you will be asked for password, you should count blinks on dongle and enter number from 1 to 6. If answer is incorrect - dongle will lock down(ignore any further commands), keep blinking each second until you physically unplug it, and plug back. This is semi-replacement of "touch confirmation" as Blue Pill don't have hardware buttons.

# Quickstart (under development)
## Required Hardware:
1. STM32F103 board with SWD header (for example Blue Pill http://wiki.stm32duino.com/index.php?title=Blue_Pill)
2. ST-Link V2 programmer (you can use j-link or others, but they are not covered in quickstart)
3. 3x female-female wires
## Software:
1. https://github.com/texane/stlink
2. cross-compiler for arm (TODO: which one?)

## Preparing hardware
### Connect your stm32f103 board to st-link
* GND to GND
* DCLK to DCLK
* DIO to DIO

### Compiling firmware
* git submodule update --init
* cd firmware/opencm3
* make
* cd ../src
* make cedarkey.bin

### Flashing firmware (if everything compiled fine)
* st-flash erase
* make cedarkey.stlink-flash
