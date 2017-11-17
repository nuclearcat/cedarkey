The CedarKey is an alternative implementation of secure storage for ssh keys

This key is mostly intended to protect from "software"(trojans, etc.) extraction of key and to provide more reliable method of storing keys than just
keeping it on disk storage. It is not protected as smartcard against physical attacks, however in some cases it is more transparent,
and wont have possible hidden backdoors as smartcards might have (like CVE-2017-15361) and uses very simple protocol to reduce probability of software exploits
using "corner cases" of protocol, such as, for example ASN.1 prone to have overflows and leaks (MITKRB5-SA-2009-002, MS04-007, CAN-2003-0545 and much more),
due implementation complexity.

And most important feature i aim to keep footprint small as possible, as result you can have hardware dongle that can keep 3 RSA4096(DER format) on 64k flash,
or whopping 30 keys in 128k flash.
As alternative you can take a look to gnuk(https://www.fsij.org/category/gnuk.html), but it generates 110592 build in current snapshot, while Blue Pill
have only 64k flash (officially).

QA
Q: Why serial, and not smartcard standard?
A: Read above. But wont hurt to repeat again - because smartcards love TLV stuff and other things i am trying to avoid, which i am trying avoid as much as possible. Additionally you need to install libraries and software
for smartcards handling, while this agent need one program with user privileges and access to ACM serial device(often allowed by default).
