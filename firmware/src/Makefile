##
## This file is part of the libopencm3 project.
##
## Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>
##
## This library is free software: you can redistribute it and/or modify
## it under the terms of the GNU Lesser General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public License
## along with this library.  If not, see <http://www.gnu.org/licenses/>.
##
CFLAGS  += -I.
BINARY = cedarkey

VPATH += ../../mbedtls/library


OBJS = entropy.o sha512.o entropy_poll.o timing.o ctr_drbg.o 
OBJS += pk_wrap.o pk.o pkparse.o bignum.o asn1parse.o oid.o 
OBJS += ecp.o pkcs12.o pem.o md.o arc4.o md5.o cipher.o pkcs5.o 
OBJS += des.o aes.o base64.o cipher_wrap.o camellia.o blowfish.o 
OBJS += ccm.o gcm.o md_wrap.o ripemd160.o sha1.o sha256.o rsa.o 
OBJS += error.o x509.o x509_crt.o


LDSCRIPT = ../stm32-h103.ld

include ../Makefile.include

