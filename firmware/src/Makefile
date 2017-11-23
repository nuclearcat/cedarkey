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
CFLAGS  += -I. -flto
BINARY = cedarkey

VPATH += ../../mbedtls/library


OBJS = sha512.o
OBJS += bignum.o asn1parse.o oid.o 
OBJS += pkcs12.o md.o cipher.o
OBJS += des.o aes.o cipher_wrap.o
OBJS += md_wrap.o sha256.o rsa.o 
#OBJS += error.o

LDSCRIPT = ../stm32-h103.ld

include ../Makefile.include

