TARGET = cedaragent
LIBS = -lm -lcrypto -lssh ../libscrypt/libscrypt.a
CC = gcc
CFLAGS = -g -Wall -I../mbedtls/include -I../libscrypt

.PHONY: default all clean

default: $(TARGET)
all: default

VPATH += ../mbedtls/library
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c)) 
OBJECTS += pk.o pem.o rsa.o md.o bignum.o md5.o pk_wrap.o base64.o des.o aes.o asn1parse.o md_wrap.o sha1.o sha256.o sha512.o oid.o ecdsa.o aesni.o
OBJECTS += ripemd160.o hmac_drbg.o pkparse.o ecp.o asn1write.o ecp_curves.o pkcs11.o pkcs12.o pkcs5.o arc4.o cipher.o cipher_wrap.o
OBJECTS += gcm.o ccm.o camellia.o blowfish.o error.o
HEADERS = $(wildcard *.h)


%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LDFLAGS) $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
