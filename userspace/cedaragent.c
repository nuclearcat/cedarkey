/*
 * CedarKey userspace
 *
 * Copyright (C) 2017 Denys Fedoryshchenko <nuclearcat@nuclearcat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * Denys Fedoryshchenko. Denys Fedoryshchenko DISCLAIMS THE WARRANTY
 * OF NON INFRINGEMENT OF THIRD PARTY RIGHTS
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA, 02110-1301 USA
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the CedarKey software without
 * disclosing the source code of your own applications.
 * For more information, please contact at this address: key@nuclearcat.com
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <openssl/sha.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include "../firmware/src/common.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
//#include "mbedtls/pk.h"


// https://tools.ietf.org/html/draft-miller-ssh-agent-02#page-3
// Where "key blob" is the standard public key encoding of the key to be removed.
// SSH protocol key encodings are defined in [RFC4253] for "ssh-rsa" and "ssh-dss" keys,
// in [RFC5656] for "ecdsa-sha2-*" keys and in [I-D.ietf-curdle-ssh-ed25519] for "ssh-ed25519" keys.

// We store just N, E, P and Q encrypted by CBC, instead of PEM/DER, because parser is too fat for STM32F1
// Also: https://tls.mbed.org/kb/development/how-to-fill-rsa-context-from-n-e-p-and-q
// https://tls.mbed.org/kb/how-to/encrypt-with-aes-cbc

#define SSH_AGENTC_REQUEST_IDENTITIES                  11
#define SSH_AGENTC_SIGN_REQUEST                        13
#define SSH_AGENTC_ADD_IDENTITY                        17
#define SSH_AGENTC_REMOVE_IDENTITY                     18
#define SSH_AGENTC_REMOVE_ALL_IDENTITIES               19
#define SSH_AGENTC_ADD_ID_CONSTRAINED                  25
#define SSH_AGENTC_ADD_SMARTCARD_KEY                   20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY                21
#define SSH_AGENTC_LOCK                                22
#define SSH_AGENTC_UNLOCK                              23
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       26
#define SSH_AGENTC_EXTENSION                           27

#define SSH_AGENT_FAILURE                               5
#define SSH_AGENT_SUCCESS                               6
#define SSH_AGENT_EXTENSION_FAILURE                     28
#define SSH_AGENT_SIGN_RESPONSE                         14
#define SSH_AGENT_IDENTITIES_ANSWER                     12

#define MAX_PRECACHED_KEYS 16
/* including null */
#define VERLEN 6
#define MAXAGENTCLIENTS 128

int serfd = -1;
char sockname[4096];
int flag_verbose = 0;
char *blinky_askpass = NULL;
char *startup_askpass = NULL;
struct termios saved_attributes;
int agent_clients[MAXAGENTCLIENTS];
int agent_clients_num = 0;
int iotimeout = 0;
// IMPORTANT TODO: as serial non-blocking, make write properly, with verifying return code

/* This is precached _public_ keys, dont worry */
char *precached_keys[MAX_PRECACHED_KEYS];
uint32_t precached_keys_len[MAX_PRECACHED_KEYS];

struct __attribute__((__packed__)) agent_msghdr {
        uint32_t message_len;
        uint8_t message_type;
        uint8_t message_contents[];
};

void verbose_printf( const char* format, ... ) {
        va_list args;
        if (!flag_verbose)
                return;
        va_start( args, format );
        vfprintf( stdout, format, args );
        va_end( args );
}

void stdin_reset (void) {
        tcsetattr (STDIN_FILENO, TCSANOW, &saved_attributes);
}

void stdin_disable_echo (int justsave) {
        struct termios tattr;

        /* Make sure stdin is a terminal. */
        if (!isatty (STDIN_FILENO)) {
                fprintf (stderr, "Not a terminal.\n");
                exit (EXIT_FAILURE);
        }

        /* Save the terminal attributes so we can restore them later. */
        tcgetattr (STDIN_FILENO, &saved_attributes);
        if (justsave)
          return;

        /* Set the funny terminal modes. */
        tcgetattr (STDIN_FILENO, &tattr);
        tattr.c_lflag &= ~(ICANON | ECHO); /* Clear ICANON and ECHO. */
        tattr.c_cc[VMIN] = 1;
        tattr.c_cc[VTIME] = 0;
        tcsetattr (STDIN_FILENO, TCSAFLUSH, &tattr);
}

void remove_newlines(char *data) {
        char *pos;
        if ((pos=strchr(data, '\r')) != NULL)
                *pos = '\0';
        if ((pos=strchr(data, '\n')) != NULL)
                *pos = '\0';
}

/* Keep disk space clean if killed, because we create sockets in home directory */
void fncleanup (void) {
        stdin_reset();
        if (sockname[0])
                unlink(sockname);
        /* Lock dongle! */
        if (serfd > 0)
                write(serfd, "Z", 1);
}

void intcleanup(int dummy) {
        verbose_printf("Cleanup done\n");
        exit(0);
}

int write_wrapper(int fd, void *buf, int len) {
        uint32_t written = 0;
        char *wrbuf = buf;
        int ret;
        while (written != len) {
                ret = write(fd, &wrbuf[written], 1);
                if (ret > 0) {
                        written += ret;
                } else {
                        perror("write error");
                }
        }
        return(len);
}


// Debugging function
void rewritefile(char *name, char *buf, int len) {
        unlink(name);
        int wfd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        write_wrapper(wfd, buf, len);
        close(wfd);
}

void rand_str(char *dest, size_t length) {
        char charset[] = "0123456789"
                         "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        while (length-- > 0) {
                size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
                *dest++ = charset[index];
        }
        *dest = '\0';
}

/* slightly better seeding, maybe better /dev/urandom? */
void time_seed(void) {
        time_t now = time(0);
        unsigned char *p = (unsigned char *)&now;
        unsigned seed = 0;

        for (size_t i = 0; i < sizeof now; i++)
        {
                seed = seed * (UCHAR_MAX + 2U) + p[i];
        }
        srand(seed);
        return;
}

int isready(int fd, int timeout) {
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        tv.tv_sec = timeout / 1000; // secs
        tv.tv_usec = (timeout % 1000) * 1000; // ms

        return(select(fd+1, &rfds, NULL, NULL, &tv));
}

int readexactly(int fd, int howmuch, char *buf) {
        fd_set rfds;
        int n;
        int bytesdone = 0;
        time_t started = time(NULL);

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        while(1) {
                if (select(fd+1, &rfds, NULL, NULL, NULL) > 0) {
                        n = read(fd, &buf[bytesdone], 1);
                        if (n <= 0) {
                                // TODO: show errno
                                if (flag_verbose)
                                  perror("[read error] ");
                                return(-1);
                        }
                        bytesdone += n;
                        if (bytesdone == howmuch)
                                return(0);
                } else {
                        if (flag_verbose)
                          perror("[select error] ");
                        return(-1); // error happened
                }
                // If iotimeout set - we have deadline for I/O
                if (iotimeout && time(NULL) - started > iotimeout)
                  return(-1);
        }
        return(0);
}


int set_interface_attribs (int fd, int speed, int parity) {
        struct termios tty;
        memset (&tty, 0, sizeof tty);
        if (tcgetattr (fd, &tty) != 0)
        {
                printf ("error %d from tcgetattr", errno);
                return -1;
        }

        cfsetospeed (&tty, speed);
        cfsetispeed (&tty, speed);

        tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
        tty.c_lflag = 0;                // no signaling chars, no echo,
                                        // no canonical processing
        tty.c_oflag = 0;                // no remapping, no delays
        tty.c_cc[VMIN]  = 0;            // read doesn't block
        tty.c_cc[VTIME] = 0;            // 0.5 seconds read timeout

        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

        tty.c_cflag |= (CLOCAL | CREAD); // ignore modem controls,
                                         // enable reading
        tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
        tty.c_cflag |= parity;
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;
        tty.c_iflag = 0;

        if (tcsetattr (fd, TCSANOW, &tty) != 0)
        {
                printf ("error %d from tcsetattr", errno);
                return -1;
        }
        return 0;
}


int precache_keys(void) {
        int i;
        uint32_t len;
        char switchkey[] = "X0";
        char loadpubkey[] = "L";
        char answer[1];
        char keybuf[4096];

        verbose_printf("Precaching keys...\n");
        /* Invalidate old cache (dongle reconnected etc)*/
        if (precached_keys_len[0] != 0) {
                for (i=0; i<MAX_PRECACHED_KEYS; i++) {
                        if (precached_keys_len[i]) {
                                precached_keys_len[i] = 0;
                                free(precached_keys[i]);
                        }
                }
        }

        /* Valid keys have to be written sequentally TODO: ? */
        for (i=0; i<MAX_PRECACHED_KEYS; i++) {
                switchkey[1] = '0' + i;
                write_wrapper(serfd, switchkey, 2);
                if (readexactly(serfd, 1, answer) < 0)
                        return(-1);
                verbose_printf("Switched key %d\n", i);
                write_wrapper(serfd, loadpubkey, 1);
                if (readexactly(serfd, 4, keybuf) < 0)
                        return(-1);
                memcpy(&len, keybuf, 4);
                len = ntohl(len);
                verbose_printf("Signature length %d\n", len);
                if (len >= 4096 || len == 0)
                        break;
                if (readexactly(serfd, len, &keybuf[4]) < 0)
                        return(-1);
                len += 4;
                precached_keys[i] = (char*)malloc(len);
                precached_keys_len[i] = len;
                memcpy(precached_keys[i], keybuf, len);
                verbose_printf("PRECACHED KEY %d\n", i);
        }

        /* switch back to 0 key, not essential but needed for development */
        switchkey[1] = '0';
        write_wrapper(serfd, switchkey, 2);
        if (readexactly(serfd, 1, answer) < 0)
                return(-1);
        return(0);
}

int open_port(char *portname, char *pincode, int checkanswer) {
        int fd; /* File descriptor for the port */
        int ret;
        char *buffer;
        char verstring[VERLEN];
        verbose_printf("[open_port] Opening port\n");
        fd = open(portname, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd == -1)   {
                perror("[open_port] Unable to open CedarKey port, ");
                return(-1);
        }
        verbose_printf("[open_port] Port successfully opened\n");
        fcntl(fd, F_SETFL, O_RDWR);

        set_interface_attribs(fd, B115200, 0);

        if (pincode) {
                int unlock_len = strlen(pincode) + 3; // 2x~ and NULL
                verbose_printf("[open_port] Entering PIN code\n");
                buffer = (char*)malloc(unlock_len);
                sprintf(buffer, "~%s~", pincode);
                ret = write_wrapper(fd, buffer, unlock_len);
                free(buffer);
                if (ret != unlock_len) {
                        return(-1);
                }
        }
        if (checkanswer) {
                verbose_printf("[open_port] Checking dongle version\n");
                ret = write_wrapper(fd, "V", 1);
                memset(verstring, 0x0, VERLEN);
                if (readexactly(fd, VERLEN-1, verstring) < 0) {
                        printf("Dongle not ready\n");
                        return(-1);
                } else {
                        verbose_printf("Dongle Version: %s\n", verstring);
                }
        }
        return (fd);
}

/* Generic way of handling length-value ssh structures */
struct packdata {
        char *buffer;
        int len;
};

struct packdata *packdata_new (void) {
        struct packdata *x = (struct packdata*)malloc(sizeof(struct packdata));
        x->len = 0;
        x->buffer = NULL;
        return(x);
}

void packdata_del(struct packdata *x) {
        if (x->len)
                free(x->buffer);
        free(x);
}

// append/prepend without adding length
void packdata_extend_raw(struct packdata *original, void *somedata, int len, int isprepend) {
        uint32_t newfulllen = original->len + len;
        char *newbuf = (char*)malloc(newfulllen);
        if (isprepend) {
                memcpy(newbuf, somedata, len);
                if (original->len)
                        memcpy(&newbuf[len], original->buffer, original->len);
        } else {
                if (original->len)
                        memcpy(newbuf, original->buffer, original->len);
                memcpy(&newbuf[original->len], somedata, len);
        }
        if (original->len)
                free(original->buffer);
        original->buffer = newbuf;
        original->len = newfulllen;

}

// prepend/append some chunk with LV encoding
void packdata_extend(struct packdata *original, void *somedata, int len, int isprepend) {
        uint32_t datalenhdr = htonl(len);
        uint32_t newfulllen = original->len + len + 4;
        char *newbuf = (char*)malloc(newfulllen);
        if (isprepend) {
                memcpy(newbuf, &datalenhdr, 4);
                memcpy(&newbuf[4], somedata, len);
                if (original->len)
                        memcpy(&newbuf[4+len], original->buffer, original->len);
        } else {
                if (original->len)
                        memcpy(newbuf, original->buffer, original->len);
                memcpy(&newbuf[original->len], &datalenhdr, 4);
                memcpy(&newbuf[original->len+4], somedata, len);
        }
        if (original->len)
                free(original->buffer);
        original->buffer = newbuf;
        original->len = newfulllen;
}

void packdata_envelope(struct packdata *original) {
        uint32_t datalenhdr = htonl(original->len);
        uint32_t newfulllen = original->len + 4;
        char *newbuf = (char*)malloc(newfulllen);
        memcpy(newbuf, &datalenhdr, 4);
        memcpy(&newbuf[4], original->buffer, original->len);
        free(original->buffer);
        original->buffer = newbuf;
        original->len = newfulllen;
}

void packdata_final(struct packdata *original, uint8_t cmdcode) {
        uint32_t datalenhdr = htonl(original->len+1);
        uint32_t newfulllen = original->len + 5;
        char *newbuf = (char*)malloc(newfulllen);
        memcpy(newbuf, &datalenhdr, 4);
        newbuf[4] = cmdcode;
        memcpy(&newbuf[5], original->buffer, original->len);
        free(original->buffer);
        original->buffer = newbuf;
        original->len = newfulllen;
}

void answer_fail(int s) {
        struct packdata *pd = packdata_new();
        packdata_final(pd, SSH_AGENT_FAILURE);
        write_wrapper(s, pd->buffer, pd->len);
        packdata_del(pd);
}

char* unpacklv(char *buf, uint32_t len, uint32_t *chunklen) {
        if (len < 4)
                return(NULL);
        memcpy(chunklen, buf, 4);
        *chunklen = htonl(*chunklen);
        if (len <= *chunklen+4)
                return(NULL);
        return(buf+4);
}

void faskpass_blinky(void) {
        char fullcmd[1024];
        FILE *fp;

        memset(fullcmd, 0x0, 1024);
        strcat(fullcmd, blinky_askpass);
        strcat(fullcmd, " \"How many blinks?\"");
        fp = popen(fullcmd, "r");
        memset(fullcmd, 0x0, 1024);
        if ( fp == NULL )
                return;
        fullcmd[0] = '\0';
        if (fgets(fullcmd, sizeof(fullcmd), fp) == NULL)
                return;
        write_wrapper(serfd, fullcmd, 1);
        fclose(fp);
}

void faskpass_startup(void) {
        char fullcmd[1024];
        FILE *fp;
        char pass_cmd[] = "P";
        char pass_end[] = "~";

        memset(fullcmd, 0x0, 1024);
        strcat(fullcmd, startup_askpass);
        strcat(fullcmd, " \"Keys unlock password?\"");
        fp = popen(fullcmd, "r");
        memset(fullcmd, 0x0, 1024);
        if ( fp == NULL )
                return;
        if (fgets(fullcmd, sizeof(fullcmd), fp) == NULL)
                return;
        remove_newlines(fullcmd);
        write_wrapper(serfd, pass_cmd, 1);
        write_wrapper(serfd, fullcmd, strlen(fullcmd));
        write_wrapper(serfd, pass_end, 1);
        memset(fullcmd, 0x0, sizeof(fullcmd));
        fclose(fp);
}


void answer_signed(int s, char *buf, uint32_t len) {
        uint32_t keyblob_len;
        uint32_t signblob_len;
        uint8_t buffer[8192]; // TODO: dynamic
        struct packdata *pd = packdata_new();
        char *keyblob, *signblob;
        int i;
        char signtype = 0;

        // skip total length header 4b
        keyblob = unpacklv(buf, len, &keyblob_len);
        if (!keyblob) {
                printf("[answer_signed] Keyblob invalid\n");
                return;
        }

        signblob = unpacklv(keyblob+keyblob_len, len-keyblob_len, &signblob_len);
        if (!signblob) {
                printf("[answer_signed] Signature invalid\n");
                return;
        } else {
                verbose_printf("[answer_signed] DATA to sign %db\n", signblob_len);
        }

        if (precached_keys_len[0]) {
                char *idstruct = keyblob;
                uint32_t idlen;
                unpacklv(keyblob, keyblob_len, &idlen);
                if (idlen == 7 && !memcmp(idstruct+4, "ssh-rsa", 7)) {
                        verbose_printf("[answer_signed] searching in cached keys\n");
                        for (i=0; precached_keys_len[i]; i++) {
                                if (keyblob_len == precached_keys_len[i]-4 && !memcmp(keyblob, precached_keys[i]+4, precached_keys_len[i]-4)) {
                                        verbose_printf("[signing] match for key %d\n", i);
                                        char switchkey[] = "X0";
                                        switchkey[1] = '0' + i;
                                        write_wrapper(serfd, switchkey, 2);
                                        if (readexactly(serfd, 1, switchkey) < 0)
                                                return;
                                        break;
                                }
                        }
                } else {
                        verbose_printf("[answer_signed] invalid key offer\n");
                        return; // not valid key
                }
        }

        // Write command
        write_wrapper(serfd, "S", 1);

        if (blinky_askpass) {
                faskpass_blinky();
        }

        // type of signature, SHA512 only for now
        write_wrapper(serfd, &signtype, 1);

        // Write signblob together with length header
        verbose_printf("[answer_signed] PROVIDING DATA TO BE SIGNED\n");
        for (uint32_t i=0; i<signblob_len+4; i++) {
                write_wrapper(serfd, signblob-4+i, 1);
        }

        verbose_printf("[answer_signed] READING SIGNED DATA HEADER 4b\n");
        for (int i = 0; i<4; i++) {
                while (read(serfd, &buffer[i], 1) != 1) ;
        }

        int total = ntohl(*((uint32_t*)buffer));
        verbose_printf("[answer_signed] READING SIGNED DATA REMAINDER %db\n", total);

        for (int i = 4; i<total+4; i++) {
                while(read(serfd, &buffer[i], 1) != 1) ;
        }

        pd = packdata_new();
        {
                char nicesig[] = "rsa-sha2-512";
                packdata_extend(pd, nicesig, strlen(nicesig), 0);
        }
        {
                packdata_extend(pd, &buffer[4], total, 0);
        }
        packdata_envelope(pd);
        packdata_final(pd, SSH_AGENT_SIGN_RESPONSE);
        write_wrapper(s, pd->buffer, pd->len);
        packdata_del(pd);
}

void answer_cached_identities(int s) {
        struct packdata *pd = packdata_new();
        int i;
        for (i=0; precached_keys_len[i]; i++) ;
        uint32_t numofkeys = htonl(i);
        verbose_printf("[answer_identities_cached] Number of cached keys %d\n", i);
        packdata_extend_raw(pd, &numofkeys, 4, 0);
        for (i=0; precached_keys_len[i]; i++) {
                char comment[64];
                verbose_printf("[answer_identities_cached] Adding key %d len %d\n", i, precached_keys_len[i]);
                sprintf(comment, "hwkey%d", i);
                packdata_extend(pd, precached_keys[i]+4, precached_keys_len[i]-4, 0);
                packdata_extend(pd, comment, strlen(comment), 0);
        }
        packdata_final(pd, SSH_AGENT_IDENTITIES_ANSWER);
        i = send(s, pd->buffer, pd->len, 0);
        if (i != pd->len) {
                verbose_printf("[answer_identities_cached] send error %d/%d\n", i, pd->len);
        }
        packdata_del(pd);
}

void answer_identities(int s) {
        struct packdata *pd = packdata_new();
        int total;
        uint8_t buffer[8192]; // TODO: dynamic
        verbose_printf("[answer_identities] REQUESTING LIST OF KEYS\n");
        write_wrapper(serfd, "L", 1);

        verbose_printf("[answer_identities] READING KEYS HEADER 4b\n");
        for (int i = 0; i<4; i++) {
                read(serfd, &buffer[i], 1);
        }

        total = ntohl(*((uint32_t*)buffer));
        if (!total) {
                // invalid key set, close socket to not hang ssh
                close(s);
                return;
        }

        verbose_printf("[answer_identities] RECEIVING %d bytes\n", total);
        if (readexactly(serfd, total, (char *)buffer) < 0)
          return;
        verbose_printf("[answer_identities] KEYS RECEIVED\n");
        /* Number of keys field */
        {
                uint32_t numofkeys = htonl(1);
                packdata_extend_raw(pd, &numofkeys, 4, 0);
        }
        /* Key, single in this case */
        {
                char comment[] = "hwkey";
                packdata_extend(pd, buffer, total, 0);
                packdata_extend(pd, comment, strlen(comment), 0);
        }
        packdata_final(pd, SSH_AGENT_IDENTITIES_ANSWER);
        send(s, pd->buffer, pd->len, 0);
        packdata_del(pd);
}

void critical_mbed_error(int errcode) {
        char buf[1024];
        mbedtls_strerror(errcode, buf, 1023);
        printf("critical crypto error: %s\n", buf);
        exit(1);
}

#define KEYBUF_SZ 2048
#define IV_SZ 16
#define KEYSRC_SZ 32 // Material for AES key generation, key salt maybe?

void dongle_keywrite(char *keyfilename) {
        char wrbuf[1];
        mbedtls_pk_context pk;
        mbedtls_rsa_context *rsa;
        int ret, rnd_dev_fd;
        char input_stdin[128];
        char input_stdin_repeat[128];
        uint32_t e_len, p_len, q_len, tocrypt_sz;
        unsigned char keybuf[KEYBUF_SZ];
        unsigned char crypted_keybuf[KEYBUF_SZ];
        unsigned char key[32];
        unsigned char iv[IV_SZ];
        size_t offset = 0;

        memset(keybuf, 0x0, KEYBUF_SZ);
        memset(crypted_keybuf, 0x0, KEYBUF_SZ);

        /* KEYSRC, IV and fill it with random data */
        rnd_dev_fd = open("/dev/urandom", O_RDONLY);
        if (rnd_dev_fd < 0) {
                perror("rnd device open error - ");
                exit(2);
        }
        read(rnd_dev_fd, keybuf, KEYBUF_SZ);
        close(rnd_dev_fd);

        offset += KEYSRC_SZ; // keysrc

        memcpy(iv, &keybuf[offset], IV_SZ);
        offset += IV_SZ;

        stdin_disable_echo(0);
        printf("Key decryption password:\r\n");
        if (fgets (input_stdin, 127, stdin) == NULL)
                exit(1);
        stdin_reset();

        remove_newlines(input_stdin);
        verbose_printf("Opening key...\n");
        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_keyfile(&pk, keyfilename, input_stdin);
        if (ret)
                critical_mbed_error(ret);
        if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
                printf("Invalid key type? We need RSA key!\n");
                exit(1);
        }
        rsa = mbedtls_pk_rsa(pk);
        e_len = mbedtls_mpi_size(&rsa->E);
        p_len = mbedtls_mpi_size(&rsa->P);
        q_len = mbedtls_mpi_size(&rsa->Q);
        memcpy(&keybuf[offset], &e_len, 4);
        offset += 4;
        memcpy(&keybuf[offset], &p_len, 4);
        offset += 4;
        memcpy(&keybuf[offset], &q_len, 4);
        offset += 4;
        //printf("E %d P %d Q %d\n", e_len, p_len, q_len);
        ret = mbedtls_mpi_write_binary(&rsa->E, &keybuf[offset], e_len);
        if (ret)
                critical_mbed_error(ret);
        offset += e_len;
        ret = mbedtls_mpi_write_binary(&rsa->P, &keybuf[offset], p_len);
        if (ret)
                critical_mbed_error(ret);
        offset += p_len;
        ret = mbedtls_mpi_write_binary(&rsa->Q, &keybuf[offset], q_len);
        if (ret)
                critical_mbed_error(ret);
        offset += q_len;

        memset(input_stdin, 0x0, 128);
        memset(input_stdin_repeat, 0x0, 128);

        do {
                if (input_stdin[0] != 0x0) {
                        printf("Try again\n");
                        memset(input_stdin, 0x0, 128);
                        memset(input_stdin_repeat, 0x0, 128);
                }
                stdin_disable_echo(0);
                printf("Key encryption password for dongle (6+ characters):\r\n");
                if (fgets (input_stdin, 127, stdin) == NULL)
                        exit(1);
                printf("Please repeat to ensure it is typed correctly:\r\n");
                if (fgets (input_stdin_repeat, 127, stdin) == NULL)
                        exit(1);
                stdin_reset();
                if (strlen(input_stdin) < 6 || strlen(input_stdin) >= 64) {
                        printf("Too short! More than 6 characters and less than 64\n");
                        continue;
                }
        } while (strncmp(input_stdin, input_stdin_repeat, 127));
        remove_newlines(input_stdin);

        /* AES Key generation Move as separate function, shared maybe ? */
        {
                unsigned char prekey[128];
                memset(prekey, 0x0, 128);
                memcpy(prekey, keybuf, KEYSRC_SZ);
                memcpy(&prekey[32], input_stdin, strlen(input_stdin));
                mbedtls_sha256(prekey, 128, key, 0);
                memset(prekey, 0x0, 128);
        }
        uint32_t sum = 0;
        for (int x=0; x<32; x++) {
                sum += key[x];
        }
        for (int x=0; x<16; x++) {
                sum += iv[x];
        }


        // Rounding to 32 byte
        tocrypt_sz = offset-KEYSRC_SZ-IV_SZ;

        if (tocrypt_sz % 32 != 0) {
                offset += 32 - (tocrypt_sz % 32); // update it too as it represents total size
                tocrypt_sz = (tocrypt_sz + 32 - (tocrypt_sz % 32));
        }

        /* Copy unencrypted header, salt for aes key and IV */
        memcpy(crypted_keybuf, keybuf, KEYSRC_SZ+IV_SZ);

        {
                mbedtls_aes_context aes;
                mbedtls_aes_init(&aes);
                mbedtls_aes_setkey_enc(&aes, key, 256);
                mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, offset-KEYSRC_SZ-IV_SZ, iv, &keybuf[KEYSRC_SZ+IV_SZ], &crypted_keybuf[KEYSRC_SZ+IV_SZ]);
                mbedtls_aes_free(&aes);
                // copy back crypted content
                memcpy(&keybuf[KEYSRC_SZ+IV_SZ], &crypted_keybuf[KEYSRC_SZ+IV_SZ], offset-KEYSRC_SZ-IV_SZ);
        }

        verbose_printf("All done, total size %d\n", offset);

        write_wrapper(serfd, "W", 1);
        verbose_printf("[writing_key] Write command issued\n");

        uint32_t offset_norder = htonl(offset);
        write_wrapper(serfd, &offset_norder, 4);
        verbose_printf("[writing_key] Data length %d sent\n", offset);


        for (int i=0; i<offset; i++) {
                write_wrapper(serfd, &keybuf[i], 1);
                if (readexactly(serfd, 1, wrbuf) < 0) {
                  printf("[writing_key] Key is NOT written. Error, confirmation of byte %d from total %lu not received\n", i, offset);
                  exit(0);
                }

        }

        if (readexactly(serfd, 1, wrbuf) < 0) {
          printf("[writing_key] Final confirmation not received, key probably not written correctly!\n");
        } else {
          printf("[writing_key] Key is written\n");
        }
        exit(0);
}

void config_dongle (void) {
        char input_stdin[128];
        unsigned char cfgbuffer[1024];
        char salt[64];
        unsigned char shainput[128];
        int rnd_dev_fd;
        uint32_t cfg = 0;

        memset(input_stdin, 0x0, 128);
        memset(cfgbuffer, 0x00, 1024); // might be 0xFF?

        printf("Remember, you can use for PIN and password any printable characters except symbol ~ \n");
        printf("Please enter PIN code to unlock dongle:");
        if (fgets (input_stdin, 127, stdin) == NULL)
                exit(1);
        remove_newlines(input_stdin);

        //printf("Entered pin: [%s]", input_stdin);

        rnd_dev_fd = open("/dev/urandom", O_RDONLY);
        if (rnd_dev_fd < 0) {
                perror("rnd device open error - ");
                exit(2);
        }
        read(rnd_dev_fd, salt, 64);
        close(rnd_dev_fd);
        verbose_printf("Reading random salt - OK\n");
        memset(shainput, 0x0, 128);
        memcpy(shainput, salt, 64);
        memcpy(shainput+64, input_stdin, strlen(input_stdin));

        /* Write to config */
        memcpy(&cfgbuffer[4], salt, 64); // write salt
        SHA512(shainput, 128, &cfgbuffer[68]); //write hashed pin


        printf("Do you want to use Blinker feature? [y/n]");
        if (fgets (input_stdin, 127, stdin) == NULL)
                exit(1);
        if (input_stdin[0] == 'y') {
                cfg |= CFG_BIT_BLINKERLOCK;
        }

        memcpy(cfgbuffer, &cfg, 4);

        /* Write 0x1 to start flashing process */
        input_stdin[0] = 0x1;
        write_wrapper(serfd, input_stdin, 1);

        for (int i=0; i<1024; i++) {
                write_wrapper(serfd, &cfgbuffer[i], 1); /* Single byte writes - safest */
        }
        printf("All done! Enjoy!\n");
        exit(0);
}

void show_help(char **argv) {
        printf("Usage: %s -s /dev/portname [OPTIONS]\n", argv[0]);
        printf("  -n \t\t initialize clean CedarKey\n");
        printf("  -w filename \t write key to dongle\n");
        printf("  -p PIN \t automatically enter access pin (INSECURE! Only on trusted host!)\n");
        printf("  -k number \t Activate only specific key number (-1 activate all keys)\n");
        printf("  -x \t\t don't reopen CedarKey automatically, if replugged, exit instead\n");
        printf("  -D \t\t debug, do not daemonize\n");
        printf("  -d \t\t Ask password only once at start, it will be in stick ram until lockout and removed from host memory (disables reopen)\n");
        printf("  -b path\t\t Path and name to 'ask pass' program (might work: ssh-askpass), will ask pass on each auth if blinker feature enabled\n");
        printf("  -a path\t\t Ask password over 'ask pass' program for keys on start (stored in RAM until key removed from power)\n");
        printf("More information at: https://github.com/nuclearcat/cedarkey\n");
        exit(0);
}

void add_agentclient(int s2) {
  int i;
  for (i=0;i<MAXAGENTCLIENTS;i++) {
    if (agent_clients[i] == -1) {
      agent_clients[i] = s2;
      agent_clients_num++;
      break;
    }
  }
  // no more space
  if (i==MAXAGENTCLIENTS) {
    close(s2);
  }
}

void remove_agentclient(int s2) {
  int i;
  verbose_printf("Removing agent client\n");
  for (i=0;i<MAXAGENTCLIENTS;i++) {
    if (agent_clients[i] == s2) {
      agent_clients[i] = -1;
      agent_clients_num--;
      break;
    }
  }
  // no more space
  if (i==MAXAGENTCLIENTS) {
    printf("Trying to remove nonexisting client socket?\n");
    exit(1);
  }
}


int handle_agentclient_data(int s2, int keynum) {
          char buf[65536];
          struct agent_msghdr agentmsg_begin;
          if (readexactly(s2, 5, buf) < 0) {
                  remove_agentclient(s2);
                  return(-1);
          }
          memcpy(&agentmsg_begin, buf, 5);
          agentmsg_begin.message_len = ntohl(agentmsg_begin.message_len);
          if (agentmsg_begin.message_len > 1) {
                  if (readexactly(s2, agentmsg_begin.message_len-1, buf) < 0) {
                          remove_agentclient(s2);
                          return(-1);
                  }
          }
          /* TODO: implement more :) */
          switch(agentmsg_begin.message_type) {
          case SSH_AGENTC_REQUEST_IDENTITIES:
                  if (keynum == -1)
                          answer_cached_identities(s2);
                  else
                          answer_identities(s2);
                  break;
          case SSH_AGENTC_SIGN_REQUEST:
                  answer_signed(s2, buf, agentmsg_begin.message_len-1);
                  break;
          default:
                  verbose_printf("Unknown action requested %d\n", agentmsg_begin.message_type);
                  answer_fail(s2);
                  break;
          }
          return(0);
}


int main(int argc, char **argv)
{
        int s, s2, t;
        struct sockaddr_un local, remote;
        int c;
        int flag_cfgnew = 0, flag_reopen = 1, flag_daemon = 1;
        int keynum = -1;
        char rndpart[16];
        char *pincode = NULL;
        char *portname = NULL;
        char *keyfilename = NULL;

        signal(SIGINT, intcleanup);

        memset(sockname, 0x0, sizeof(sockname));
        /* Lock dongle on exit and cleanup unix socket file */
        stdin_disable_echo(1); // just save stdin tcattr
        atexit(fncleanup);

        /* Initialize precached keys array */
        for (int i = 0; i < MAX_PRECACHED_KEYS; i++) {
                precached_keys[i] = NULL;
                precached_keys_len[i] = 0;
        }
        for (int i = 0; i < MAXAGENTCLIENTS; i++)
          agent_clients[i] = -1;

        while ((c = getopt (argc, argv, "hns:p:Dw:k:b:a:v")) != -1) {
                switch (c)
                {
                case 'h':
                        show_help(argv);
                        break;
                case 'n':
                        flag_cfgnew = 1;
                        break;
                case 'r':
                        flag_reopen = 1;
                        break;
                case 'D':
                        flag_daemon = 0;
                        break;
                case 'v':
                        flag_verbose = 1;
                        break;
                case 'w':
                        keyfilename = strdup(optarg);
                        break;
                case 's':
                        portname = strdup(optarg);
                        break;
                case 'p':
                        pincode = strdup(optarg);
                        break;
                case 'b':
                        blinky_askpass = strdup(optarg);
                        break;
                case 'a':
                        startup_askpass = strdup(optarg);
                        break;
                case 'k':
                        keynum = atoi(optarg);
                        break;
                default:
                        exit(1);
                }
        }
        if (argc == 1) {
                show_help(argv);
                exit(0);
        }

        if (portname == NULL) {
                printf("Please specify device name for CedarKey, for example /dev/ttyACM0\n");
                exit(1);
        }



        if (flag_cfgnew) {
                char buf[32];
                printf("Please make sure blue led is ON. If not, unplug dongle, and plug it back\n");
                printf("After that, press <Enter>");
                if (fgets (buf, 2, stdin) == NULL)
                        exit(1);
                serfd = open_port(portname, NULL, 0);
                if (serfd < 0) {
                        printf("Can't open device, exiting.\n");
                        exit(0);
                }
                config_dongle();
                exit(0);
        }

        serfd = open_port(portname, pincode, 1);
        if (serfd < 0) {
                printf("Initial port opening failed, exiting\n");
                exit(1);
        }

        if (startup_askpass) {
                faskpass_startup();
        }

        if (keynum == -1 && !keyfilename) {
                iotimeout = 15;
                if (precache_keys()) {
                  printf("Error during key precaching, exiting\n");
                }
                iotimeout = 0;
        } else {
                char switchkey[] = "X0";
                if (keynum > 0 && keynum < 30)
                        switchkey[1] = '0' + keynum;
                write_wrapper(serfd, switchkey, 2);
                iotimeout = 3;
                if (readexactly(serfd, 1, switchkey) < 0) {
                  printf("Can't switch key, exiting\n");
                  exit(0);
                }
                iotimeout = 0;
                verbose_printf("Switched\n");
        }

        time_seed();
        rand_str(rndpart, 8);

        if (keyfilename) {
                if (keynum != -1) {
                        printf("Free key will be selected automatically, you should not specify it\n");
                        exit(0);
                }
                dongle_keywrite(keyfilename);
        }

        /* For safety it is better to say within home directory */
        if (chdir(getenv("HOME"))) {
                printf("Can't chdir to home directory\n");
                exit(1);
        }

        snprintf(sockname, 4096, ".cedarkey-%s.sock", rndpart);
        printf("SSH_AUTH_SOCK=~/%s; export SSH_AUTH_SOCK;\n", sockname);

        if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
                perror("unix socket error - ");
                exit(1);
        }

        memset(&local, 0x0, sizeof(local));
        local.sun_family = AF_UNIX;
        strcpy(local.sun_path, sockname);
        unlink(local.sun_path);
        if (bind(s, (struct sockaddr *)&local, sizeof(local)) == -1) {
                perror("bind");
                exit(1);
        }

        if (listen(s, 100) == -1) {
                perror("listen");
                exit(1);
        }
        if (flag_daemon)
                daemon(1, 0);

        for(;; ) {
                if (serfd < 0) {
                        if (!flag_reopen) {
                                exit(0);
                        }
                        serfd = open_port(portname, pincode, 1);
                        if (serfd < 0) {
                                /* Not ready yet ... */
                                verbose_printf("CedarKey can't be opened yet, retrying after 1s\n");
                                usleep(1000);
                                continue;
                        }
                        if (keynum == -1) {
                                if (precache_keys()) {
                                  verbose_printf("Error while trying to precache keys, closing device\n");
                                  close(serfd);
                                  serfd = -1;
                                }
                        } else {
                                char switchkey[] = "X0";
                                switchkey[1] = '0' + keynum;
                                write_wrapper(serfd, switchkey, 2);
                                if (readexactly(serfd, 1, switchkey) < 0) {
                                  verbose_printf("Key switching error, closing device\n");
                                  close(serfd);
                                  serfd = -1;
                                }
                        }
                }

                /* Check if CedarKey is ok, if not - close socket and keep trying to reopen
                   Serial unplug behaves following way - it signals that select can read
                 */
                if (isready(serfd, 1) > 0) {
                        printf("Error on CedarKey fd, closing\n");
                        close(serfd);
                        serfd = -1;
                        continue;
                }
                iotimeout = 30;
                for (int i=0;i<MAXAGENTCLIENTS;i++) {
                  if (agent_clients[i] != -1 && isready(agent_clients[i], 0)) {
                    verbose_printf("Handling data from agent client\n");
                    handle_agentclient_data(agent_clients[i],keynum);
                  }
                };
                iotimeout = 0;

                // Anything on main unix socket? If not, keep looping and checking serial state
                if (!isready(s, 1)) {
                        usleep(1);
                        continue;
                } else {
                  t = sizeof(remote);
                  if ((s2 = accept(s, (struct sockaddr *)&remote, (socklen_t *)&t)) == -1) {
                        perror("accept");
                        exit(1);
                  }
                  verbose_printf("New agent client...\n");
                  add_agentclient(s2);
                }
        }

        return 0;
}
