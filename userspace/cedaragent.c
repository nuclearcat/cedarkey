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

// https://tools.ietf.org/html/draft-miller-ssh-agent-02#page-3
// Where "key blob" is the standard public key encoding of the key to be removed.
// SSH protocol key encodings are defined in [RFC4253] for "ssh-rsa" and "ssh-dss" keys,
// in [RFC5656] for "ecdsa-sha2-*" keys and in [I-D.ietf-curdle-ssh-ed25519] for "ssh-ed25519" keys.
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

int serfd = -1;
char sockname[4096];
int flag_verbose = 0;

/* This is precached _public_ keys, dont worry */
char *precached_keys[MAX_PRECACHED_KEYS];
uint32_t precached_keys_len[MAX_PRECACHED_KEYS];

struct __attribute__((__packed__)) agent_msghdr {
        uint32_t message_len;
        uint8_t message_type;
        uint8_t message_contents[];
};

/* Keep disk space clean if killed, because we create sockets in home directory */
void fncleanup (void) {
        if (sockname[0])
                unlink(sockname);
        /* Lock dongle! */
        if (serfd > 0)
                write(serfd, "Z", 1);
}

void intcleanup(int dummy) {
        exit(0);
}


   // Debugging function
   void rewritefile(char *name, char *buf, int len) {
        unlink(name);
        int wfd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        write(wfd, buf, len);
        close(wfd);
   }



void verbose_printf( const char* format, ... ) {
        va_list args;
        if (!flag_verbose)
          return;
        va_start( args, format );
        vfprintf( stdout, format, args );
        va_end( args );
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

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        while(1) {
                if (select(fd+1, &rfds, NULL, NULL, NULL) > 0) {
                        n = read(fd, &buf[bytesdone], 1);
                        if (n <= 0) {
                                // TODO: show errno
                                perror("[read error] ");
                                return(-1);
                        }
                        bytesdone += n;
                        if (bytesdone == howmuch)
                                return(0);
                } else {
                        perror("[select error] ");
                        return(-1); // error happened
                }
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
        // disable IGNBRK for mismatched speed tests; otherwise receive break
        // as \000 chars
        tty.c_iflag &= ~IGNBRK;         // disable break processing
        tty.c_lflag = 0;                // no signaling chars, no echo,
                                        // no canonical processing
        tty.c_oflag = 0;                // no remapping, no delays
        tty.c_cc[VMIN]  = 0;            // read doesn't block
        tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

        tty.c_cflag |= (CLOCAL | CREAD); // ignore modem controls,
                                         // enable reading
        tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
        tty.c_cflag |= parity;
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;

        if (tcsetattr (fd, TCSANOW, &tty) != 0)
        {
                printf ("error %d from tcsetattr", errno);
                return -1;
        }
        return 0;
}

void precache_keys(void) {
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
                write(serfd, switchkey, 2);
                if (readexactly(serfd, 1, answer) < 0)
                        return;
                verbose_printf("Switched key %d\n", i);
                write(serfd, loadpubkey, 1);
                if (readexactly(serfd, 4, keybuf) < 0)
                        return;
                memcpy(&len, keybuf, 4);
                len = ntohl(len);
                verbose_printf("Signature length %d\n", len);
                if (len >= 4096 || len == 0)
                        break;
                if (readexactly(serfd, len, &keybuf[4]) < 0)
                        return;
                len += 4;
                precached_keys[i] = (char*)malloc(len);
                precached_keys_len[i] = len;
                memcpy(precached_keys[i], keybuf, len);
                verbose_printf("PRECACHED KEY %d\n", i);
        }

        /* switch back to 0 key, not essential but needed for development */
        switchkey[1] = '0';
        write(serfd, switchkey, 2);
        if (readexactly(serfd, 1, answer) < 0)
                return;
}

void set_blocking (int fd, int should_block) {
        struct termios tty;
        memset (&tty, 0, sizeof tty);
        if (tcgetattr (fd, &tty) != 0)
        {
                printf ("error %d from tggetattr", errno);
                return;
        }

        tty.c_cc[VMIN]  = should_block ? 1 : 0;
        tty.c_cc[VTIME] = 50;
        cfmakeraw(&tty);
        if (tcsetattr (fd, TCSANOW, &tty) != 0)
                printf ("error %d setting term attributes", errno);
}

/* including null */
#define VERLEN 6
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
        set_blocking(fd, 0);
        if (pincode) {
                int unlock_len = strlen(pincode) + 2;
                verbose_printf("[open_port] Entering PIN code\n");
                buffer = (char*)malloc(unlock_len);
                sprintf(buffer, "~%s~", pincode);
                ret = write(fd, buffer, unlock_len);
                free(buffer);
                if (ret != unlock_len) {
                        return(-1);
                }
        }
        if (checkanswer) {
                verbose_printf("[open_port] Checking dongle version\n");
                ret = write(fd, "V", 1);
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
  write(s, pd->buffer, pd->len);
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

void answer_signed(int s, char *buf, uint32_t len) {
        uint32_t keyblob_len;
        uint32_t signblob_len;
        uint8_t buffer[8192]; // TODO: dynamic
        struct packdata *pd = packdata_new();
        char *keyblob, *signblob;
        //char *dataforsign_ptr;
        int i;
        char signtype = 0;

        /* Extract key blob length */
        /* TODO: protect from invalid data length, damned LV/TLV */
        //memcpy(&keyblob_len, buf, 4);
        //keyblob_len = ntohl(keyblob_len);

        // skip total length header 4b
        keyblob = unpacklv(buf, len, &keyblob_len);
        if (!keyblob) {
          printf("Keyblob invalid\n");
          return;
        }


        signblob = unpacklv(keyblob+keyblob_len, len-keyblob_len, &signblob_len);
        if (!signblob) {
          printf("Signature invalid\n");
          return;
        }


        if (precached_keys_len[0]) {
                char *idstruct = keyblob;
                uint32_t idlen;
                memcpy(&idlen, keyblob, 4);
                if (ntohl(idlen) == 7 && !memcmp(idstruct+4, "ssh-rsa", 7)) {
                        verbose_printf("[answer_signed] searching in cached keys\n");
                        for (i=0; precached_keys_len[i]; i++) {
                                if (keyblob_len == precached_keys_len[i]-4 && !memcmp(keyblob, precached_keys[i]+4, precached_keys_len[i]-4)) {
                                        verbose_printf("[signing] match for key %d\n", i);
                                        char switchkey[] = "X0";
                                        switchkey[1] = '0' + i;
                                        write(serfd, switchkey, 2);
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
        write(serfd, "S", 1);

        // type of signature, SHA512 only for now
        write(serfd, &signtype, 1);

        // Write signblob together with length header
        verbose_printf("[answer_signed] PROVIDING DATA TO BE SIGNED\n");
        for (uint32_t i=0; i<signblob_len+4; i++) {
                write(serfd, signblob-4+i, 1);
        }

        verbose_printf("[answer_signed] READING SIGNED DATA HEADER 4b\n");
        for (int i = 0; i<4; i++) {
                read(serfd, &buffer[i], 1);
        }
        int total = ntohl(*((uint32_t*)buffer));
        verbose_printf("[answer_signed] READING SIGNED DATA REMAINDER %db\n", total);

        for (int i = 4; i<total+4; i++) {
                read(serfd, &buffer[i], 1);
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
        write(s, pd->buffer, pd->len);
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
                //packdata_del(pd2);
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
        write(serfd, "L", 1);

        // was 535
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
        readexactly(serfd, total, (char *)buffer); /* TODO: smart way readying with len */
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

void remove_newlines(char *data) {
        char *pos;
        if ((pos=strchr(data, '\r')) != NULL)
                *pos = '\0';
        if ((pos=strchr(data, '\n')) != NULL)
                *pos = '\0';
}

void config_dongle (void) {
        char input_stdin[128];
        unsigned char cfgbuffer[1024];
        char salt[64];
        unsigned char shainput[128];
        int rnd_dev_fd;

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

        /* Write 0x1 to start flashing process */
        input_stdin[0] = 0x1;
        write(serfd, input_stdin, 1);

        for (int i=0; i<1024; i++) {
                write(serfd, &cfgbuffer[i], 1); /* Single byte writes - safest */
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
        printf("  -a path\t\t Path and name to ask pass program (might work: ssh-askpass), will ask pass on each auth\n");
        printf("More information at: https://github.com/nuclearcat/cedarkey\n");
        exit(0);
}

int main(int argc, char **argv)
{
        int s, s2, t;
        struct sockaddr_un local, remote;
        char buf[65536];
        int c;
        int flag_cfgnew = 0, flag_reopen = 1, flag_daemon = 1;
        int keynum = -1;
        char rndpart[16];
        char *pincode = NULL;
        char *portname = NULL;
        char *keyfilename = NULL;
        char *askpass = NULL;
        char *password = NULL;

        signal(SIGINT, intcleanup);

        memset(sockname, 0x0, sizeof(sockname));
        /* Lock dongle on exit and cleanup unix socket file */
        atexit(fncleanup);

        /* Initialize precached keys array */
        for (int i = 0; i < MAX_PRECACHED_KEYS; i++) {
                precached_keys[i] = NULL;
                precached_keys_len[i] = 0;
        }

        while ((c = getopt (argc, argv, "hns:p:Dw:k:a:v")) != -1) {
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
                case 'd':
                        password = strdup(optarg);
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
                case 'a':
                        askpass = strdup(askpass);
                        break;
                case 'k':
                        keynum = atoi(optarg);
                        break;
                default:
                        exit(1);
                }
        }

        if (portname == NULL) {
                printf("Please specify device name for CedarKey\n");
                exit(1);
        }

        if (flag_cfgnew) {
                char buf[32];
                printf("Please make sure blue led is ON. If not, unplug dongle, and plug it back\n");
                printf("After that, press enter:");
                if (fgets (buf, 2, stdin) == NULL)
                        exit(1);
                serfd = open_port(portname, NULL, 0);
                if (serfd < 0) {
                  printf("Can't open device, exiting. \n");
                  printf("TIP: After plugging you need to wait a little, till modemmanager give up messing up with device\n");
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
        if (keynum == -1 && !keyfilename) {
                precache_keys();
        } else {
                char switchkey[] = "X0";
                if (keynum > 0 && keynum < 30)
                  switchkey[1] = '0' + keynum;
                write(serfd, switchkey, 2);
                readexactly(serfd, 1, switchkey);
                verbose_printf("Switched\n");
        }

        /* If password is set, give to dongle and erase it
           Problem: reconnecting dongle wont work
         */
        if (password) {
                write(serfd, "P", 1);
                write(serfd, password, strlen(password));
                write(serfd, "~", 1);
                memset(password, 0x0, strlen(password));
                free(password);
                password = NULL;
                flag_reopen = 0;
        }

        time_seed();
        rand_str(rndpart, 8);

        if (keyfilename) {
                int keyfd;
                char wrbuf[1];
                if (keynum != -1) {
                  printf("Free key will be selected automatically, you should not specify it\n");
                  exit(0);
                }
                keyfd = open(keyfilename, O_RDONLY);
                if (keyfd < 0) {
                        perror("key open error - ");
                        exit(2);
                }
                verbose_printf("[writing_key] Key file opened\n");
                write(serfd, "W", 1);
                verbose_printf("[writing_key] Write command issued\n");
                while (read(keyfd, wrbuf, 1)  == 1) {
                        verbose_printf("[writing_key] Write 1 byte of key\n");
                        write(serfd, wrbuf, 1);
                }
                verbose_printf("[writing_key] Final byte\n");
                write(serfd, "_", 1);
                close(keyfd);
                printf("Done, key is written\n");
                readexactly(serfd, 1, wrbuf); // read Y
                exit(1);
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

        if (listen(s, 1) == -1) {
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
                        if (keynum == -1)
                                precache_keys();
                        else {
                                char switchkey[] = "X0";
                                switchkey[1] = '0' + keynum;
                                write(serfd, switchkey, 2);
                                readexactly(serfd, 1, switchkey);
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

                // Anything on unix socket? If not, keep looping and checking serial state
                if (!isready(s, 1)) {
                        usleep(1);
                        continue;
                }

                t = sizeof(remote);
                if ((s2 = accept(s, (struct sockaddr *)&remote, (socklen_t *)&t)) == -1) {
                        perror("accept");
                        exit(1);
                }

                while (1) {
                        struct agent_msghdr agentmsg_begin;
                        if (readexactly(s2, 5, buf)) {
                                break;
                        }
                        memcpy(&agentmsg_begin, buf, 5);
                        agentmsg_begin.message_len = ntohl(agentmsg_begin.message_len);
                        if (agentmsg_begin.message_len > 1) {
                                if (readexactly(s2, agentmsg_begin.message_len-1, buf)) {
                                        break;
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
                                answer_fail(s2);
                                break;
                        }
                }
                close(s2);
        }

        return 0;
}
