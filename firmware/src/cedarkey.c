/*
 * CedarKey firmware (STM32F1)
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

/*
 * STM32 serial?
 * uint16 *idBase0 =  (uint16 *) (0x1FFFF7E8);
 * uint16 *idBase1 =  (uint16 *) (0x1FFFF7E8+0x02);
 * uint32 *idBase2 =  (uint32 *) (0x1FFFF7E8+0x04);
 * uint32 *idBase3 =  (uint32 *) (0x1FFFF7E8+0x08);
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/flash.h>
#include <libopencm3/cm3/systick.h>
#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/cdc.h>
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/sha512.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "common.h"
volatile uint32_t ticktock;

// Optional for testing code for overflows and etc
#define TEST_SEQUENCE

// Enable this if you want to protect from potential timing attack
// But it will make key signing much slower
//#define TIMING_PROTECTION

// THIS COMPROMISES SECURITY!!!!
// Do not enable it unless you are doing debugging, it makes device insecure!
//#define ALLOW_READING_KEY

// Disable JTAG/SWD on run
// Soon also enable readout protection
// Not tested yet!
//#define PROTECT_HARDER

/* We need to read/write protect 28 pages, 0-27 */
#define FLASH_ADDRESS             0x08000000
#define KEYS_OFFSET               (56*1024)
#define CFG_OFFSET                (55*1024)
#define CFG_SALT_OFFSET           4
#define CFG_USERPIN_HASH_OFFSET   68
#define CFG_ADMINPIN_HASH_OFFSET  132
#define CFG_SIZES_OFFSET          196


#define STATE_UNLOCKING       0
#define STATE_DEFAULT         1
#define STATE_PREWRITE        2
#define STATE_WRITE           3
#define STATE_PRESIGNBLOCKED  4
#define STATE_PRESIGN         5
#define STATE_PRESIGN2        6
#define STATE_PRESIGN3        7
#define STATE_KEYSELECT       8
#define STATE_GETPASS         9
#define STATE_BLOCKED         252
#define STATE_EMPTY           253
#define STATE_CONFIGWRITE     254

#define LOCKSTATE_LOCKED                     0
#define LOCKSTATE_UNLOCKED_FORSIGN_ONEKEY    1
#define LOCKSTATE_UNLOCKED_FORSIGN_ALLKEY    2
#define LOCKSTATE_UNLOCKED_FORWRITE          3

uint32_t stick_state = STATE_DEFAULT;
uint32_t bytes_written = 0;
char *bigbuf = NULL;
char tmplenbuf[4];
unsigned char *password;
uint32_t current_key_index = 0;
usbd_device *usbd_dev;
uint32_t signature_type = 0;

//static void pgm_prewrite_key (uint32_t);
static void pgm_write_key (char *data, uint32_t len);
static void pgm_config(char *);
#ifdef ALLOW_READING_KEY
static void pgm_read_key (uint32_t);
#pragma message ("YOU HAVE INSECURE CONFIGURATION! REMOVE ALLOW_READING_KEY AS ITS FOR DEBUGGING ONLY")
#endif

static const struct usb_device_descriptor dev = {
        .bLength = USB_DT_DEVICE_SIZE,
        .bDescriptorType = USB_DT_DEVICE,
        .bcdUSB = 0x0200,
        .bDeviceClass = USB_CLASS_CDC,
        .bDeviceSubClass = 0,
        .bDeviceProtocol = 0,
        .bMaxPacketSize0 = 64,
        .idVendor = 0xf055,
        .idProduct = 0x0001,
        .bcdDevice = 0x0200,
        .iManufacturer = 1,
        .iProduct = 2,
        .iSerialNumber = 3,
        .bNumConfigurations = 1,
};

static const struct usb_endpoint_descriptor comm_endp[] = {{
                                                                   .bLength = USB_DT_ENDPOINT_SIZE,
                                                                   .bDescriptorType = USB_DT_ENDPOINT,
                                                                   .bEndpointAddress = 0x83,
                                                                   .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
                                                                   .wMaxPacketSize = 16,
                                                                   .bInterval = 255,
                                                           }};

static const struct usb_endpoint_descriptor data_endp[] = {{
                                                                   .bLength = USB_DT_ENDPOINT_SIZE,
                                                                   .bDescriptorType = USB_DT_ENDPOINT,
                                                                   .bEndpointAddress = 0x01,
                                                                   .bmAttributes = USB_ENDPOINT_ATTR_BULK,
                                                                   .wMaxPacketSize = 64,
                                                                   .bInterval = 1,
                                                           }, {
                                                                   .bLength = USB_DT_ENDPOINT_SIZE,
                                                                   .bDescriptorType = USB_DT_ENDPOINT,
                                                                   .bEndpointAddress = 0x82,
                                                                   .bmAttributes = USB_ENDPOINT_ATTR_BULK,
                                                                   .wMaxPacketSize = 64,
                                                                   .bInterval = 1,
                                                           }};

static const struct {
        struct usb_cdc_header_descriptor header;
        struct usb_cdc_call_management_descriptor call_mgmt;
        struct usb_cdc_acm_descriptor acm;
        struct usb_cdc_union_descriptor cdc_union;
} __attribute__((packed)) cdcacm_functional_descriptors = {
        .acm = {
                .bFunctionLength = sizeof(struct usb_cdc_acm_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_ACM,
                .bmCapabilities = 0,
        },
        .call_mgmt = {
                .bFunctionLength =
                        sizeof(struct usb_cdc_call_management_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_CALL_MANAGEMENT,
                .bmCapabilities = 0,
                .bDataInterface = 1,
        },
        .cdc_union = {
                .bFunctionLength = sizeof(struct usb_cdc_union_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_UNION,
                .bControlInterface = 0,
                .bSubordinateInterface0 = 1,
        },

        .header = {
                .bFunctionLength = sizeof(struct usb_cdc_header_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_HEADER,
                .bcdCDC = 0x0110,
        },
};

static const struct usb_interface_descriptor comm_iface[] = {{
                                                                     .bLength = USB_DT_INTERFACE_SIZE,
                                                                     .bDescriptorType = USB_DT_INTERFACE,
                                                                     .bInterfaceNumber = 0,
                                                                     .bAlternateSetting = 0,
                                                                     .bNumEndpoints = 1,
                                                                     .bInterfaceClass = USB_CLASS_CDC,
                                                                     .bInterfaceSubClass = USB_CDC_SUBCLASS_ACM,
                                                                     .bInterfaceProtocol = USB_CDC_PROTOCOL_AT,
                                                                     .iInterface = 0,

                                                                     .endpoint = comm_endp,

                                                                     .extra = &cdcacm_functional_descriptors,
                                                                     .extralen = sizeof(cdcacm_functional_descriptors),
                                                             }};

static const struct usb_interface_descriptor data_iface[] = {{
                                                                     .bLength = USB_DT_INTERFACE_SIZE,
                                                                     .bDescriptorType = USB_DT_INTERFACE,
                                                                     .bInterfaceNumber = 1,
                                                                     .bAlternateSetting = 0,
                                                                     .bNumEndpoints = 2,
                                                                     .bInterfaceClass = USB_CLASS_DATA,
                                                                     .bInterfaceSubClass = 0,
                                                                     .bInterfaceProtocol = 0,
                                                                     .iInterface = 0,

                                                                     .endpoint = data_endp,
                                                             }};

static const struct usb_interface ifaces[] = {{
                                                      .num_altsetting = 1,
                                                      .altsetting = comm_iface,
                                              }, {
                                                      .num_altsetting = 1,
                                                      .altsetting = data_iface,
                                              }};

static const struct usb_config_descriptor config = {
        .bLength = USB_DT_CONFIGURATION_SIZE,
        .bDescriptorType = USB_DT_CONFIGURATION,
        .wTotalLength = 0,
        .bNumInterfaces = 2,
        .bConfigurationValue = 1,
        .iConfiguration = 0,
        .bmAttributes = 0x80,
        .bMaxPower = 0x32,
        .interface = ifaces,
};

static const char *usb_strings[] = {
        "Denys Fedoryshchenko",
        "CedarKey Dongle",
        "BETA1",
};

/* Buffer to be used for control requests. */
uint8_t usbd_control_buffer[128];

static void send_ok (void) {
        char buf[] = "Y";
        while (usbd_ep_write_packet(usbd_dev, 0x82, buf, 1) == 0) ;
}

static void send_error (void) {
        char buf[] = "E";
        while (usbd_ep_write_packet(usbd_dev, 0x82, buf, 1) == 0) ;
}

/* Pseudorandom */
static int blinker_random (void) {
  unsigned char tmpbuf[128];
  unsigned char hash[32];
  uint32_t ticktock_now = ticktock;
  uint32_t start_address = FLASH_ADDRESS + CFG_OFFSET;
  unsigned char* salt_ptr= (unsigned char*)start_address+CFG_SALT_OFFSET;
  memcpy(tmpbuf, salt_ptr, 64);
  memcpy(&tmpbuf[64], &ticktock_now, 4);
  mbedtls_sha256((unsigned char*)bigbuf, 128, hash, 0);
  if ((hash[0] % 6) == 0)
    return(6);
  else
    return(hash[0] % 6);
}

static int cdcacm_control_request(usbd_device *usbd_dev_local, struct usb_setup_data *req, uint8_t **buf,
                                  uint16_t *len, void (**complete) (usbd_device *usbd_dev, struct usb_setup_data *req)) {
        (void)complete;
        (void)buf;
        (void)usbd_dev_local;

        switch (req->bRequest) {
        case USB_CDC_REQ_SET_CONTROL_LINE_STATE: {
                /*
                 * This Linux cdc_acm driver requires this to be implemented
                 * even though it's optional in the CDC spec, and we don't
                 * advertise it in the ACM functional descriptor.
                 */
                char local_buf[10];
                struct usb_cdc_notification *notif = (void *)local_buf;

                /* We echo signals back to host as notification. */
                notif->bmRequestType = 0xA1;
                notif->bNotification = USB_CDC_NOTIFY_SERIAL_STATE;
                notif->wValue = 0;
                notif->wIndex = 0;
                notif->wLength = 2;
                local_buf[8] = req->wValue & 3;
                local_buf[9] = 0;
                // usbd_ep_write_packet(0x83, buf, 10);
                return 1;
        }
        case USB_CDC_REQ_SET_LINE_CODING:
                if (*len < sizeof(struct usb_cdc_line_coding))
                        return 0;
                return 1;
        }
        return 0;
}

static void usb_write_packedlen(uint32_t len) {
        uint32_t network_order_len = 0;
        network_order_len = __builtin_bswap32(len);
        while(usbd_ep_write_packet(usbd_dev, 0x82, &network_order_len, 4) == 0) ;
}

static uint32_t findkeyoffset(uint32_t index) {
        uint32_t key_size_address = FLASH_ADDRESS + CFG_OFFSET + CFG_SIZES_OFFSET;
        uint32_t i;
        uint32_t sum_offset = 0;
        uint32_t *sz_key;

        for (i=0; i<index; i++) {
                sz_key = (uint32_t*)(key_size_address+i*4);
                if (*sz_key == UINT_MAX)
                        return(0);
                sum_offset += *sz_key;
        }
        return(sum_offset);
}

static uint32_t findkeylen(uint32_t index) {
        uint32_t key_size_address = FLASH_ADDRESS + CFG_OFFSET + CFG_SIZES_OFFSET + (index*4);
        uint32_t *sz_key = (uint32_t*)key_size_address;
        return(*sz_key);
}

static void walktofreekey(void) {
        uint32_t key_size_address = FLASH_ADDRESS + CFG_OFFSET + CFG_SIZES_OFFSET;
        uint32_t *sz_key;
        for (int i=0; i<128; i++) {
                sz_key = (uint32_t*)(key_size_address+i*4);
                if (*sz_key == UINT_MAX) {
                        current_key_index = i;
                        break;
                }
        }
}

/*
   Config structure as follows:

   0x0 - 0x4 option word (uint32_t) - 0xFFFFFFFF - config not written
    0 bit - if unset - config ok
    1 bit - enable access timeout (TODO)
    etc...
   0x4 - 0x44 salt string for pin code
   0x44 - 0x84 pin code salted hash (SHA512)
 */

static void cfg_read (void *data, uint32_t len, uint32_t offset) {
        uint32_t start_address = FLASH_ADDRESS + CFG_OFFSET + offset;
        unsigned char* memory_ptr= (unsigned char*)start_address;
        memcpy(data, memory_ptr, len);
}

static int verify_pin(unsigned char *data, uint32_t len) {
        uint32_t start_address = FLASH_ADDRESS + CFG_OFFSET;
        unsigned char* salt_ptr= (unsigned char*)start_address+CFG_SALT_OFFSET;
        unsigned char* verification_saltedhash_ptr= (unsigned char*)start_address+CFG_USERPIN_HASH_OFFSET;

        unsigned char input[128];
        unsigned char output[64];
        memset(input, 0x0, 128);
        /* Hashing [salt,entered_pin,0x0 padding] */
        memcpy(input, salt_ptr, 64);
        memcpy(input+64, data, len);
        mbedtls_sha512((unsigned char*)input, 128, output, 0);
        memset(input, 0x0, 128);
        // TODO: timing attack protection (as it might weaken - with power analysis can know if pin correct or no)
        return(memcmp(output, verification_saltedhash_ptr, 64));
}

// mbedtls_pk_get_type

static void sign_data_rsa (uint32_t index) {
        unsigned char hash[64];
        mbedtls_pk_context pk;
        int n = 0;
        size_t outn;
        //uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + (index*4096);
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + findkeyoffset(index);
        unsigned char* memory_ptr= (unsigned char*)start_address;

        if (signature_type == 0)
                mbedtls_sha512((unsigned char*)bigbuf, bytes_written, hash, 0);
        else
                mbedtls_sha256((unsigned char*)bigbuf, bytes_written, hash, 0);
        /* Release memory early, we don't need this data anymore
           and we are very short on ram
         */
        free(bigbuf);
        bigbuf = NULL;
        mbedtls_pk_init(&pk);
        {
                uint32_t i = findkeylen(index);
                if (!start_address || i == UINT_MAX) {
                        mbedtls_pk_free(&pk);
                        return;
                }
                n = mbedtls_pk_parse_key(&pk, memory_ptr, i, password, strlen((char*)password));
        }
        if (!n) {
                char out[560]; /* TODO: put more precise value. Memory is scarce */
#ifdef TIMING_PROTECTION
                uint32_t starttock = ticktock;
                // TODO: Add handling of counter rollover. Do we really expect stick to stay 49 days?
#endif
                if (signature_type == 0)
                        mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA512, hash, 0, (unsigned char*)out, &outn, NULL, NULL);
                else
                        mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)out, &outn, NULL, NULL);
#ifdef TIMING_PROTECTION
                while (ticktock < starttock + 15000) ;
#endif
                usb_write_packedlen(outn);
                for (size_t i=0; i<outn; i++) {
                        while(usbd_ep_write_packet(usbd_dev, 0x82, &out[i], 1) == 0) ;
                }
        }
        mbedtls_pk_free(&pk);
}


#ifdef TEST_SEQUENCE
static void test_key (uint32_t index) {
        mbedtls_rsa_context *rsa;
        mbedtls_pk_context pk;
        int n;
        char rndbuf[32];
        unsigned char hash[64];
        unsigned char out[512];
        size_t outn;
        //uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + (index*4096);
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + findkeyoffset(index);
        unsigned char* memory_ptr= (unsigned char*)start_address;
        uint32_t i = findkeylen(index);

        if (i == 0)
                send_error();
        while(usbd_ep_write_packet(usbd_dev, 0x82, "0", 1) == 0) ;
        if (i == UINT32_MAX)
                send_error();
        while(usbd_ep_write_packet(usbd_dev, 0x82, "1", 1) == 0) ;
        mbedtls_pk_init(&pk);
        while(usbd_ep_write_packet(usbd_dev, 0x82, "2", 1) == 0) ;
        n = mbedtls_pk_parse_key(&pk, memory_ptr, i, password, strlen((char*)password));
        while(usbd_ep_write_packet(usbd_dev, 0x82, "3", 1) == 0) ;
        if (!n) {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "U", 1) == 0) ;
                rsa = mbedtls_pk_rsa(pk);
                if (mbedtls_rsa_check_pubkey(rsa))
                        gpio_clear(GPIOC, GPIO13);
                if (mbedtls_rsa_check_privkey(rsa))
                        gpio_clear(GPIOC, GPIO13);
        } else {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "E", 1) == 0) ;
        }
        mbedtls_sha512((unsigned char*)rndbuf, 32, hash, 0);
        while(usbd_ep_write_packet(usbd_dev, 0x82, "H", 1) == 0) ;
        n = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA512, hash, 0, (unsigned char*)out, &outn, NULL, NULL);
        if (!n) {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "S", 1) == 0) ;
        } else {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "E", 1) == 0) ;
        }
        mbedtls_pk_free(&pk);
        walktofreekey();
        if (current_key_index > 30) {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "E", 1) == 0) ;
        } else {
                char rs[] = "0";
                rs[0]+=current_key_index;
                while(usbd_ep_write_packet(usbd_dev, 0x82, rs, 1) == 0) ;
        }
}
#endif

static int list_key (uint32_t index) {
        mbedtls_rsa_context *rsa;
        mbedtls_pk_context pk;
        int n;
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + findkeyoffset(index);
        unsigned char* memory_ptr= (unsigned char*)start_address;
        uint32_t i = findkeylen(index);

        if (i == UINT_MAX) {
          usb_write_packedlen(0);
          return(0);
        }

        mbedtls_pk_init(&pk);
        n = mbedtls_pk_parse_key(&pk, memory_ptr, i, password, strlen((char*)password));
        if (!n) {
                unsigned char buf[513];
                /* TODO: calculate total length depends on modulus length */
                rsa = mbedtls_pk_rsa(pk);

                #define EXP_LEN           3 // Exponent len
                #define RSA_HEADER_LEN    7 // RSA header

                // Whole packet size
                usb_write_packedlen((4 + rsa->N.n*4 + 1) + (4 + RSA_HEADER_LEN) + (4 + EXP_LEN));

                /* Why it's here? Because one day we might have other protocols */
                usb_write_packedlen(RSA_HEADER_LEN);
                while(usbd_ep_write_packet(usbd_dev, 0x82, "ssh-rsa", RSA_HEADER_LEN) == 0) ;

                /* Exponent part */
                usb_write_packedlen(EXP_LEN);
                mbedtls_mpi_write_binary(&rsa->E, buf, EXP_LEN);
                for (i=0; i<EXP_LEN; i++) {
                        while(usbd_ep_write_packet(usbd_dev, 0x82, &buf[i], 1) == 0) ;
                }

                /* Modulus part */
                usb_write_packedlen(rsa->N.n*4 + 1);

                /* Black magic of RSA? 00 prefix - means positive number */
                buf[0] = 0x0;
                while(usbd_ep_write_packet(usbd_dev, 0x82, buf, 1) == 0) ;

                if (mbedtls_mpi_write_binary(&rsa->N, buf, rsa->N.n*4)) {
                        send_error();
                }

                for (size_t x=0; x<(rsa->N.n*4); x++) {
                        while(usbd_ep_write_packet(usbd_dev, 0x82, &buf[x], 1) == 0) ;
                }
        } else {
                usb_write_packedlen(0); // This means nothing to send / error unpacking key
        }
        mbedtls_pk_free(&pk);
        return(n);
}

/* This part of code intentionally left for debugging purposes, in case of memory shortage issues */
/*
   void * _sbrk(int32_t incr)
   {
        extern char end;
        static char * heap_end;
        char *        prev_heap_end;
        if (heap_end == 0) {
                heap_end = &end;
        }
        char x[64];

        prev_heap_end = heap_end;
        heap_end += incr;
        sprintf(x, "grow %d 0x%X-0x%X(%d)\r\n",
                incr,
                (uint32_t)(&end),
                (uint32_t)(heap_end),
                (uint32_t)(heap_end) - (uint32_t)(&end));
        usbd_ep_write_packet(usbd_dev, 0x82, x, strlen(x));
        return (void *) prev_heap_end;
   }
 */

static void feed_rx_data(char byte) {
        switch(stick_state) {
        case STATE_UNLOCKING:
                // TODO: remove temporary termination symbol ~
                if (byte == 0x0 || byte == '~' || bytes_written == 64) {
                        // TODO: make it secure! timing attack!
                        if (strlen((char*)password) > 0 && !verify_pin(password, strlen((char*)password))) {
                                stick_state = STATE_DEFAULT;
                                free(password);
                                password = NULL;
                                bytes_written = 1; /* THIS IS SPECIAL STATE INDICATING KEY IS JUST UNLOCKED! */
                        } else {
                                memset(password, 0x0, 65);
                                bytes_written = 0;
                                // sleep for a while?
                        }
                } else {
                        password[bytes_written] = byte;
                        bytes_written++;
                }
                break;
        case STATE_GETPASS:
                bytes_written++;
                if (byte == 0x0 || byte == '~' || bytes_written == 64) {
                        // If we set password 0 length - free it
                        if (!bytes_written) {
                                free(password);
                                password = NULL;
                        }
                        stick_state = STATE_DEFAULT;
                        bytes_written = 0;
                } else {
                        password[bytes_written] = byte;
                        bytes_written++;
                }
                break;
        case STATE_KEYSELECT:
        {
                int idx = byte - '0';
                if (idx >= 0 && idx < 30) {
                        current_key_index = idx;
                        usbd_ep_write_packet(usbd_dev, 0x82, &byte, 1);
                }
        }
                stick_state = STATE_DEFAULT;
                break;

                /* I add this state because crappy systemd/modemmanager probe devices
                   and send garbage to them
                 */
#define FLASH_OBP_RDP   0x1FFFF800
#define FLASH_OBP_WRP10 0x1FFFF808
        case STATE_EMPTY:
                if (byte == 0x1) {
                        gpio_set(GPIOC, GPIO13);
                        stick_state = STATE_CONFIGWRITE;
#ifdef PROTECT_HARDER
                        flash_unlock();
                        flash_unlock_option_bytes();
                        flash_wait_for_last_operation();
                        flash_erase_option_bytes();
                        flash_program_option_bytes(FLASH_OBP_RDP, 0x0);
                        // Writeout protection as well TODO
#endif
                        flash_lock();
                }
                break;

        case STATE_CONFIGWRITE:
                bigbuf[bytes_written] = byte;
                bytes_written++;
                if (bytes_written == 1024) {
                        //stick_state = STATE_UNLOCKING;
                        stick_state = STATE_DEFAULT;
                        password = malloc(65);
                        memset(password, 0x0, 65);
                        pgm_config(bigbuf);
                        bytes_written = 0;
                        free(bigbuf);
                        bigbuf = NULL;

                }
                break;
        /* Write key to flash TODO: verify it with parse after writing? */
        case STATE_WRITE:
                // We signal end of key by _ symbol or 0, maybe better some other way?
                if (bytes_written == 4095 || byte == 0x0 || byte == '_') {
                        /* We dont have space anymore */
                        byte = 0x0; /* Final byte should be 0 */
                        bigbuf[bytes_written] = byte;
                        stick_state = STATE_DEFAULT;
                        bytes_written++;
                        // Round bytes
                        if (bytes_written % 4 != 0) {
                                uint32_t bytes = ((bytes_written / 4) * 4) + 4;
                                bytes_written = bytes;
                        }

                        pgm_write_key(bigbuf, bytes_written);
                        memset(bigbuf, 0x0, 4096);
                        free(bigbuf);
                        /* Final byte and write is done! */
                        usbd_ep_write_packet(usbd_dev, 0x82, "#", 1);
                } else {
                        bigbuf[bytes_written] = byte;
                        bytes_written++;
                        /* Show that we received byte and its not final */
                        usbd_ep_write_packet(usbd_dev, 0x82, "#", 1);
                }
                break;

        case STATE_PRESIGNBLOCKED:
        {
          if (byte - '0' != (uint8_t)bytes_written) {
            stick_state = STATE_BLOCKED;
          } else {
            stick_state = STATE_PRESIGN;
            gpio_clear(GPIOC, GPIO13); // it will be toggled during sign
            bytes_written = 0;
          }
        }
        break;
        case STATE_PRESIGN3:
        {        /* Len of data to sign received, proceed to receive this data */
                 /* Not efficient, each time, but i dont want one more static variable */
                uint32_t expected_data;
                memcpy(&expected_data, tmplenbuf, 4);
                expected_data = __builtin_bswap32(expected_data);

                bigbuf[bytes_written] = byte;
                bytes_written++;
                /* Is it last byte? sign and output result*/
                if (bytes_written == expected_data) {
                        gpio_toggle(GPIOC, GPIO13); // TODO: optional, change LED state to show we are in process of signing, mb make it blink?
                        if (signature_type == 0 || signature_type == 1)
                                sign_data_rsa(current_key_index);
                        bytes_written = 0;
                        stick_state = STATE_DEFAULT;
                }
                break;
        }
        /* Receive length of signature */
        case STATE_PRESIGN2:
        {
                tmplenbuf[bytes_written] = byte;
                bytes_written++;
                /* Are we done? */
                if (bytes_written == 4) {
                        uint32_t expected_data;
                        memcpy(&expected_data, tmplenbuf, 4);
                        expected_data = __builtin_bswap32(expected_data);
                        bytes_written = 0;
                        /* TODO: ssh usually send less than 1024 bytes,
                           need to be sure. We can't afford more anyway */
                        if (expected_data < 1024) {
                                bigbuf = malloc(1024);
                                stick_state = STATE_PRESIGN3;
                        } else {
                                stick_state = STATE_DEFAULT;
                        }
                }
        }
        break;
        /* Receive type of signature */
        case STATE_PRESIGN:
                signature_type = byte;
                if (signature_type != 0 && signature_type != 1) {
                        stick_state = STATE_DEFAULT;
                } else {
                        stick_state = STATE_PRESIGN2;
                }
                break;
        /* Receive key index and TODO: in future key len maybe */
        case STATE_DEFAULT:
        {
                char veranswer[] = "V1a-X";
                switch(byte) {
                /* Dongle ID */
                case 'V':
                        veranswer[4] = '0' + current_key_index;
                        while(usbd_ep_write_packet(usbd_dev, 0x82, veranswer, strlen(veranswer)) == 0) ;
                        break;
                /* Write key */
                case 'W':
                        /* This value has 1(magic value) only if it is just unlocked, otherwise don't allow write to avoid random key erasure
                           TODO: add separate admin PIN
                         */
                        if (bytes_written != 1)
                                break;
                        bytes_written = 0;
                        walktofreekey();
                        //pgm_prewrite_key(current_key_index);
                        stick_state = STATE_WRITE;
                        /* TODO such fat buffer maybe not necessary,
                           we can rewrite by writing 4 byte chunks */
                        bigbuf = malloc(4096);
                        memset(bigbuf, 0x0, 4096);
                        break;
                /* Select key index */
                case 'X':
                        stick_state = STATE_KEYSELECT;
                        break;
                /* Request signing (TODO: SHA256 option) */
                case 'S':
                        {
                          uint32_t cfg;
                          cfg_read(&cfg, 4, 0);
                          if (cfg & CFG_BIT_BLINKERLOCK) {
                            stick_state = STATE_PRESIGNBLOCKED;
                            bytes_written = blinker_random();
                          } else {
                            stick_state = STATE_PRESIGN;
                            bytes_written = 0;
                          }
                        }
                        break;
                /* Set password for unlocking keys */
                case 'P':
                        bytes_written = 0;
                        stick_state = STATE_GETPASS;
                        if (!password) {
                                password = malloc(65);
                                memset(password, 0x0, 65);
                        }
                        break;
                /* Lock dongle */
                case 'Z':
                        bytes_written = 0;
                        if (password)
                                free(password);
                        stick_state = STATE_UNLOCKING;
                        password = malloc(65);
                        memset(password, 0x0, 65);
                        break;
                /* Return public part of current key */
                case 'L':
                        list_key(current_key_index);
                        break;

                        /* TODO: ping, timeout? */
#ifdef ALLOW_READING_KEY
                /* WARNING! CRITICALLY INSECURE! DO NOT USE IT! */
                case 'R':
                        /* TODO: Read key index also */
                        pgm_read_key(current_key_index);
                        break;
#endif

#ifdef TEST_SEQUENCE
                /* Valid answer is: 0123UHS
                   S might take time to appear (15s on RSA4096)
                 */
                case 'T':
                        test_key(current_key_index);
                        break;
#endif
                }
        }
        break;
        default:
                break;
        }
}

static void cdcacm_data_rx_cb(usbd_device *usbd_dev_local, uint8_t ep)
{
        (void)ep;
        char buf[64];
        uint32_t len = usbd_ep_read_packet(usbd_dev_local, 0x01, buf, 64);

        if (len) {
                for (uint32_t i=0; i<len; i++) {
                        feed_rx_data(buf[i]);
                }
        }
}

static void cdcacm_set_config(usbd_device *usbd_dev_local, uint16_t wValue)
{
        (void)wValue;

        usbd_ep_setup(usbd_dev_local, 0x01, USB_ENDPOINT_ATTR_BULK, 64, cdcacm_data_rx_cb);
        usbd_ep_setup(usbd_dev_local, 0x82, USB_ENDPOINT_ATTR_BULK, 64, NULL);
        usbd_ep_setup(usbd_dev_local, 0x83, USB_ENDPOINT_ATTR_INTERRUPT, 16, NULL);
        usbd_register_control_callback(
                usbd_dev_local,
                USB_REQ_TYPE_CLASS | USB_REQ_TYPE_INTERFACE,
                USB_REQ_TYPE_TYPE | USB_REQ_TYPE_RECIPIENT,
                cdcacm_control_request);
}

void sys_tick_handler(void);
void sys_tick_handler(void) {
        ticktock++;
}

#ifdef ALLOW_READING_KEY
// Debug and invalid
static void pgm_read_key (uint32_t index) {
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + (index * 4096);
        uint8_t *memory_ptr= (uint8_t*)((uint32_t*)start_address);

        uint16_t i;
        for(i=0; i<4096; i++) {
                while (usbd_ep_write_packet(usbd_dev, 0x82, memory_ptr+i, 1) == 0) ;
                if (*(memory_ptr+i) == 0x0)
                        break;
        }
}
#endif

/* TODO: larger flashes has page >1024. Handle that correctly! */
static void pgm_config(char *data) {
        uint32_t start_address = FLASH_ADDRESS + CFG_OFFSET;
        uint32_t address_offset = 0;
        flash_erase_page(start_address);
        flash_unlock();
        /* Program only until sizes */
        while(address_offset < CFG_SIZES_OFFSET) {
                flash_program_word(start_address + address_offset, *((uint32_t*)(data + address_offset)));
                address_offset += 4;
        }
        flash_lock();
}

/*
  Leave for future, when we gain capability of rewriting/erasing keys
 */
 /*
static void pgm_prewrite_key (uint32_t index) {
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET +findkeyoffset(index);
        uint32_t i;
        // TODO: Change this. 16 for "invisible" 64kb flash
        if (index > 9) {
                stick_state = STATE_DEFAULT;
                send_error();
                return;
        }
        flash_unlock();
        for (i=start_address; i<start_address+4096; i+=1024) {
                flash_erase_page(i);
                flash_wait_for_last_operation();
        }
}
*/

// Should be divisible by 4 byte!
static void pgm_write_key (char *data, uint32_t len) {
        uint32_t start_address = FLASH_ADDRESS + KEYS_OFFSET + findkeyoffset(current_key_index);
        uint32_t address_offset = 0;
        uint32_t key_size_address = FLASH_ADDRESS + CFG_OFFSET + CFG_SIZES_OFFSET + (current_key_index * 4);

        flash_unlock();
        while(address_offset < len) {
                flash_program_word(start_address + address_offset, *((uint32_t*)(data + address_offset)));
                address_offset += 4;
        }
        flash_program_word(key_size_address, len);
        flash_lock();
        send_ok();
}

int main(void) {
        uint32_t i;
        uint32_t lastmsgtock = 0;

        //rcc_clock_setup_in_hsi_out_48mhz();
        rcc_clock_setup_in_hse_8mhz_out_72mhz();

        rcc_periph_clock_enable(RCC_GPIOC);
        rcc_periph_clock_enable(RCC_GPIOA);
        rcc_periph_clock_enable(RCC_AFIO);

#ifdef PROTECT_HARDER
        gpio_primary_remap(AFIO_MAPR_SWJ_CFG_JTAG_OFF_SW_OFF, 0); // Disable JTAG/SWD
#endif

        /* Hack for bluepill USB resistor issue */
        gpio_set_mode(GPIOA, GPIO_MODE_OUTPUT_2_MHZ,
                      GPIO_CNF_OUTPUT_PUSHPULL, GPIO12);
        /* LED for blinking */
        gpio_set_mode(GPIOC, GPIO_MODE_OUTPUT_2_MHZ,
                      GPIO_CNF_OUTPUT_PUSHPULL, GPIO13);

        gpio_clear(GPIOA, GPIO12);


        for (i = 0; i < 800000; i++) {
                __asm__("nop");
        }
        /* Find out initial state
           TODO: find out also PIN-less config state
         */
        bytes_written = 0;
        {
                uint32_t cfg;
                cfg_read(&cfg, 4, 0);
                if (cfg == 0xFFFFFFFF && !bigbuf) {
                        stick_state = STATE_EMPTY;
                        bigbuf = malloc(1024);
                        gpio_clear(GPIOC, GPIO13);
                } else {
                        /* Initial state */
                        stick_state = STATE_UNLOCKING;
                        password = malloc(65);
                        memset(password, 0x0, 65);
                        gpio_set(GPIOC, GPIO13);
                }
        }

        usbd_dev = usbd_init(&st_usbfs_v1_usb_driver, &dev, &config, usb_strings, 3, usbd_control_buffer, sizeof(usbd_control_buffer));
        usbd_register_set_config_callback(usbd_dev, cdcacm_set_config);

        /* 72MHz / 8 => 9000000 counts per second TODO: fix 1 second slice */
        systick_set_clocksource(STK_CSR_CLKSOURCE_AHB_DIV8);
        systick_set_reload(8999);
        systick_interrupt_enable();
        systick_counter_enable();

        for (i = 0; i < 0x800000; i++)
                __asm__("nop");

        lastmsgtock = ticktock + 3000;
        i = 0;
        while (1) {
                usbd_poll(usbd_dev);
                /* TODO: This called each second, put here timeouts for operations
                   TODO: detect "overshooting", as for example signing takes 10+ sec
                   for RSA4096/SHA512
                 */
                if (ticktock - lastmsgtock > 500) {
                        lastmsgtock = ticktock;
                        if (stick_state == STATE_BLOCKED) {
                          gpio_toggle(GPIOC, GPIO13);
                        }
                        if (stick_state == STATE_PRESIGNBLOCKED && bytes_written) {
                            if (i < bytes_written * 2) {
                              gpio_toggle(GPIOC, GPIO13);
                            } else if (i > bytes_written*2+2) {
                              i = 0;
                              gpio_toggle(GPIOC, GPIO13);
                            }
                            i++;
                        } else {
                          i = 0;
                        }
                }
        }
}
