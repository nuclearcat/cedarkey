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
uint32_t ticktock;

// Optional for testing code for overflows and etc
//#define TEST_SEQUENCE

#define KEYS_OFFSET (64*1024)
#define STATE_UNDEFINED 0
#define STATE_DEFAULT   1
#define STATE_PREWRITE  2
#define STATE_WRITE     3
#define STATE_PRESIGN   4
#define STATE_PRESIGN2  5

#define LOCKSTATE_LOCKED                     0
#define LOCKSTATE_UNLOCKED_FORSIGN_ONEKEY    1
#define LOCKSTATE_UNLOCKED_FORSIGN_ALLKEY    2
#define LOCKSTATE_UNLOCKED_FORWRITE          3

uint32_t stick_state = STATE_DEFAULT;
uint32_t lock_state = LOCKSTATE_LOCKED;
uint32_t bytes_written = 0;
char *keybuf;
char tmplenbuf[4];
uint32_t current_key_index = 0;
usbd_device *usbd_dev;

void pgm_prewrite_key (uint32_t);
void pgm_write_key (char *data, uint32_t len);
void pgm_read_key (uint32_t);
static const struct usb_device_descriptor dev = {
        .bLength = USB_DT_DEVICE_SIZE,
        .bDescriptorType = USB_DT_DEVICE,
        .bcdUSB = 0x0200,
        .bDeviceClass = USB_CLASS_CDC,
        .bDeviceSubClass = 0,
        .bDeviceProtocol = 0,
        .bMaxPacketSize0 = 64,
        .idVendor = 0x0483,
        .idProduct = 0x5740,
        .bcdDevice = 0x0200,
        .iManufacturer = 1,
        .iProduct = 2,
        .iSerialNumber = 3,
        .bNumConfigurations = 1,
};

/*
 * This notification endpoint isn't implemented. According to CDC spec its
 * optional, but its absence causes a NULL pointer dereference in Linux
 * cdc_acm driver.
 */
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
        .header = {
                .bFunctionLength = sizeof(struct usb_cdc_header_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_HEADER,
                .bcdCDC = 0x0110,
        },
        .call_mgmt = {
                .bFunctionLength =
                        sizeof(struct usb_cdc_call_management_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_CALL_MANAGEMENT,
                .bmCapabilities = 0,
                .bDataInterface = 1,
        },
        .acm = {
                .bFunctionLength = sizeof(struct usb_cdc_acm_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_ACM,
                .bmCapabilities = 0,
        },
        .cdc_union = {
                .bFunctionLength = sizeof(struct usb_cdc_union_descriptor),
                .bDescriptorType = CS_INTERFACE,
                .bDescriptorSubtype = USB_CDC_TYPE_UNION,
                .bControlInterface = 0,
                .bSubordinateInterface0 = 1,
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
        "SpineSystems SARL",
        "Security Key",
        "ALPHA00002",
};

/* Buffer to be used for control requests. */
uint8_t usbd_control_buffer[128];

/*
int mbedtls_hardware_poll( void *data,
                           unsigned char *output,
                           size_t len,
                           size_t *olen);
int mbedtls_hardware_poll( void *data,
                           unsigned char *output,
                           size_t len,
                           size_t *olen) {
        ((void) data);
        for( uint32_t i = 0; i < len; i++ )
                *(output+i)=i;
        *olen = len;
        return(0);
}
*/

static int cdcacm_control_request(usbd_device *usbd_dev_local, struct usb_setup_data *req, uint8_t **buf,
                                  uint16_t *len, void (**complete) (usbd_device *usbd_dev, struct usb_setup_data *req))
{
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

static int findkeylen(unsigned char *memptr) {
  int i;
  /* TODO: put in header if key present or not */
  for (i=0; i<4096; i++) {
          if (*(memptr+i) == 0x0) {
                  break;
          }
  }
  /* Key not found hack TODO: fix it */
  if (i == 4096)
    i = 0;
  return(i+1);
}

static void sign_data (uint32_t index) {
        unsigned char hash[64];
        mbedtls_pk_context pk;
        int n = 0;
        size_t outn;
        uint32_t start_address = 0x08000000 + 64*1024 + (index*4096);
        unsigned char* memory_ptr= (unsigned char*)start_address;

        mbedtls_sha512((unsigned char*)keybuf, bytes_written, hash, 0);
        /* Release memory early, we don't need this data anymore
           and we are very short on ram
        */
        free(keybuf);
        mbedtls_pk_init(&pk);
        {
                int i = findkeylen(memory_ptr);
                n = mbedtls_pk_parse_key(&pk, memory_ptr, i, NULL, 0);
        }
        if (!n) {
                char out[560]; /* TODO: put more precise value. Memory is scarce */
                mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA512, hash, 0, (unsigned char*)out, &outn, NULL, NULL);
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
        uint32_t start_address = 0x08000000 + KEYS_OFFSET + (index*4096);
        unsigned char* memory_ptr= (unsigned char*)start_address;
        int i = findkeylen(memory_ptr);

        while(usbd_ep_write_packet(usbd_dev, 0x82, "0", 1) == 0) ;
        while(usbd_ep_write_packet(usbd_dev, 0x82, "1", 1) == 0) ;
        mbedtls_pk_init(&pk);
        while(usbd_ep_write_packet(usbd_dev, 0x82, "2", 1) == 0) ;
        n = mbedtls_pk_parse_key(&pk, memory_ptr, i, NULL, 0);
        while(usbd_ep_write_packet(usbd_dev, 0x82, "3", 1) == 0) ;
        if (!n) {
                while(usbd_ep_write_packet(usbd_dev, 0x82, "4", 1) == 0) ;
                rsa = mbedtls_pk_rsa(pk);
                if (mbedtls_rsa_check_pubkey(rsa))
                        gpio_set(GPIOC, GPIO13);
                if (mbedtls_rsa_check_privkey(rsa))
                        gpio_set(GPIOC, GPIO13);
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

}
#endif

static int list_key (uint32_t index) {
        mbedtls_rsa_context *rsa;
        mbedtls_pk_context pk;
        int n;
        uint32_t start_address = 0x08000000 + KEYS_OFFSET + (index*4096);
        unsigned char* memory_ptr= (unsigned char*)start_address;
        int i = findkeylen(memory_ptr);
        mbedtls_pk_init(&pk);
        n = mbedtls_pk_parse_key(&pk, memory_ptr, i, NULL, 0);
        if (!n) {
                unsigned char buf[513];
                /* TODO: calculate total length depends on modulus length */
                rsa = mbedtls_pk_rsa(pk);

                /* TODO: Move ssh-rsa header to Linux program? */
                usb_write_packedlen(7);
                memcpy(buf, "ssh-rsa", 7);
                while(usbd_ep_write_packet(usbd_dev, 0x82, (unsigned char *)buf, 7) == 0) ;

                /* Exponent part */
                #define EXP_LEN 3
                usb_write_packedlen(EXP_LEN);
                mbedtls_mpi_write_binary(&rsa->E, buf, EXP_LEN);
                for (i=0; i<EXP_LEN; i++) {
                        while(usbd_ep_write_packet(usbd_dev, 0x82, &buf[i], 1) == 0) ;
                }
                /* Modulus part */
                usb_write_packedlen(rsa->N.n*4 + 1);

                /* Black magic of RSA, 00 means positive number */
                buf[0] = 0x0;
                while(usbd_ep_write_packet(usbd_dev, 0x82, buf, 1) == 0) ;

                mbedtls_mpi_write_binary(&rsa->N, buf, 512);
                for (size_t x=0; x<(rsa->N.n*4); x++) {
                        while(usbd_ep_write_packet(usbd_dev, 0x82, &buf[x], 1) == 0) ;
                }
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
        case STATE_WRITE:
          if (bytes_written == 4095 || byte == 0x0) {
            /* We dont have space anymore */
            stick_state = STATE_DEFAULT;
          }
          break;

        default:
          break;
      }
}

static void cdcacm_data_rx_cb(usbd_device *usbd_dev_local, uint8_t ep)
{
        (void)ep;
        (void)usbd_dev_local;

        char buf[68];         // We might need 4 bytes for remainder
        int len = usbd_ep_read_packet(usbd_dev_local, 0x01, buf, 64);

        if (len) {
                for (uint32_t i=0;i<len;i++) {
                  feed_rx_data(buf[i]);
                }
                if (stick_state == STATE_WRITE) {
                        if (bytes_written + len > 4096) {
                                len = 4096 - bytes_written;
                        }
                        int nullfound = 0;
                        /* Special replacement for NULL (_ as NULL)
                           This symbol is not used in base64/PEM
                           TODO: Make len 4 byte prefix for expected key length?
                           and don't forget to include final zero byte
                        */
                        for (int i = 0; i < len; i++) {
                                if (buf[i] == '_') {
                                        buf[i] = 0;
                                        nullfound = 1;
                                }
                        }

                        memcpy(&keybuf[bytes_written], buf, len);
                        bytes_written += len;
                        if (bytes_written == 4096 || nullfound) {
                                stick_state = STATE_DEFAULT;
                                pgm_write_key(keybuf, 4096);
                                free(keybuf);
                        }
                        usbd_ep_write_packet(usbd_dev_local, 0x82, "#", 1);
                }

                if (len == 1 && stick_state == STATE_PRESIGN2) {
                        uint32_t expected_data;
                        memcpy(&expected_data, tmplenbuf, 4);
                        expected_data = __builtin_bswap32(expected_data);
                        keybuf[bytes_written] = buf[0];
                        bytes_written++;
                        if (bytes_written == expected_data) {
                                if (bytes_written == (535-4))
                                  gpio_toggle(GPIOC, GPIO13);
                                sign_data(0);
                                bytes_written = 0;
                                stick_state = STATE_DEFAULT;
                        }
                }
                /* RXing data to sign */
                if (len == 1 && stick_state == STATE_PRESIGN) {
                        tmplenbuf[bytes_written] = buf[0];
                        bytes_written++;
                        if (bytes_written == 4) {
                                bytes_written = 0;
                                uint32_t expected_data;
                                memcpy(&expected_data, tmplenbuf, 4);
                                expected_data = __builtin_bswap32(expected_data);
                                if (expected_data < 1024) {
                                        keybuf = malloc(1024);
                                        stick_state = STATE_PRESIGN2;
                                } else {
                                        stick_state = STATE_DEFAULT;
                                }
                        }
                }
                /* Read key index position. Type 0 as 0, but after 9 things get complex, 10 is ":"
                   Hint: ASCII table
                */
                if (len == 1 && stick_state == STATE_PREWRITE) {
                        int idx = buf[0] - '0';
                        pgm_prewrite_key(idx);
                        stick_state = STATE_WRITE;
                        usbd_ep_write_packet(usbd_dev_local, 0x82, buf, len);
                        keybuf = malloc(4096);
                }

                if (len == 1 && stick_state == STATE_DEFAULT) {
                        char veranswer[] = "V1a\r\n";
                        int cmdok = 0;
                        switch(buf[0]) {
                        case 'V':
                                while(usbd_ep_write_packet(usbd_dev, 0x82, veranswer, strlen(veranswer)) == 0) ;
                                cmdok = 1;
                                break;
                        case 'W':
                                stick_state = STATE_PREWRITE;
                                cmdok = 1;
                                break;
                        case 'S':
                                bytes_written = 0;
                                stick_state = STATE_PRESIGN;
                                cmdok = 1;
                                break;
                        case 'R':
                                /* TODO: Read key index also */
                                pgm_read_key(0);
                                cmdok = 1;
                                break;
                        case 'L':
                                list_key(0);
                                cmdok = 1;
                                break;
#ifdef TEST_SEQUENCE
                        case 'T':
                                test_key(0);
                                cmdok = 1;
                                break;
#endif
                        default:
                                break;
                        }
                        if (!cmdok)
                          usbd_ep_write_packet(usbd_dev_local, 0x82, buf, len);
                }
        }
}

static void cdcacm_set_config(usbd_device *usbd_dev_local, uint16_t wValue)
{
        (void)wValue;
        (void)usbd_dev_local;

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

void pgm_read_key (uint32_t index) {
        uint32_t start_address = 0x08000000 + KEYS_OFFSET;
        uint8_t *memory_ptr= (uint8_t*)((uint32_t*)start_address + (index*4096));
        uint16_t i;

        for(i=0; i<4096; i++) {
                while (usbd_ep_write_packet(usbd_dev, 0x82, memory_ptr+i, 1) == 0) ;
                if (*(memory_ptr+i) == 0x0)
                        break;
        }
}

/* Erase pages where key will be stored */
void pgm_prewrite_key (uint32_t index) {
        uint32_t start_address = 0x08000000 + KEYS_OFFSET;
        uint32_t i;
        start_address += (index*4096);
        // TODO: Change this. 16 for "invisible" 64kb flash
        if (index > 9) {
                stick_state = STATE_DEFAULT;
        }
        flash_unlock();
        for (i=start_address; i<start_address+4096; i+=1024) {
                flash_erase_page(i);
                flash_wait_for_last_operation();
        }
        current_key_index = index;
        bytes_written = 0;
}

// Should be divisible by 4 byte!
void pgm_write_key (char *data, uint32_t len) {
        uint32_t start_address = 0x08000000 + 64*1024;
        uint32_t address_offset = 0;
        start_address += (current_key_index*4096);

        while(address_offset < len) {
                flash_program_word(start_address + address_offset, *((uint32_t*)(data + address_offset)));
                flash_wait_for_last_operation();
                address_offset += 4;
        }
        /* Send confirmation TODO: Maybe we don't need that? Or unify across the procedures */
        {
                  char buf[] = "!";
                  while (usbd_ep_write_packet(usbd_dev, 0x82, buf, 1) == 0) ;
        }
}

int main(void) {
        int i;
        uint32_t lastmsgtock = 0;

        rcc_clock_setup_in_hsi_out_48mhz();

        rcc_periph_clock_enable(RCC_GPIOC);
        rcc_periph_clock_enable(RCC_GPIOA);

        /* Hack for bluepill USB resistor issue */
        gpio_set_mode(GPIOA, GPIO_MODE_OUTPUT_2_MHZ,
                      GPIO_CNF_OUTPUT_PUSHPULL, GPIO12);
        /* LED for blinking */
        gpio_set_mode(GPIOC, GPIO_MODE_OUTPUT_2_MHZ,
                      GPIO_CNF_OUTPUT_PUSHPULL, GPIO13);

        gpio_clear(GPIOA, GPIO12);
        gpio_clear(GPIOC, GPIO13);
        for (i = 0; i < 800000; i++) {
                __asm__("nop");
        }

        usbd_dev = usbd_init(&st_usbfs_v1_usb_driver, &dev, &config, usb_strings, 3, usbd_control_buffer, sizeof(usbd_control_buffer));
        usbd_register_set_config_callback(usbd_dev, cdcacm_set_config);

        systick_set_clocksource(STK_CSR_CLKSOURCE_AHB_DIV8);
        systick_set_reload(8999);
        systick_interrupt_enable();
        systick_counter_enable();

        for (i = 0; i < 0x800000; i++)
                __asm__("nop");

        lastmsgtock = ticktock + 3000;
        while (1) {
                usbd_poll(usbd_dev);
                /* TODO: This called each second, put here timeouts for operations
                   Also detect "overshooting", as for example signing takes 10+ sec
                   for RSA4096/SHA512
                */
                if (ticktock - lastmsgtock > 1000) {
                        lastmsgtock = ticktock;
                }
        }
}
