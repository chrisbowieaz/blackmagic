/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2020-2021 Uwe Bonnes (bon@elektron.ikp.physik.tu-darmstadt.de)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PLATFORMS_HOSTED_BMP_HOSTED_H
#define PLATFORMS_HOSTED_BMP_HOSTED_H

#if HOSTED_BMP_ONLY != 1
#include <libusb.h>
#endif
#include "cli.h"
#include "platform.h"

#if HOSTED_BMP_ONLY != 1
struct trans_ctx {
#define TRANS_FLAGS_IS_DONE   (1 << 0)
#define TRANS_FLAGS_HAS_ERROR (1 << 1)
	volatile unsigned long flags;
};

typedef struct usb_link {
	libusb_context *ul_libusb_ctx;
	libusb_device_handle *ul_libusb_device_handle;
	uint8_t interface;
	uint8_t ep_tx;
	uint8_t ep_rx;
	struct libusb_transfer *req_trans;
	struct libusb_transfer *rep_trans;
	void *priv;
} usb_link_s;
#endif

typedef struct bmp_info {
	bmp_type_t bmp_type;
	char dev;
	char serial[64];
	char manufacturer[512];
	char product[256];
	char version[256];
	bool is_jtag;
	uint16_t vid;
	uint16_t pid;
#if HOSTED_BMP_ONLY != 1
	libusb_context *libusb_ctx;
	struct ftdi_context *ftdic;
	usb_link_s *usb_link;
	uint8_t interface_num;
	uint8_t in_ep;
	uint8_t out_ep;
#endif
} bmp_info_t;

extern bmp_info_t info;
void bmp_ident(bmp_info_t *info);
int find_debuggers(BMP_CL_OPTIONS_t *cl_opts, bmp_info_t *info);
void libusb_exit_function(bmp_info_t *info);

#if HOSTED_BMP_ONLY == 1
bool device_is_bmp_gdb_port(const char *device);
#else
int send_recv(usb_link_s *link, uint8_t *txbuf, size_t txsize, uint8_t *rxbuf, size_t rxsize);
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#include <wchar.h>
#define PRINT_INFO(fmt, ...) wprintf(L##fmt, ##__VA_ARGS__)
#else
#include <stdio.h>
#define PRINT_INFO(fmt, ...) printf((fmt), ##__VA_ARGS__)
#endif

#endif /* PLATFORMS_HOSTED_BMP_HOSTED_H */
