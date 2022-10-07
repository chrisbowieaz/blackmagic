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

#ifndef PLATFORMS_HOSTED_PLATFORM_H
#define PLATFORMS_HOSTED_PLATFORM_H

#include "timing.h"

char *platform_ident(void);
void platform_buffer_flush(void);

#define PLATFORM_IDENT "(Black Magic Debug App) "
#define SET_IDLE_STATE(x)
#define SET_RUN_STATE(x)
#define PLATFORM_HAS_POWER_SWITCH

#define SYSTICKHZ 1000

#define VENDOR_ID_BMP     0x1d50
#define PRODUCT_ID_BMP_BL 0x6017
#define PRODUCT_ID_BMP    0x6018

#define VENDOR_ID_STLINK           0x0483
#define PRODUCT_ID_STLINK_MASK     0xffe0
#define PRODUCT_ID_STLINK_GROUP    0x3740
#define PRODUCT_ID_STLINKV1        0x3744
#define PRODUCT_ID_STLINKV2        0x3748
#define PRODUCT_ID_STLINKV21       0x374b
#define PRODUCT_ID_STLINKV21_MSD   0x3752
#define PRODUCT_ID_STLINKV3_NO_MSD 0x3754
#define PRODUCT_ID_STLINKV3_BL     0x374d
#define PRODUCT_ID_STLINKV3        0x374f
#define PRODUCT_ID_STLINKV3E       0x374e

#define VENDOR_ID_SEGGER 0x1366

typedef enum bmp_type_e {
	BMP_TYPE_NONE = 0,
	BMP_TYPE_BMP,
	BMP_TYPE_STLINKV2,
	BMP_TYPE_LIBFTDI,
	BMP_TYPE_CMSIS_DAP,
	BMP_TYPE_JLINK
} bmp_type_t;

void gdb_ident(char *p, int count);

#endif /* PLATFORMS_HOSTED_PLATFORM_H */
