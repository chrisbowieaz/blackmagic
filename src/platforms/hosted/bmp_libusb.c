/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright(C) 2020 - 2022 Uwe Bonnes (bon@elektron.ikp.physik.tu-darmstadt.de)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Find all known usb connected debuggers */
#include "general.h"
#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#include <stdint.h>

#include "ftd2xx.h"
#else
#include <libusb.h>
#include "libftdi1/ftdi.h"
#endif
#include "cli.h"
#include "ftdi_bmp.h"
#include "version.h"

#define NO_SERIAL_NUMBER "<no serial number>"

typedef struct debuggerDevice {
	uint16_t vendor;
	uint16_t product;
	bmp_type_t type;
	bool isCMSIS;
	char *typeString;
} DEBUGGER_DEVICE;

/**
 * @brief Structure used to receive probe information from probe processing functions
 * 
 */
typedef struct probeInformation {
	char vid_pid[32];
	char probe_type[64];
	char serial_number[64];
} PROBE_INFORMATION;

#define MAX_PROBES 32
/**
 * @brief Array of probe inforatiokn structures for the currently attached probes.
 * 
 */
static PROBE_INFORMATION probes[MAX_PROBES];
//
// Create the list of debuggers BMDA works with
//
DEBUGGER_DEVICE debuggerDevices[] = {
	{VENDOR_ID_BMP, PRODUCT_ID_BMP, BMP_TYPE_BMP, false, "Black Magic Probe"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV2, BMP_TYPE_STLINKV2, false, "ST-Link v2"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV21, BMP_TYPE_STLINKV2, false, "ST-Link v2.1"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV21_MSD, BMP_TYPE_STLINKV2, false, "ST-Link v2.1 MSD"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3_NO_MSD, BMP_TYPE_STLINKV2, false, "ST-Link v2.1 No MSD"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3, BMP_TYPE_STLINKV2, false, "ST-Link v3"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3E, BMP_TYPE_STLINKV2, false, "ST-Link v3E"},
	{VENDOR_ID_SEGGER, PRODUCT_ID_UNKNOWN, BMP_TYPE_JLINK, false, "Segger JLink"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT2232, BMP_TYPE_LIBFTDI, false, "FTDI FT2232"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT4232, BMP_TYPE_LIBFTDI, false, "FTDI FT4232"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT232, BMP_TYPE_LIBFTDI, false, "FTDI FT232"},
	{0, 0, BMP_TYPE_NONE, false, ""},
};

void bmp_ident(bmp_info_t *info)
{
	PRINT_INFO("Black Magic Debug App %s\n for Black Magic Probe, ST-Link v2 and v3, CMSIS-DAP,"
			   " JLink and libftdi/MPSSE\n",
		FIRMWARE_VERSION);
	if (info && info->vid && info->pid) {
		PRINT_INFO("Using %04x:%04x %s %s\n %s\n", info->vid, info->pid,
			(info->serial[0]) ? info->serial : NO_SERIAL_NUMBER, info->manufacturer, info->product);
	}
}

void libusb_exit_function(bmp_info_s *info)
{
	if (!info->usb_link)
		return;
	libusb_free_transfer(info->usb_link->req_trans);
	libusb_free_transfer(info->usb_link->rep_trans);
	if (info->usb_link->ul_libusb_device_handle) {
		libusb_release_interface(info->usb_link->ul_libusb_device_handle, 0);
		libusb_close(info->usb_link->ul_libusb_device_handle);
	}
}

// static bmp_type_e find_cmsis_dap_interface(libusb_device *dev, bmp_info_s *info)
// {
// 	bmp_type_t type = BMP_TYPE_NONE;

// 	libusb_config_descriptor_s *conf;
// 	char interface_string[128];

// 	int res = libusb_get_active_config_descriptor(dev, &conf);
// 	if (res < 0) {
// 		DEBUG_WARN("WARN: libusb_get_active_config_descriptor() failed: %s", libusb_strerror(res));
// 		return type;
// 	}

// 	libusb_device_handle *handle;
// 	res = libusb_open(dev, &handle);
// 	if (res != LIBUSB_SUCCESS) {
// 		DEBUG_INFO("INFO: libusb_open() failed: %s\n", libusb_strerror(res));
// 		libusb_free_config_descriptor(conf);
// 		return type;
// 	}

// 	for (int i = 0; i < conf->bNumInterfaces; i++) {
// 		const struct libusb_interface_descriptor *interface = &conf->interface[i].altsetting[0];

// 		if (!interface->iInterface) {
// 			continue;
// 		}

// 		res = libusb_get_string_descriptor_ascii(
// 			handle, interface->iInterface, (uint8_t *)interface_string, sizeof(interface_string));
// 		if (res < 0) {
// 			DEBUG_WARN("WARN: libusb_get_string_descriptor_ascii() failed: %s\n", libusb_strerror(res));
// 			continue;
// 		}

// 		if (!strstr(interface_string, "CMSIS")) {
// 			continue;
// 		}
// 		type = BMP_TYPE_CMSIS_DAP;

// 		if (interface->bInterfaceClass == 0xff && interface->bNumEndpoints == 2) {
// 			info->interface_num = interface->bInterfaceNumber;

// 			for (int j = 0; j < interface->bNumEndpoints; j++) {
// 				uint8_t n = interface->endpoint[j].bEndpointAddress;

// 				if (n & 0x80) {
// 					info->in_ep = n;
// 				} else {
// 					info->out_ep = n;
// 				}
// 			}

// 			/* V2 is preferred, return early. */
// 			break;
// 		}
// 	}
// 	libusb_free_config_descriptor(conf);
// 	return type;
// }

#if defined(_WIN32) || defined(__CYGWIN__)
size_t process_ftdi_probe(PROBE_INFORMATION *probe_information)
{
	DWORD ftdiDevCount = 0;
	size_t devicesFound = 0;
	FT_DEVICE_LIST_INFO_NODE *devInfo;
	if (FT_CreateDeviceInfoList(&ftdiDevCount) == FT_OK) {
		if ((devInfo = (FT_DEVICE_LIST_INFO_NODE *)malloc(sizeof(FT_DEVICE_LIST_INFO_NODE) * ftdiDevCount)) != NULL) {
			if (FT_GetDeviceInfoList(devInfo, &ftdiDevCount) == FT_OK) {
				//
				// Device list is loaded, iterate over the found probes
				//
				for (size_t devIndex = 0; devIndex < ftdiDevCount; devIndex++) {
					memcpy(probe_information->probe_type, devInfo[devIndex].Description,
						strlen(devInfo[devIndex].Description));
					size_t serial_len = strlen(devInfo[devIndex].SerialNumber) - 1U;
					if (devInfo[devIndex].SerialNumber[serial_len] == 'A') {
						devInfo[devIndex].SerialNumber[serial_len] = '\0';
					}
					if (serial_len == 0) {
						memcpy(probe_information->serial_number, "Unknown", strlen("Unknown"));
					} else {
						memcpy(probe_information->serial_number, devInfo[devIndex].SerialNumber,
							strlen(devInfo[devIndex].SerialNumber));
					}
					devicesFound++;
					probe_information++;
				}
			}
		} else {
			printf("process_ftdi_probe: memory allocation failed\n");
		}
	}
	return devicesFound;
}
#endif

libusb_device_descriptor_s *device_check_for_cmsis_interface(libusb_device_descriptor_s *device_descriptor,
	libusb_device *device, libusb_device_handle *handle, PROBE_INFORMATION *probe_information)
{
	libusb_device_descriptor_s *result = NULL;
	libusb_config_descriptor_s *config;
	if (libusb_get_active_config_descriptor(device, &config) == 0 && libusb_open(device, &handle) == 0) {
		bool cmsis_dap = false;
		for (size_t iface = 0; iface < config->bNumInterfaces && !cmsis_dap; ++iface) {
			const libusb_interface_s *interface = &config->interface[iface];
			for (int descriptorIndex = 0; descriptorIndex < interface->num_altsetting; ++descriptorIndex) {
				const libusb_interface_descriptor_s *descriptor = &interface->altsetting[descriptorIndex];
				uint8_t string_index = descriptor->iInterface;
				if (string_index == 0)
					continue;
				//
				// Read back the string descriptor interpreted as ASCII (wrong but
				// easier to deal with in C)
				//
				if (libusb_get_string_descriptor_ascii(handle, string_index,
						(unsigned char *)probe_information->probe_type, sizeof(probe_information->probe_type)) < 0)
					continue; /* We failed but that's a soft error at this point. */
				if (strstr(probe_information->probe_type, "CMSIS") != NULL) {
					//
					// Read the serial number from the probe
					//
					string_index = device_descriptor->iSerialNumber;
					if (libusb_get_string_descriptor_ascii(handle, string_index,
							(unsigned char *)probe_information->serial_number,
							sizeof(probe_information->serial_number)) < 0)
						continue; /* We failed but that's a soft error at this point. */

					result = device_descriptor;
					cmsis_dap = true;
				} else {
					memset(probe_information->probe_type, 0x00, sizeof(probe_information->probe_type));
				}
			}
		}
		libusb_close(handle);
	}
	return result;
}

struct libusb_device_descriptor *device_check_in_vid_pid_table(
	struct libusb_device_descriptor *device_descriptor, libusb_device *device, PROBE_INFORMATION *probe_information)
{
	struct libusb_device_descriptor *result = NULL;
	libusb_device_handle *handle;
	ssize_t vid_pid_index = 0;
	while (debuggerDevices[vid_pid_index].type != BMP_TYPE_NONE) {
		if (device_descriptor->idVendor == debuggerDevices[vid_pid_index].vendor &&
			(device_descriptor->idProduct == debuggerDevices[vid_pid_index].product ||
				debuggerDevices[vid_pid_index].product == PRODUCT_ID_UNKNOWN)) {
			result = device_descriptor;
			memcpy(probe_information->probe_type, debuggerDevices[vid_pid_index].typeString,
				strlen(debuggerDevices[vid_pid_index].typeString));
			//
			// Default to unknown serial number, operations below may fail
			//
			memcpy(probe_information->serial_number, "Unknown", sizeof("Unknown"));
			if (libusb_open(device, &handle) == 0) {
				if (device_descriptor->iSerialNumber != 0) {
					libusb_get_string_descriptor_ascii(handle, device_descriptor->iSerialNumber,
						(unsigned char *)&probe_information->serial_number, sizeof(probe_information->serial_number));
				}
				libusb_close(handle);
			}
			break;
		}
		vid_pid_index++;
	}
	return result;
}

int scan_for_probes(void)
{
	libusb_device **device_list;
	libusb_device_descriptor_s device_descriptor;
	libusb_device_descriptor_s *known_device_descriptor;
	libusb_device *device;
	libusb_device_handle *handle = NULL;
	// struct libusb_config_descriptor *config = NULL;

	int result;
	ssize_t cnt;
	size_t deviceIndex = 0;
	size_t debuggerCount = 0;
	bool skipFTDI;
	//
	// If we are running on Windows the proprietory FTD2XX library is used
	// to collect debugger information.
	//
#if defined(_WIN32) || defined(__CYGWIN__)
	debuggerCount += process_ftdi_probe(probes);
	skipFTDI = true;
#else
	skipFTDI = false;
#endif
	result = libusb_init(NULL);
	if (result == 0) {
		cnt = libusb_get_device_list(NULL, &device_list);
		if (cnt > 0) {
			//
			// Parse the list of USB devices found
			//
			while ((device = device_list[deviceIndex++]) != NULL) {
				result = libusb_get_device_descriptor(device, &device_descriptor);
				memset(probes[debuggerCount].serial_number, 0x00, sizeof(probes[debuggerCount].serial_number));
				if (result < 0) {
					result = fprintf(stderr, "failed to get device descriptor");
					return -1;
				}
				if (device_descriptor.idVendor != VENDOR_ID_FTDI || skipFTDI == false) {
					if ((known_device_descriptor = device_check_in_vid_pid_table(
							 &device_descriptor, device, &probes[debuggerCount])) == NULL) {
						//
						// Check if there is a CMSIS interface on this device
						//
						known_device_descriptor = device_check_for_cmsis_interface(
							&device_descriptor, device, handle, &probes[debuggerCount]);
					}
					//
					// If we have a known device we can continue to report its data
					//
					if (known_device_descriptor != NULL) {
						if (device_descriptor.idVendor == VENDOR_ID_STLINK &&
							device_descriptor.idProduct == PRODUCT_ID_STLINKV2) {
							memcpy(probes[debuggerCount].serial_number, "Unknown", 8);
						}
						debuggerCount++;
					}
				}
			}
			libusb_free_device_list(device_list, 1);
		}
		//
		// Print the probes found
		//
		if (debuggerCount != 0) {
			for (size_t debugger_index = 0; debugger_index < debuggerCount; debugger_index++) {
				printf("%zu\t%-20s\tS/N: %s\n", debugger_index + 1, probes[debugger_index].probe_type,
					probes[debugger_index].serial_number);
			}
		} else {
			printf("No debug probes attached\n");
		}
		libusb_exit(NULL);
	}
	return result;
}

int find_debuggers(BMP_CL_OPTIONS_t *cl_opts, bmp_info_t *info)
{
	(void)cl_opts;
	(void)info;
	return scan_for_probes();
}

static void LIBUSB_CALL on_trans_done(libusb_transfer_s *const transfer)
{
	transfer_ctx_s *const ctx = transfer->user_data;

	if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
		DEBUG_WARN("on_trans_done: ");
		if (transfer->status == LIBUSB_TRANSFER_TIMED_OUT)
			DEBUG_WARN(" Timeout\n");
		else if (transfer->status == LIBUSB_TRANSFER_CANCELLED)
			DEBUG_WARN(" cancelled\n");
		else if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE)
			DEBUG_WARN(" no device\n");
		else
			DEBUG_WARN(" unknown\n");
		ctx->flags |= TRANSFER_HAS_ERROR;
	}
	ctx->flags |= TRANSFER_IS_DONE;
}

static int submit_wait(usb_link_s *link, libusb_transfer_s *transfer)
{
	transfer_ctx_s transfer_ctx;

	transfer_ctx.flags = 0;

	/* brief intrusion inside the libusb interface */
	transfer->callback = on_trans_done;
	transfer->user_data = &transfer_ctx;

	const libusb_error_e error = libusb_submit_transfer(transfer);
	if (error) {
		DEBUG_WARN("libusb_submit_transfer(%d): %s\n", error, libusb_strerror(error));
		exit(-1);
	}

	const uint32_t start_time = platform_time_ms();
	while (transfer_ctx.flags == 0) {
		timeval_s timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (libusb_handle_events_timeout(link->ul_libusb_ctx, &timeout)) {
			DEBUG_WARN("libusb_handle_events()\n");
			return -1;
		}
		const uint32_t now = platform_time_ms();
		if (now - start_time > 1000U) {
			libusb_cancel_transfer(transfer);
			DEBUG_WARN("libusb_handle_events() timeout\n");
			return -1;
		}
	}
	if (transfer_ctx.flags & TRANSFER_HAS_ERROR) {
		DEBUG_WARN("libusb_handle_events() | has_error\n");
		return -1;
	}

	return 0;
}

/* One USB transaction */
int send_recv(usb_link_s *link, uint8_t *txbuf, size_t txsize, uint8_t *rxbuf, size_t rxsize)
{
	int res = 0;
	if (txsize) {
		libusb_fill_bulk_transfer(link->req_trans, link->ul_libusb_device_handle, link->ep_tx | LIBUSB_ENDPOINT_OUT,
			txbuf, txsize, NULL, NULL, 0);
		size_t i = 0;
		DEBUG_WIRE(" Send (%3zu): ", txsize);
		for (; i < txsize; ++i) {
			DEBUG_WIRE("%02x", txbuf[i]);
			if ((i & 7U) == 7U)
				DEBUG_WIRE(".");
			if ((i & 31U) == 31U)
				DEBUG_WIRE("\n             ");
		}
		if (!(i & 31U))
			DEBUG_WIRE("\n");
		if (submit_wait(link, link->req_trans)) {
			libusb_clear_halt(link->ul_libusb_device_handle, link->ep_tx);
			return -1;
		}
	}
	/* send_only */
	if (rxsize != 0) {
		/* read the response */
		libusb_fill_bulk_transfer(link->rep_trans, link->ul_libusb_device_handle, link->ep_rx | LIBUSB_ENDPOINT_IN,
			rxbuf, rxsize, NULL, NULL, 0);

		if (submit_wait(link, link->rep_trans)) {
			DEBUG_WARN("clear 1\n");
			libusb_clear_halt(link->ul_libusb_device_handle, link->ep_rx);
			return -1;
		}
		res = link->rep_trans->actual_length;
		if (res > 0) {
			const size_t rxlen = (size_t)res;
			DEBUG_WIRE(" Rec (%zu/%zu)", rxsize, rxlen);
			for (size_t i = 0; i < rxlen && i < 32U; ++i) {
				if (i && ((i & 7U) == 0U))
					DEBUG_WIRE(".");
				DEBUG_WIRE("%02x", rxbuf[i]);
			}
		}
	}
	DEBUG_WIRE("\n");
	return res;
}
