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
#include "probe_info.h"

#define NO_SERIAL_NUMBER "<no serial number>"

void get_orbtrace_version_string(struct libusb_device_descriptor *device_descriptor, libusb_device *device,
	libusb_device_handle *handle, char **product, char **manufacturer, char **serial, char **version);
void get_bmp_product_version_string(struct libusb_device_descriptor *device_descriptor, libusb_device *device,
	libusb_device_handle *handle, char **product, char **manufacturer, char **serial, char **version);

typedef struct debugger_device {
	uint16_t vendor;
	uint16_t product;
	bmp_type_t type;
	bool isCMSIS;
	void (*function)(
		struct libusb_device_descriptor *, libusb_device *, libusb_device_handle *, char **, char **, char **, char **);
	char *type_string;
} debugger_device_s;

//
// Create the list of debuggers BMDA works with
//
debugger_device_s debugger_devices[] = {
	{VENDOR_ID_BMP, PRODUCT_ID_BMP, BMP_TYPE_BMP, false, get_bmp_product_version_string, "Black Magic Probe"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV2, BMP_TYPE_STLINKV2, false, NULL, "ST-Link v2"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV21_MSD, BMP_TYPE_STLINKV2, false, NULL, "ST-Link v2.1 MSD"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3_NO_MSD, BMP_TYPE_STLINKV2, false, NULL, "ST-Link v2.1 No MSD"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3, BMP_TYPE_STLINKV2, false, NULL, "ST-Link v3"},
	{VENDOR_ID_STLINK, PRODUCT_ID_STLINKV3E, BMP_TYPE_STLINKV2, false, NULL, "ST-Link v3E"},
	{VENDOR_ID_SEGGER, PRODUCT_ID_UNKNOWN, BMP_TYPE_JLINK, false, NULL, "Segger JLink"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT2232, BMP_TYPE_LIBFTDI, false, NULL, "FTDI FT2232"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT4232, BMP_TYPE_LIBFTDI, false, NULL, "FTDI FT4232"},
	{VENDOR_ID_FTDI, PRODUCT_ID_FTDI_FT232, BMP_TYPE_LIBFTDI, false, NULL, "FTDI FT232"},
	{VENDOR_ID_ORBCODE, PRODUCT_ID_ORBTRACE, BMP_TYPE_CMSIS_DAP, true, get_orbtrace_version_string, "Orbtrace"},
	{0, 0, BMP_TYPE_NONE, false, NULL, ""},
};

bmp_type_t get_type_from_vid_pid(uint16_t probe_vid, uint16_t probe_pid)
{
	bmp_type_t probe_type = BMP_TYPE_NONE;
	for (size_t index = 0; debugger_devices[index].type != BMP_TYPE_NONE; index++) {
		if (probe_vid == debugger_devices[index].vendor && probe_pid == debugger_devices[index].product) {
			probe_type = debugger_devices[index].type;
			break;
		}
	}
	return probe_type;
}

void bmp_ident(bmp_info_s *info)
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

char *get_device_descriptor_string(libusb_device_handle *handle, uint16_t string_index)
{
	char read_string[128] = {0};
	if (string_index != 0) {
		libusb_get_string_descriptor_ascii(handle, string_index, (unsigned char *)read_string, sizeof(read_string));
	}
	return strdup(read_string);
}

//
// BMP Probes have there version in formation in the product string.
//
// Extract the product and version, skip the manufacturer string
//
void get_bmp_product_version_string(struct libusb_device_descriptor *device_descriptor, libusb_device *device,
	libusb_device_handle *handle, char **product, char **manufacturer, char **serial, char **version)
{
	(void)device;
	(void)serial;
	(void)manufacturer;
	char *start_of_version;
	*product = get_device_descriptor_string(handle, device_descriptor->iProduct);
	start_of_version = strrchr(*product, ' ');
	if (start_of_version == NULL) {
		version = NULL;
	} else {
		while (start_of_version[0] == ' ' && start_of_version != *product)
			--start_of_version;
		start_of_version[1] = '\0';
		start_of_version += 2;
		while (start_of_version[0] == ' ' && start_of_version[0] != '\0')
			++start_of_version;
		*version = strdup(start_of_version);
	}
}

void get_orbtrace_version_string(struct libusb_device_descriptor *device_descriptor, libusb_device *device,
	libusb_device_handle *handle, char **product, char **manufacturer, char **serial, char **version)
{	
	(void)device ;
	(void)device_descriptor ;
	(void)serial;
	(void)manufacturer;
	(void)product ;
	*version = get_device_descriptor_string(handle, 8);	// Version is in the #8 interface descriptor string
}

#if defined(_WIN32) || defined(__CYGWIN__)
probe_info_s *process_ftdi_probe(void)
{
	probe_info_s *probe_list = NULL;
	DWORD ftdiDevCount = 0;
	char *serial;
	char *manufacturer;
	char *product;

	FT_DEVICE_LIST_INFO_NODE *devInfo;
	if (FT_CreateDeviceInfoList(&ftdiDevCount) == FT_OK) {
		if ((devInfo = (FT_DEVICE_LIST_INFO_NODE *)malloc(sizeof(FT_DEVICE_LIST_INFO_NODE) * ftdiDevCount)) != NULL) {
			if (FT_GetDeviceInfoList(devInfo, &ftdiDevCount) == FT_OK) {
				//
				// Device list is loaded, iterate over the found probes
				//
				for (size_t devIndex = 0; devIndex < ftdiDevCount; devIndex++) {
					product = strdup(devInfo[devIndex].Description);
					serial = strdup(devInfo[devIndex].SerialNumber);
					size_t serial_len = strlen(serial);
					if (serial_len == 1) {
						free((void *)serial);
						serial = strdup("Unknown serial");
					} else {
						serial_len -= 1;
						if (*(serial + serial_len) == 'A') {
							*(serial + serial_len) = '\0';
						}
					}
					manufacturer = strdup("FTDI");
					probe_list = probe_info_add(probe_list, BMP_TYPE_LIBFTDI, manufacturer, product, serial, "---");
				}
			}
			free((void *)devInfo);
		} else {
			DEBUG_WARN("process_ftdi_probe: memory allocation failed\n");
		}
	}
	return probe_list;
}
#endif

void orbtrace_read_version(libusb_device *device, libusb_device_handle *handle, char *version, size_t buffer_size)
{
	libusb_config_descriptor_s *config;
	if (libusb_get_active_config_descriptor(device, &config) == 0) {
		for (size_t iface = 0; iface < config->bNumInterfaces; ++iface) {
			const libusb_interface_s *interface = &config->interface[iface];
			for (int descriptorIndex = 0; descriptorIndex < interface->num_altsetting; ++descriptorIndex) {
				const libusb_interface_descriptor_s *descriptor = &interface->altsetting[descriptorIndex];
				uint8_t string_index = descriptor->iInterface;
				if (string_index == 0)
					continue;
				if (libusb_get_string_descriptor_ascii(handle, string_index, (unsigned char *)version, buffer_size) < 0)
					continue; /* We failed but that's a soft error at this point. */

				if (strstr(version, "Version") != NULL) {
					break;
				}
			}
		}
	}
}

bool process_cmsis_interface_probe(
	libusb_device_descriptor_s *device_descriptor, libusb_device *device, probe_info_s **probe_list)
{
	(void)device_descriptor;
	(void)device;
	(void)probe_list;
	char *serial;
	char *manufacturer;
	char *product;
	libusb_device_handle *handle;
	bool cmsis_dap = false;

	libusb_config_descriptor_s *config;

	if (libusb_get_active_config_descriptor(device, &config) == 0 && libusb_open(device, &handle) == 0) {
		char read_string[128];

		for (size_t iface = 0; iface < config->bNumInterfaces && !cmsis_dap; ++iface) {
			const libusb_interface_s *interface = &config->interface[iface];
			for (int descriptorIndex = 0; descriptorIndex < interface->num_altsetting; ++descriptorIndex) {
				const libusb_interface_descriptor_s *descriptor = &interface->altsetting[descriptorIndex];
				uint8_t string_index = descriptor->iInterface;
				if (string_index == 0)
					continue;
				if (libusb_get_string_descriptor_ascii(
						handle, string_index, (unsigned char *)read_string, sizeof(read_string)) < 0)
					continue; /* We failed but that's a soft error at this point. */

				if (strstr(read_string, "CMSIS") != NULL) {
					if (device_descriptor->iSerialNumber == 0) {
						serial = strdup("Unknown serial number");
					} else {
						serial = get_device_descriptor_string(handle, device_descriptor->iSerialNumber);
					}
					if (device_descriptor->iManufacturer == 0) {
						manufacturer = strdup("Unknown manufacturer");
					} else {
						manufacturer = get_device_descriptor_string(handle, device_descriptor->iManufacturer);
					}
					if (device_descriptor->iProduct == 0) {
						product = strdup("Unknown product");
					} else {
						product = get_device_descriptor_string(handle, device_descriptor->iProduct);;
					}
					*probe_list = probe_info_add(*probe_list, BMP_TYPE_CMSIS_DAP, manufacturer, product, serial, "---");
					cmsis_dap = true;
				}
			}
		}
		libusb_close(handle);
	}
	return cmsis_dap;
}

bool process_vid_pid_table_probe(
	libusb_device_descriptor_s *device_descriptor, libusb_device *device, probe_info_s **probe_list)
{
	(void)device;
	libusb_device_handle *handle;
	bool probe_added = false;
	char *serial = NULL;
	char *manufacturer = NULL;
	char *product = NULL;
	char *version;
	bmp_type_t probe_type;
	ssize_t vid_pid_index = 0;
	while (debugger_devices[vid_pid_index].type != BMP_TYPE_NONE) {
		if (device_descriptor->idVendor == debugger_devices[vid_pid_index].vendor &&
			(device_descriptor->idProduct == debugger_devices[vid_pid_index].product ||
				debugger_devices[vid_pid_index].product == PRODUCT_ID_UNKNOWN)) {
			if (libusb_open(device, &handle) == 0) {
				probe_type = get_type_from_vid_pid(device_descriptor->idVendor, device_descriptor->idProduct);
				//
				// If the probe has a custom string reader installed, use it first.
				//
				// This will read and process any strings that need special work, e.g., extracting
				// a version string from a product string (BMP native)
				if (debugger_devices[vid_pid_index].function != NULL) {
					debugger_devices[vid_pid_index].function(
						device_descriptor, device, handle, &product, &manufacturer, &serial, &version);
				}
				//
				// Now read any strings that have not been set by a custom reader function
				//
				if (product == NULL) {
					product = get_device_descriptor_string(handle, device_descriptor->iProduct);
				}
				if (manufacturer == NULL) {
					manufacturer = get_device_descriptor_string(handle, device_descriptor->iManufacturer);
				}
				if (serial == NULL) {
					serial = get_device_descriptor_string(handle, device_descriptor->iSerialNumber);
				}

				*probe_list = probe_info_add(*probe_list, probe_type, manufacturer, product, serial, version);
				probe_added = true;
			}
			libusb_close(handle);
			break;
		}
		vid_pid_index++;
	}
	return probe_added;
}

static const probe_info_s *scan_for_devices(void)
{
	libusb_device **device_list;
	libusb_device_descriptor_s device_descriptor;
	// libusb_device_descriptor_s *known_device_descriptor;
	libusb_device *device;
	// libusb_device_handle *handle = NULL;
	probe_info_s *probe_list = NULL;
	// probe_info_s *added_probe = NULL;
	// libusb_config_descriptor_s *config = NULL;

	int result;
	ssize_t cnt;
	size_t deviceIndex = 0;
	bool skipFTDI = false;
	//
	// If we are running on Windows the proprietory FTD2XX library is used
	// to collect debugger information.
	//
#if defined(_WIN32) || defined(__CYGWIN__)
	if ((probe_list = process_ftdi_probe()) != NULL) {
		skipFTDI = true;
	}
#else
	skipFTDI = false;
#endif
	result = libusb_init(NULL);
	if (result == 0) {
		cnt = libusb_get_device_list(NULL, &device_list);
		if (cnt > 0) {
			// Parse the list of USB devices found

			while ((device = device_list[deviceIndex++]) != NULL) {
				result = libusb_get_device_descriptor(device, &device_descriptor);
				if (result < 0) {
					result = fprintf(stderr, "failed to get device descriptor");
					return (probe_info_s *)NULL;
				}
				if (device_descriptor.idVendor != VENDOR_ID_FTDI || skipFTDI == false) {
					if (process_vid_pid_table_probe(&device_descriptor, device, &probe_list) == false) {
						process_cmsis_interface_probe(&device_descriptor, device, &probe_list);
					}
				}
			}
			libusb_free_device_list(device_list, 1);
		}
		libusb_exit(NULL);
	}
	return probe_info_correct_order(probe_list);
}

int find_debuggers(bmda_cli_options_s *cl_opts, bmp_info_s *info)
{
	(void)cl_opts;
	(void)info;
	if (cl_opts->opt_device)
		return 1;
	/* Scan for all possible probes on the system */
	const probe_info_s *probe_list = scan_for_devices();
	if (!probe_list) {
		DEBUG_WARN("No probes found\n");
		return -1;
	}
	size_t position = 1;
	while (probe_list != NULL) {
		DEBUG_WARN("%d. %-20s %-20s %-25s %s\n", position++, probe_list->product, probe_list->serial,
			probe_list->manufacturer, probe_list->version);
		probe_list = probe_list->next;
	}
	return 1;
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
