/***************************************************************************//**
 * @file
 * @brief Silicon Labs iBeacon Demo Application
 * This application is intended to be used with the iOS and Android Silicon Labs
 * app for demonstration purposes
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include <stdint.h>

#include "init_mcu.h"
#include "init_board.h"
#include "init_app.h"
#include "ble-configuration.h"
#include "board_features.h"

/* BG stack headers */
#include "bg_types.h"
#include "native_gecko.h"
#include "gatt_db.h"
#include "infrastructure.h"

/* libraries containing default gecko configuration values */
#include "em_emu.h"
#include "em_cmu.h"

/* Device initialization header */
#include "hal-config.h"

#ifdef FEATURE_BOARD_DETECTED
#if defined(HAL_CONFIG)
#include "bsphalconfig.h"
#else
#include "bspconfig.h"
#endif
#endif

#include <stdio.h>
#include "retargetswo.h"
#include "app/ignition.h"

/***********************************************************************************************//**
 * @addtogroup Application
 * @{
 **************************************************************************************************/

/***********************************************************************************************//**
 * @addtogroup app
 * @{
 **************************************************************************************************/

#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 4
#endif
uint8_t bluetooth_stack_heap[DEFAULT_BLUETOOTH_HEAP(MAX_CONNECTIONS)];

/* Gecko configuration parameters (see gecko_configuration.h) */
static const gecko_configuration_t geckoconfig = {
  .config_flags = 0,
#if DEBUG_LEVEL == 0
  .sleep.flags = SLEEP_FLAGS_DEEP_SLEEP_ENABLE,
#else
  .sleep.flags = 0,
#endif // DEBUG
  .bluetooth.max_connections = MAX_CONNECTIONS,
  .bluetooth.max_advertisers = 2,
  .bluetooth.heap = bluetooth_stack_heap,
  .bluetooth.sleep_clock_accuracy = 100, // ppm
  .bluetooth.heap_size = sizeof(bluetooth_stack_heap),
  .gattdb = &bg_gattdb_data,
#if (HAL_PA_ENABLE)
  .pa.config_enable = 1, // Set this to be a valid PA config
#if defined(FEATURE_PA_INPUT_FROM_VBAT)
  .pa.input = GECKO_RADIO_PA_INPUT_VBAT, // Configure PA input to VBAT
#else
  .pa.input = GECKO_RADIO_PA_INPUT_DCDC,
#endif // defined(FEATURE_PA_INPUT_FROM_VBAT)
#endif // (HAL_PA_ENABLE)

  .ota.flags = 0,
  .ota.device_name_len = 5,
  .ota.device_name_ptr = "MCIGN"
};

/**
 * @brief Function for creating a custom advertisement package
 *
 * The function builds the advertisement package according to Apple iBeacon specifications,
 * configures this as the device advertisement data and starts broadcasting.
 */
void bcnSetupAdvBeaconing(void)
{
  /* This function sets up a custom advertisement package according to iBeacon specifications.
   * The advertisement package is 30 bytes long. See the iBeacon specification for further details.
   */

  static struct {
    uint8_t flagsLen;     /* Length of the Flags field. */
    uint8_t flagsType;    /* Type of the Flags field. */
    uint8_t flags;        /* Flags field. */
    uint8_t mandataLen;   /* Length of the Manufacturer Data field. */
    uint8_t mandataType;  /* Type of the Manufacturer Data field. */
    uint8_t compId[2];    /* Company ID field. */
    uint8_t beacType[2];  /* Beacon Type field. */
    uint8_t uuid[16];     /* 128-bit Universally Unique Identifier (UUID). The UUID is an identifier for the company using the beacon*/
    uint8_t majNum[2];    /* Beacon major number. Used to group related beacons. */
    uint8_t minNum[2];    /* Beacon minor number. Used to specify individual beacons within a group.*/
    uint8_t txPower;      /* The Beacon's measured RSSI at 1 meter distance in dBm. See the iBeacon specification for measurement guidelines. */
  }
  bcnBeaconAdvData
    = {
    /* Flag bits - See Bluetooth 4.0 Core Specification , Volume 3, Appendix C, 18.1 for more details on flags. */
    2,  /* length  */
    0x01, /* type */
    0x04 | 0x02, /* Flags: LE General Discoverable Mode, BR/EDR is disabled. */

    /* Manufacturer specific data */
    26,  /* length of field*/
    0xFF, /* type of field */

    /* The first two data octets shall contain a company identifier code from
     * the Assigned Numbers - Company Identifiers document */
    /* 0x004C = Apple */
    { UINT16_TO_BYTES(0x004C) },

    /* Beacon type */
    /* 0x0215 is iBeacon */
    { UINT16_TO_BYTE1(0x0215), UINT16_TO_BYTE0(0x0215) },

    /* 128 bit / 16 byte UUID */
	"\x00h>'\xaaQC\xb7\xb8m\xe5\x88\x8f!\xb5\xa9",		// 00683e27-aa51-43b7-b86d-e5888f21b5a9

    /* Beacon major number */
    { UINT16_TO_BYTE1(34987), UINT16_TO_BYTE0(34987) },

    /* Beacon minor number */
    { 0, 0 },	// this will be filled in with LSB of bt addr

    /* The Beacon's measured RSSI at 1 meter distance in dBm */
    0xBA
    };

  // base minor number off LSB of bt addr
  const uint16_t *minor = (uint16_t*)gecko_cmd_system_get_bt_address();
  bcnBeaconAdvData.minNum[0] = UINT16_TO_BYTE1(*minor);
  bcnBeaconAdvData.minNum[1] = UINT16_TO_BYTE0(*minor);

  uint8_t len = sizeof(bcnBeaconAdvData);
  uint8_t *pData = (uint8_t*)(&bcnBeaconAdvData);

  /* Set 0 dBm Transmit Power */
  gecko_cmd_system_set_tx_power(0);

  /* Set custom advertising data */
  gecko_cmd_le_gap_bt5_set_adv_data(1, 0, len, pData);

  /* Set advertising parameters. 100ms advertisement interval.
   * The first two parameters are minimum and maximum advertising interval,
   * both in units of (milliseconds * 1.6). */
  gecko_cmd_le_gap_set_advertise_timing(1, 160, 160, 0, 0);

  /* Start advertising in user mode and enable connections */
  gecko_cmd_le_gap_start_advertising(1, le_gap_user_data, le_gap_non_connectable);
  //gecko_cmd_le_gap_start_advertising(0, le_gap_user_data, le_gap_connectable_scannable);
}

/**
 * @brief  Main function
 */
int main(void)
{
  // Initialize device
  initMcu();
  // Initialize board
  initBoard();
  // Initialize application
  initApp();

  // Initialize stack
  gecko_init(&geckoconfig);

  initDebug();

  while (1) {
    struct gecko_cmd_packet* evt;

    // Check for stack event.
    evt = gecko_wait_event();

    // Run application and event handler.
    switch (BGLIB_MSG_ID(evt->header)) {
      // This boot event is generated when the system boots up after reset.
      // Do not call any stack commands before receiving the boot event.
      case gecko_evt_system_boot_id:
        // Initialize iBeacon ADV data
    	debug("boot\n");
    	initIgnition();
        gecko_cmd_le_gap_start_advertising(0, le_gap_general_discoverable, le_gap_connectable_scannable);
        bcnSetupAdvBeaconing();
        break;

      case gecko_evt_le_connection_opened_id:
      {
    	  const int auth_timeout = 32768*5;		// 5 seconds
    	  const uint8_t conn_id = evt->data.evt_le_connection_opened.connection;
		  init_conn_info(conn_id);
		  gecko_cmd_hardware_set_lazy_soft_timer(auth_timeout, auth_timeout/10, conn_id, 1);
		  debug("connection opened\n");
		  if(++status.nConnections < MAX_CONNECTIONS)
			  gecko_cmd_le_gap_start_advertising(0, le_gap_general_discoverable, le_gap_connectable_scannable);
		  break;
      }

      case gecko_evt_hardware_soft_timer_id:
      {
		  const uint8_t conn_id = evt->data.evt_hardware_soft_timer.handle;
		  if(!conn_info[conn_id].authenticated){
			  debug("disconnecting unauthenticated client\n");
			  gecko_cmd_le_connection_close(conn_id);
		  }
    	  break;
      }

      case gecko_evt_le_connection_closed_id:
      {
    	  debug("conn closed\n");
    	  if(status.boot_to_ota){
			// Enter to OTA DFU mode
			gecko_cmd_system_reset( 2 );
    	  }
    	  else{
			  // close client connection
			  close_conn_info(evt->data.evt_le_connection_closed.connection);
			  status.nConnections--;
    	  }
		  break;
      }

      case gecko_evt_gatt_server_attribute_value_id:
    	  debug("got msg\n");
    	  //debug("got msg: \"%s\"\n", evt->data.evt_gatt_server_attribute_value.value.data);
    	  decode_msg(evt->data.evt_gatt_server_attribute_value.value.data, evt->data.evt_gatt_server_attribute_value.value.len, evt->data.evt_gatt_server_attribute_value.connection);
    	  break;

      case gecko_evt_gatt_server_user_write_request_id:
    	  debug("got write request\n");
    	  // TODO: change data type to user to increase available command buf size
    	  decode_msg(evt->data.evt_gatt_server_user_write_request.value.data, evt->data.evt_gatt_server_user_write_request.value.len, evt->data.evt_gatt_server_attribute_value.connection);
    	  break;

      case gecko_evt_gatt_server_characteristic_status_id:
    	  debug("char status: %d %d\n", evt->data.evt_gatt_server_characteristic_status.status_flags, evt->data.evt_gatt_server_characteristic_status.client_config_flags);
    	  break;

      case gecko_evt_gatt_server_execute_write_completed_id:
    	  debug("exec write\n");
    	  break;

      default:
    	  debug("got unknown command: %x\n", BGLIB_MSG_ID(evt->header));
        break;
    }
  }
}

/** @} (end addtogroup app) */
/** @} (end addtogroup Application) */
