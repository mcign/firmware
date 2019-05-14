/*
 * ignition.h
 *
 *  Created on: Mar 8, 2019
 *      Author: Austin
 */

#ifndef IGNITION_H_
#define IGNITION_H_

#include "assert.h"
#include <stdio.h>

#define DEBUG_LEVEL 1

#if DEBUG_LEVEL
#include "retargetswo.h"

#define initDebug() { \
		RETARGET_SwoInit(); \
	}
#define debug(...) printf(__VA_ARGS__)
#else
#define initDebug()
#define debug(...)
#endif

//#define KEYSTORE_MAGIC_NUMBER 0xBD99
#define AES_KEYSIZE 16
#define SHA_KEYSIZE 32
#define IV_SIZE 16

#define CONFIG_MAGIC 0x3d35

#define IGN_GPIO_PORT gpioPortA
#define IGN_GPIO_PIN 5
//#define IGN_GPIO_PORT gpioPortF
//#define IGN_GPIO_PIN 7
#define IGN_GPIO_OFF 1	// initial (off) value for ignition on boot
#define IGN_GPIO_ON (IGN_GPIO_OFF^1)

#define MAX_RULES 56/sizeof(struct KeyRule)	// max number of rules that can be stored in 1 key
#define MAX_KEYS 16

// config PS keys:
#define PS_KEY_CONFIG(id) (0x4000 | (id))
#define PS_KEY_NAME(id) (0x4000 | (MAX_KEYS+id))
#define PS_MAIN_CONFIG (0x4000 | (MAX_KEYS*2) )
#define PS_RULE(id) (0x4000 | (MAX_KEYS*2+1+id))

/////////////////////////////////////////////////////
// struct definitions:
/////////////////////////////////////////////////////

struct KeyRule {	// current size: 5 bytes
	enum {
		END_OF_LIST = 0,
		CURFEW,
		EXPIRATION
	} type;
	union {
		struct {
			uint16_t start;	// minutes past midnight to start curfew (key doesnt work during curfew)
			uint16_t end;	// minutes past midnight to end curfew
		} curfew;
		uint32_t expiration;	// unix timestamp of expiration date
	} rule;
};

struct KeyConfig {
	uint8_t limited : 1;
	uint8_t rules_id : 4;		// PS key of rules
	uint16_t next_code;		// every command is sent with a command code, if it is not > last_code then assume the command is being resent by an attacker
	unsigned char aes[AES_KEYSIZE];
	unsigned char sha[SHA_KEYSIZE];
};

struct MainConfig {
	int32_t magic;
	uint8_t registered_keys_bitmap[4];
};

struct CryptoKeys {
	unsigned char aes[AES_KEYSIZE];
	unsigned char sha[SHA_KEYSIZE];
};

struct Status {
	uint32_t time_offset;			// offset of hardware rtc
	uint8_t on : 1;
	uint8_t nConnections:3;
	uint8_t boot_to_ota:1;
};

struct ConnInfo{
	uint8_t authenticated : 1;
	uint8_t keyid : 4;
	uint8_t config_index : 2;
};

STATIC_ASSERT((sizeof(struct MainConfig) <= 56), "struct MainConfig can't be more than 56 bytes");
STATIC_ASSERT((sizeof(struct KeyConfig) <= 56), "struct DeviceConfig can't be more than 56 bytes");


/////////////////////////////////////////////////////
// extern variables:
/////////////////////////////////////////////////////

extern uint8_t iv_seed[SHA_KEYSIZE];		// this has to be 256 bits because the iv is generated with sha256

extern struct ConnInfo conn_info[256];
extern struct MainConfig config;
extern struct KeyConfig key_config[MAX_KEYS];
extern struct Status status;
extern struct Info info;

/////////////////////////////////////////////////////
// method declarations:
/////////////////////////////////////////////////////

int decode_msg(uint8_t *msg, uint8_t msgLen, uint8_t connection);
void initIgnition(void);
uint8_t check_rules(int id, int cur, int exp);
void save_config();
void close_conn_info(uint8_t);
void init_conn_info(uint8_t);
void set_time_offset(time_t now);
time_t get_local_time();
void send_response(uint8_t keyid, const struct KeyConfig *keys, const char *resp, uint8_t connection);

#endif /* IGNITION_H_ */
