/*
    Copyright 2018,2019 Austin Haigh

    This file is part of MCIGN.

    MCIGN is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    MCIGN is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MCIGN.  If not, see <https://www.gnu.org/licenses/>.

*/


/*
 * ignition.c
 *
 *  Created on: Mar 8, 2019
 *      Author: Austin
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gatt_db.h"

#include "native_gecko.h"

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/cipher.h"

#include "b64.h"
#include "ignition.h"
#include "commands.h"
#include "crypto.h"

struct ConnInfo conn_info[256] = {0};
struct MainConfig config = {0};
struct KeyConfig key_config[MAX_KEYS] = {0};
struct Status status = {0};

void save_config(){
	struct gecko_msg_flash_ps_save_rsp_t *res = gecko_cmd_flash_ps_save(PS_MAIN_CONFIG, sizeof(struct MainConfig), (uint8_t*)&config);
	if(res->result){
		debug("Error saving main config block: %04x\n", res->result);
	}
}

// this function is only run the first time the device boots (if config.magic isn't set)
void first_boot(){
	debug("First boot...\n");

#if DEBUG_LEVEL
	struct KeyConfig masterkey = {0};
	if(decode_keys(&masterkey, TEST_MASTER_KEYS))
		debug("error decoding master keys\n");
	struct gecko_msg_flash_ps_save_rsp_t *res = gecko_cmd_flash_ps_save(PS_KEY_CONFIG(0), sizeof(struct KeyConfig), (uint8_t*)&masterkey);
	if(res->result)
		debug("error saving master keys\n");
	else
		set_registered_key(0, 1);

	config.magic = CONFIG_MAGIC;
	save_config();

#endif
}

void initIgnition(){
	debug("Starting MCIGN...\n");
	//gecko_cmd_flash_ps_erase_all();

	struct gecko_msg_flash_ps_load_rsp_t *res = gecko_cmd_flash_ps_load(PS_MAIN_CONFIG);
	if(res->result == 0x0502)	// if key not found
		first_boot();
	else {
		if(res->value.len != sizeof(struct MainConfig))
			debug("Invalid size for saved config\n");
		else if(*(int32_t*)res->value.data != CONFIG_MAGIC)
			debug("Invalid magic number for saved config\n");

		// unrecoverable error...
		//debug("Unrecoverable error...\n");
		//while(1);

		memcpy(&config, res->value.data, sizeof(struct MainConfig));
	}

	// load saved keys
	for(int i=0;i<MAX_KEYS;i++)
		if(get_registered_key(i))
			memcpy(&key_config[i], get_keys(i), sizeof(struct KeyConfig));

	GPIO_PinModeSet(IGN_GPIO_PORT, IGN_GPIO_PIN, gpioModePushPull, IGN_GPIO_OFF);
	GPIO_PortOutSetVal(IGN_GPIO_PORT, IGN_GPIO_OFF<<IGN_GPIO_PIN, 1<<IGN_GPIO_PIN);

	if(!get_registered_key(0)){
		debug("ERROR: master key not registered!\n");
		while(1);	// TODO: load master keys from serial
	}
}

void close_conn_info(uint8_t conn){
	memset(&conn_info[conn], 0, sizeof(struct ConnInfo));
}

void init_conn_info(uint8_t conn){
	conn_info[conn].authenticated = 0;
}

void send_response(uint8_t keyid, const struct KeyConfig *keys, const char *resp, uint8_t connection){
	char buf[255];
	uint8_t iv[IV_SIZE], hmac[32], cipher[255];
	unsigned int cipherLen, bufLen, resp_len = strlen(resp);

	//debug("pt msg: \"%s\"\n",resp);

	char *msgAndCode=malloc(resp_len+8);
	memcpy(msgAndCode, resp, resp_len);
	sprintf(msgAndCode+resp_len, ":%d", get_next_code(keyid));

	debug("sending response: \"%s\"\n", msgAndCode);

    generate_iv(iv);
	char *b64Iv = b64_encode(iv, IV_SIZE);

	cipherLen = encrypt_cmd(cipher, msgAndCode, keys->aes, iv);
	char *b64Cipher = b64_encode(cipher, cipherLen);

	calculate_hmac(hmac, cipher, cipherLen, keys->sha, iv);
	char *b64Hmac = b64_encode(hmac, 32);

	//debug("%p != %p\n", b64Iv, b64Cipher);
	//debug("decrypted: \"%s\"\n", decrypt_cmd(cipher, cipherLen, keys->aes, iv));


	bufLen = snprintf(buf, sizeof(buf), "%s:%s:%s", b64Iv, b64Hmac, b64Cipher);

	if(bufLen >= 255){
		debug("!!Error!!: generated command is too long\n");
		return;
	}

	//debug("Encrypted response: %s\n", buf);

	gecko_cmd_gatt_server_send_characteristic_notification(connection, gattdb_out, bufLen, (uint8_t*)buf);

	free(b64Iv);
	free(b64Hmac);
	free(b64Cipher);
	free(msgAndCode);
}

void set_time_offset(time_t now) {
	struct gecko_msg_hardware_get_time_rsp_t *rtc_time = gecko_cmd_hardware_get_time();
	status.time_offset = now - rtc_time->seconds;
}

time_t get_local_time(){
	if(!status.time_offset)
		return 0;

	struct gecko_msg_hardware_get_time_rsp_t *rtc_time = gecko_cmd_hardware_get_time();
	return rtc_time->seconds + status.time_offset;
}

const struct KeyRule *get_rules(int psid){
	static const struct KeyRule none = {END_OF_LIST};

	struct gecko_msg_flash_ps_load_rsp_t *res = gecko_cmd_flash_ps_load(PS_RULE(psid));
	if(res->result)
		return &none;

	const struct KeyRule *rules = (const struct KeyRule*)res->value.data;
	int nrules = res->value.len/sizeof(struct KeyRule);

	if(rules[nrules-1].type != END_OF_LIST)
		return &none;

	return rules;
}

uint8_t check_rules(int id, int curfew, int expiration){
	if(key_config[id].rules_id)
		for(const struct KeyRule *rule = get_rules(key_config[id].rules_id);
				rule->type != END_OF_LIST;
				rule += sizeof(struct KeyRule))
			switch(rule->type){
			case CURFEW:
			{
				if(!curfew)
					break;

				time_t unixtime = get_local_time();
				struct tm *now = localtime(&unixtime);
				uint16_t min_since_midnight = now->tm_hour * 60 + now->tm_min;
				if(rule->rule.curfew.end > rule->rule.curfew.start){
					if(min_since_midnight >= rule->rule.curfew.start &&
							min_since_midnight < rule->rule.curfew.end)
						return 1;
				}
				else {
					if(min_since_midnight >= rule->rule.curfew.start ||
							min_since_midnight < rule->rule.curfew.end)
						return 1;
				}
				break;
			}
			case EXPIRATION:
				if(!expiration)
					break;

				if(rule->rule.expiration <= get_local_time()){
					del_keys(id);
					return 1;
				}
				break;
			default:
				return 1;
			}

	return 0;
}

int decode_msg(uint8_t *msg, uint8_t msgLen, uint8_t connection){
	// TODO: use msgLen to avoid buffer overflow
	// msg format: [key_id]:[iv]:[hmac]:[cipher]
	char *part[4], *cmd;
	unsigned int nparts = 1, cipherLen;

	part[0] = strtok((char*)msg, ":");
	while((part[nparts] = strtok(0, ":")) && nparts < 4)
		nparts++;

	if(nparts != 4){
		debug("BAD COMMAND: nparts = %d\n",nparts);
		return 1;
	}

	const int id = atoi((char*)msg);
	uint8_t *iv = b64_decode(part[1], strlen(part[1]));
	uint8_t *hmac = b64_decode(part[2], strlen(part[2]));
	uint8_t *cipher = b64_decode_ex(part[3], strlen(part[3]), &cipherLen);

	if(!get_registered_key(id)){
		debug("key ID not valid: %d\n", id);
		return 1;
	}

	struct KeyConfig *keys = &key_config[id];

	// verify hmac
	uint8_t calculated_hmac[32];
	calculate_hmac(calculated_hmac, cipher, cipherLen, keys->sha, iv);
	if(memcmp_constant_time(calculated_hmac, hmac, 32) != 0){
		debug("invalid hmac\n");
		return 1;
	}

	// decrypt the command:
	cmd = decrypt_cmd(cipher, cipherLen, keys->aes, iv);
	if(!cmd){
		debug("error decrypting\n");
		return 1;
	}

	// the keys worked, set the new key id
	conn_info[connection].keyid = id;

	return handle_command(cmd, connection);
}
