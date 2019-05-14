/*
 * crypto.c
 *
 *  Created on: Apr 3, 2019
 *      Author: Austin
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gatt_db.h"

#include "native_gecko.h"

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/cipher.h"

#include "b64.h"
#include "crypto.h"

void set_registered_key(uint8_t id, uint8_t value){
	if(value)
		config.registered_keys_bitmap[id/8] |= 1<<(id%8);
	else
		config.registered_keys_bitmap[id/8] &= ~(1<<(id%8));
}

uint8_t get_registered_key(uint8_t id){
	if(!(config.registered_keys_bitmap[id/8] & (1<<(id%8))))
		return 0;

	// check if the key has expired
	if(check_rules(id, 0, 1)){
		del_keys(id);
		return 0;
	}

	return 1;
}

int decode_keys(struct KeyConfig *decoded, char *encoded){
	char *delim = strchr(encoded, ':');
	if(!delim){
		debug("Error: no separator found: \"%s\"\n", encoded);
		return 1;
	}

	uint8_t *aes = b64_decode(encoded, delim-encoded),
			*sha = b64_decode(delim+1, strlen(delim+1));

	if(!aes || !sha){
		debug("Base64 decode error\n");
		return 1;
	}

	memcpy(decoded->aes, aes, AES_KEYSIZE);
	memcpy(decoded->sha, sha, SHA_KEYSIZE);

	free(aes);
	free(sha);

	return 0;
}

void calculate_hmac(uint8_t *out, uint8_t *cipher, unsigned int cipherLen, const uint8_t *key, uint8_t *iv){
	// calculate hmac:
	mbedtls_md_context_t ctx;

	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx, key, SHA_KEYSIZE);
	mbedtls_md_hmac_update(&ctx, iv, IV_SIZE);
	mbedtls_md_hmac_update(&ctx, cipher, cipherLen);
	mbedtls_md_hmac_finish(&ctx, out);
	mbedtls_md_free(&ctx);
}

struct KeyConfig *get_keys(int id){
	if(!get_registered_key(id)){
		debug("Error: key %d not registered\n", id);
		return 0;
	}

	struct gecko_msg_flash_ps_load_rsp_t *res = gecko_cmd_flash_ps_load(0x4000 | id);
	if(res->result){
		debug("Error retrieving encryption key: %04x\n", res->result);
		return 0;
	}

	struct KeyConfig *keys = (struct KeyConfig*)&res->value.data;

	if (res->value.len == sizeof(struct KeyConfig))
		return keys;
	else
		return 0;
}

char *save_keys(struct KeyConfig *keys){
	static char buf[3];

	for(int i=0;i<MAX_KEYS;i++)
		if(!get_registered_key(i)){
			struct gecko_msg_flash_ps_save_rsp_t *sres = gecko_cmd_flash_ps_save(0x4000 | i, sizeof(struct KeyConfig), (uint8_t*)keys);
			if(sres->result){
				debug("Error saving encryption key: %04x\n", sres->result);
				return "0";
			}

			set_registered_key(i, 1);
			save_config();

			memcpy(&key_config[i], keys, sizeof(struct KeyConfig));

			snprintf(buf, sizeof(buf), "%d", i);
			return buf;
		}

	return "0";
}

int del_keys(int id){
	set_registered_key(id, 0);
	save_config();
	struct gecko_msg_flash_ps_erase_rsp_t *res = gecko_cmd_flash_ps_erase(0x4000 + id);
	if(res->result){
		debug("Error deleting encryption key: %04x\n", res->result);
		return 0;
	}
	return 1;
}

char *decrypt_cmd(const uint8_t *cipher, const unsigned int cipherLen, const uint8_t *key, uint8_t *iv){
	mbedtls_aes_context aesctx;
	unsigned char *cmd = malloc(cipherLen);
	memset(cmd, 0, cipherLen);
	mbedtls_aes_init(&aesctx);
	if(mbedtls_aes_setkey_dec(&aesctx, key, AES_KEYSIZE*8)){
		debug("setkey_dec failed\n");
		free(cmd);
		return 0;
	}

	if(mbedtls_aes_crypt_cbc(&aesctx, MBEDTLS_AES_DECRYPT, cipherLen, iv, cipher, cmd)){
		debug("decrypt failed\n");
		free(cmd);
		return 0;
	}

	mbedtls_aes_free(&aesctx);

	return (char*)cmd;
}

// round up `num` so it's a multiple of `mult`
int round_int(int num, int mult){
	return ((num + mult ) / mult) * mult;
}

int encrypt_cmd(uint8_t *cipher, const char *plaintext, const uint8_t *key, const uint8_t *iv){
	const unsigned int ptlen = strlen(plaintext);
	if(ptlen > 255){
		debug("!!ERROR!! plaintext too long\n");
		return 0;
	}

	uint8_t iv_copy[IV_SIZE];
	memcpy(iv_copy, iv, IV_SIZE);

	uint8_t buf[round_int(strlen(plaintext), 16)];
	memcpy(buf, plaintext, strlen(plaintext));

	// PKCS5 padding:
	size_t padding = sizeof(buf) - (strlen(plaintext));
	for(int i=0;i<padding;i++)
		buf[strlen(plaintext)+i] = padding;

	mbedtls_aes_context aesctx;
	mbedtls_aes_init(&aesctx);
	if(mbedtls_aes_setkey_enc(&aesctx, key, AES_KEYSIZE*8)){
		debug("setkey_dec failed\n");
		return 0;
	}

	if(mbedtls_aes_crypt_cbc(&aesctx, MBEDTLS_AES_ENCRYPT, sizeof(buf), iv_copy, buf, cipher)){
		debug("encrypt failed\n");
		return 0;
	}

	mbedtls_aes_free(&aesctx);

	return sizeof(buf);
}

void generate_iv(uint8_t *iv){
	for(int i=0;i<SHA_KEYSIZE/16;i++){
		struct gecko_msg_system_get_random_data_rsp_t *resp = gecko_cmd_system_get_random_data(16);
		memcpy(iv + i*16, resp->data.data, 16);
	}
	return;
}

uint16_t get_next_code(uint8_t keyid){
	struct gecko_msg_system_get_random_data_rsp_t *resp = gecko_cmd_system_get_random_data(16);

	key_config[keyid].next_code = *(uint16_t*)resp->data.data;

	return key_config[keyid].next_code;
}

/**
 * As memcmp(), but constant-time.
 * Returns 0 when data is equal, non-zero otherwise.
 */
int memcmp_constant_time (const void *a, const void *b, size_t size) {
  const uint8_t * a1 = a;
  const uint8_t * b1 = b;
  int ret = 0;
  size_t i;

  for (i = 0; i < size; i++) {
      ret |= *a1++ ^ *b1++;
  }

  return ret;
}
