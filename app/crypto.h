/*
 * crypto.h
 *
 *  Created on: Apr 3, 2019
 *      Author: Austin
 */

#ifndef APP_CRYPTO_H_
#define APP_CRYPTO_H_

#include "ignition.h"

#define TEST_MASTER_KEYS "IEi07yA1VFxEEo7c3VRiHQ==:VoXoX4o2E01NTJrVOBcQGXlpwEF7lypDirgKoAwDYEM="

void set_registered_key(uint8_t id, uint8_t value);
uint8_t get_registered_key(uint8_t id);
int decode_keys(struct KeyConfig *decoded, char *encoded);
char *save_keys(struct KeyConfig *keys);
int del_keys(int id);
struct KeyConfig *get_keys(int id);
int memcmp_constant_time (const void *a, const void *b, size_t size);
uint16_t get_next_code(uint8_t keyid);
void generate_iv(uint8_t *iv);
int encrypt_cmd(uint8_t *cipher, const char *plaintext, const uint8_t *key, const uint8_t *iv);
void calculate_hmac(uint8_t *out, uint8_t *cipher, unsigned int cipherLen, const uint8_t *key, uint8_t *iv);
char *decrypt_cmd(const uint8_t *cipher, const unsigned int cipherLen, const uint8_t *key, uint8_t *iv);

#endif /* APP_CRYPTO_H_ */
