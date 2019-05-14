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
