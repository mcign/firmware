/***************************************************************************//**
 * @file
 * @brief Accelerated cryptographic primitives for the CRYPTO peripheral
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: APACHE-2.0
 *
 * This software is subject to an open source license and is distributed by
 * Silicon Laboratories Inc. pursuant to the terms of the Apache License,
 * Version 2.0 available at https://www.apache.org/licenses/LICENSE-2.0.
 * Such terms and conditions may be further supplemented by the Silicon Labs
 * Master Software License Agreement (MSLA) available at www.silabs.com and its
 * sections applicable to open source software.
 *
 ******************************************************************************/
#ifndef CRYPTO_RADIO_H
#define CRYPTO_RADIO_H

/***************************************************************************//**
 * \defgroup  sl_crypto_internal Silicon Labs INTERNAL Cryptography APIs
 * \{
 ******************************************************************************/

/***************************************************************************//**
 * \addtogroup sl_crypto_radio Accelerated Radio-specific AES
 * \brief Accelerated cryptographic primitives for the CRYPTO peripheral
 *
 * \{
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES-ECB block encryption/decryption optimized for radio
 *
 * \param encrypt  true for encryption, false for decryption
 * \param key      AES key
 * \param keybits  must be 128 or 256
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful, negative on error
 */
int mbedtls_aes_crypt_ecb_radio(bool                   encrypt,
                                const unsigned char    *key,
                                unsigned int           keybits,
                                const unsigned char    input[16],
                                volatile unsigned char output[16]);

/**
 * \brief          AES-CTR block encryption/decryption optimized for radio
 *
 * \param key      AES key
 * \param keybits  must be 128 or 256
 * \param input    16-byte input block
 * \param iv_in    16-byte counter/IV starting value
 * \param iv_out   16-byte counter/IV output after block round
 * \param output   16-byte output block
 *
 * \return         0 if successful, negative on error
 */
int mbedtls_aes_crypt_ctr_radio(const unsigned char   *key,
                                unsigned int           keybits,
                                const unsigned char    input[16],
                                const unsigned char    iv_in[16],
                                volatile unsigned char iv_out[16],
                                volatile unsigned char output[16]);

#ifdef __cplusplus
}
#endif

/** \} (end addtogroup sl_crypto_radio) */
/** \} (end addtogroup sl_crypto_internal) */

#endif /* CRYPTO_RADIO_H */
