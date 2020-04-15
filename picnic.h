/*! @file picnic.h
 *  @brief Public API for the Picnic signature scheme.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

// Doxygen mainpage:
/** @mainpage
 *
 *  This is a reference implementation of the Picnic signature
 *  scheme, as described in the Picnic Specification and Design
 *  Document..
 *
 *  The library API is documented in \ref picnic.h.
 *
 *  Authors: Steven Goldfeder and Greg Zaverucha <br/>
 *  May 2017
 */

#ifndef PICNIC_H
#define PICNIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

/* Maximum lengths in bytes */
#define PICNIC_MAX_LOWMC_BLOCK_SIZE 32
#define PICNIC_MAX_PUBLICKEY_SIZE  (2 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 1)    /**< Largest serialized public key size, in bytes */
#define PICNIC_MAX_PRIVATEKEY_SIZE (3 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 2)    /**< Largest serialized private key size, in bytes */
#define PICNIC_MAX_SIGNATURE_SIZE  209522                                   /**< Largest signature size, in bytes */

/** Parameter set names */
typedef enum picnic_params_t {
    PARAMETER_SET_INVALID = 0,
    Picnic_L1_FS = 1,
    Picnic_L1_UR = 2,
    Picnic_L3_FS = 3,
    Picnic_L3_UR = 4,
    Picnic_L5_FS = 5,
    Picnic_L5_UR = 6,
    Picnic3_L1 = 7,
    Picnic3_L3 = 8,
    Picnic3_L5 = 9,
    Picnic_L1_full = 10,
    Picnic_L3_full = 11,
    Picnic_L5_full = 12,
    PARAMETER_SET_MAX_INDEX = 13
} picnic_params_t;

/** Public key */
typedef struct {
    picnic_params_t params;                                     /**< The parameter set used with this public key. */
    uint8_t plaintext[PICNIC_MAX_LOWMC_BLOCK_SIZE];             /**< The input plaintext block to LowMC. */
    uint8_t ciphertext[PICNIC_MAX_LOWMC_BLOCK_SIZE];            /**< The encryption of plaintext under the private key. */
} picnic_publickey_t;

/** Private key */
typedef struct {
    picnic_params_t params;                             /**< The parameter set used with this private key. */
    uint8_t data[PICNIC_MAX_LOWMC_BLOCK_SIZE];          /**< The private key data. */
    picnic_publickey_t pk;                              /**< The corresponding public key.  */
} picnic_privatekey_t;

/**
 * Get a string representation of the parameter set.
 *
 * @param parameters A parameter set
 *
 * @return A null-terminated string describing the parameter set.
 */
const char* picnic_get_param_name(picnic_params_t parameters);

/* Signature API */

/**
 * Key generation function.
 * Generates a public and private key pair, for the specified parameter set.
 *
 * @param[in]  parameters The parameter set to use when generating a key.
 * @param[out] pk         The new public key.
 * @param[out] sk         The new private key.
 *
 * @return Returns 0 for success, or a nonzero value indicating an error.
 *
 * @see picnic_verify(), picnic_sign()
 */
int picnic_keygen(picnic_params_t parameters, picnic_publickey_t* pk,
                  picnic_privatekey_t* sk);

/**
 * Signature function.
 * Signs a message with the given keypair.
 *
 * @param[in] sk      The signer's private key.
 * @param[in] message The message to be signed.
 * @param[in] message_len The length of the message, in bytes.
 * @param[out] signature A buffer to hold the signature. The required size does
 * not exceed PICNIC_MAX_SIGNATURE_SIZE bytes.  The specific max number of
 * bytes required for a parameter set is given by picnic_signature_size(). Note
 * that the length of each signature varies slightly, for the parameter sets
 * using the FS transform.  The parameter sets using the Unruh transform have a
 * fixed length.
 * @param[in,out] signature_len The length of the provided signature buffer.
 * On success, this is set to the number of bytes written to the signature buffer.
 *
 * @return Returns 0 for success, or a nonzero value indicating an error.
 *
 * @see picnic_verify(), picnic_keygen(), picnic_signature_size()
 */
int picnic_sign(picnic_privatekey_t* sk, const uint8_t* message, size_t message_len,
                uint8_t* signature, size_t* signature_len);

/**
 * Get the number of bytes required to hold a signature.
 *
 * @param[in] parameters The parameter set of the signature.
 *
 * @return The number of bytes required to hold the signature created by
 * picnic_sign
 *
 * @note The size of signatures with parameter sets using the FS transform vary
 *       slightly based on the random choices made during signing.  This function
 *       will return a suffcient number of bytes to hold a signature, and the
 *       picnic_sign() function returns the exact number used for a given signature.
 *
 * @see picnic_sign()
 */
size_t picnic_signature_size(picnic_params_t parameters);

/**
 * Verification function.
 * Verifies a signature is valid with respect to a public key and message.
 *
 * @param[in] pk      The signer's public key.
 * @param[in] message The message the signature purpotedly signs.
 * @param[in] message_len The length of the message, in bytes.
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 *
 * @return Returns 0 for success, indicating a valid signature, or a nonzero
 * value indicating an error or an invalid signature.
 *
 * @see picnic_sign(), picnic_keygen()
 */
int picnic_verify(picnic_publickey_t* pk, const uint8_t* message, size_t message_len,
                  const uint8_t* signature, size_t signature_len);

/**
 * Serialize a public key.
 *
 * @param[in]  key The public key to serialize
 * @param[out] buf The buffer to write the key to.
 *                 Must have size at least PICNIC_MAX_PUBLICKEY_SIZE bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns the number of bytes written, at most PICNIC_MAX_PUBLICKEY_SIZE bytes.
 */
int picnic_write_public_key(const picnic_publickey_t* key, uint8_t* buf, size_t buflen);

/**
 * De-serialize a public key.
 *
 * @param[out]  key The public key object to be populated.
 * @param[in] buf The buffer to read the public key from.
 *                 Must be at least PICNIC_MAX_PUBLICKEY_SIZE bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns 0 on success, or a nonzero value indicating an error.
 */
int picnic_read_public_key(picnic_publickey_t* key, const uint8_t* buf, size_t buflen);

/**
 * Serialize a private key.
 *
 * @param[in]  key The private key to serialize
 * @param[out] buf The buffer to write the key to.
 *                 Must have size at least PICNIC_MAX_PRIVATEKEY_SIZE bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns the number of bytes written, at most PICNIC_MAX_PRIVATEKEY_SIZE bytes.
 */
int picnic_write_private_key(const picnic_privatekey_t* key, uint8_t* buf, size_t buflen);

/**
 * De-serialize a private key.
 *
 * @param[out]  key The private key object to be populated
 * @param[in] buf The buffer to read the key from.
 *                 Must have size at least PICNIC_MAX_PRIVATEKEY_SIZE bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns 0 on success, or a nonzero value indicating an error.
 */
int picnic_read_private_key(picnic_privatekey_t* key, const uint8_t* buf, size_t buflen);

/**
 * Check that a key pair is valid.
 *
 * @param[in] privatekey The private key to check
 * @param[in] publickey The public key to check
 *
 * @return Returns 0 if the key pair is valid, or a nonzero value indicating an error
 */
int picnic_validate_keypair(const picnic_privatekey_t* privatekey, const picnic_publickey_t* publickey);

/**
 * picnic_random_bytes is used to generate random bytes in key generation.
 * (Signing is deterministic; it derives randomness from the secret key and the
 * message to be signed.) See the provided implementation
 * "random_bytes_default" which uses /dev/urandom on Linux and BCryptGenRandom
 * on Windows. The Linux implementation should work on other Unix-like systems
 * as well.
 *
 * To use another RNG, make sure it has the same behavior as
 * random_bytes_default, and change the definition of
 * picnic_random_bytes.
 */
#if SUPERCOP
int random_bytes_supercop(uint8_t* buf, size_t len);
    #define picnic_random_bytes random_bytes_supercop
#else
    #define PICNIC_BUILD_DEFAULT_RNG 1
    #define picnic_random_bytes random_bytes_default
#endif


/** Parse the signature and print the individual parts. Used when creating test vectors */
void print_signature(const uint8_t* sigBytes, size_t sigBytesLen, picnic_params_t picnic_params);

#ifdef __cplusplus
}
#endif

#endif /*PICNIC_H*/
