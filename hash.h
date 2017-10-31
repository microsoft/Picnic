/*! @file hash.h
 *  @brief Wraps the SHA-3 implementation.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef HASH_H
#define HASH_H

#include "sha3/KeccakHash.h"
#include "picnic_impl.h"

/* Wrap the Keccak API, checking return values, logging errors, and working
 * with byte lengths instead of bitlengths. */


/* Prefix values for domain separation. */
static const uint8_t HASH_PREFIX_NONE = -1;
static const uint8_t HASH_PREFIX_0 = 0;
static const uint8_t HASH_PREFIX_1 = 1;
static const uint8_t HASH_PREFIX_2 = 2;
static const uint8_t HASH_PREFIX_4 = 4;
static const uint8_t HASH_PREFIX_5 = 5;

typedef Keccak_HashInstance HashInstance;

void HashUpdate(HashInstance* ctx, const uint8_t* data, size_t byteLen);

void HashInit(HashInstance* ctx, paramset_t* params, uint8_t hashPrefix);

void HashFinal(HashInstance* ctx);

void HashSqueeze(HashInstance* ctx, uint8_t* digest, size_t byteLen);

#endif /* HASH_H */
