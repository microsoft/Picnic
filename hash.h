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

#ifndef SUPERCOP
#include "sha3/KeccakHash.h"
#else
#include <libkeccak.a.headers/KeccakHash.h>
#endif
#include "picnic_impl.h"

/* Wrap the Keccak API, checking return values, logging errors, and working
 * with byte lengths instead of bitlengths. */

#define MAX_DIGEST_SIZE 64

/* Prefix values for domain separation. */
static const uint8_t HASH_PREFIX_NONE = -1;
static const uint8_t HASH_PREFIX_0 = 0;
static const uint8_t HASH_PREFIX_1 = 1;
static const uint8_t HASH_PREFIX_2 = 2;
static const uint8_t HASH_PREFIX_3 = 3;
static const uint8_t HASH_PREFIX_4 = 4;
static const uint8_t HASH_PREFIX_5 = 5;

typedef Keccak_HashInstance HashInstance;

void HashUpdate(HashInstance* ctx, const uint8_t* data, size_t byteLen);

void HashInit(HashInstance* ctx, paramset_t* params, uint8_t hashPrefix);

void HashFinal(HashInstance* ctx);

void HashSqueeze(HashInstance* ctx, uint8_t* digest, size_t byteLen);


uint16_t toLittleEndian(uint16_t x);
void HashUpdateIntLE(HashInstance* ctx, uint16_t x);
uint16_t fromLittleEndian(uint16_t x);

#endif /* HASH_H */
