/*! @file picnic_impl.h
 *  @brief This is the main implementation file of the signature scheme. All of
 *  the LowMC MPC code is here as well as lower-level versions of sign and
 *  verify that are called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_IMPL_H
#define PICNIC_IMPL_H

#include <stdint.h>
#include <stddef.h>

//#define DEBUG

/* Macro that wraps printf and only produces output when DEBUG is defined */
#ifdef DEBUG
    #define PRINT_DEBUG(printf_args) printf("%s %s:%d : ", __func__, __FILE__, __LINE__); printf printf_args; fflush(stdout);
#else
    #define PRINT_DEBUG(args)   /* Nothing */
#endif


typedef enum {
    TRANSFORM_FS = 0,
    TRANSFORM_UR = 1,
    TRANSFORM_INVALID = 255
} transform_t;

typedef struct paramset_t {
    uint32_t numRounds;
    uint32_t numSboxes;
    uint32_t stateSizeBits;
    uint32_t stateSizeBytes;
    uint32_t stateSizeWords;
    uint32_t andSizeBytes;
    uint32_t UnruhGWithoutInputBytes;
    uint32_t UnruhGWithInputBytes;
    uint32_t numMPCRounds;          // T
    uint32_t numOpenedRounds;       // u
    uint32_t numMPCParties;         // N
    uint32_t seedSizeBytes;
    uint32_t saltSizeBytes;
    uint32_t digestSizeBytes;
    transform_t transform;
} paramset_t;

typedef struct proof_t {
    uint8_t* seed1;
    uint8_t* seed2;
    uint32_t* inputShare;     // Input share of the party which does not derive it from the seed (not included if challenge is 0)
    uint8_t* communicatedBits;
    uint8_t* view3Commitment;
    uint8_t* view3UnruhG;     // we include the max length, but we will only serialize the bytes we use
} proof_t;

typedef struct signature_t {
    proof_t* proofs;
    uint8_t* challengeBits;     // has length numBytes(numMPCRounds*2)
    uint8_t* salt;              // has length saltSizeBytes
} signature_t;

int sign_picnic1(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, signature_t* sig, paramset_t* params);
int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params);

void allocateSignature(signature_t* sig, paramset_t* params);
void freeSignature(signature_t* sig, paramset_t* params);

uint8_t getChallenge(const uint8_t* challenge, size_t round);
void printHex(const char* s, const uint8_t* data, size_t len);

void LowMCEnc(const uint32_t* plaintext, uint32_t* output, uint32_t* key, paramset_t* params);

/* Returns the number of bytes written on success, or -1 on error */
int serializeSignature(const signature_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);
/* Returns EXIT_SUCCESS on success or EXIT_FAILURE on error */
int deserializeSignature(signature_t* sig, const uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);

/*
 * Fill buf with len random bytes.
 * Returns 1 on success, 0 on failure
 */
int random_bytes_default(uint8_t* buf, size_t len);

/* Return the number of bytes required to represent the given number of bits */
uint32_t numBytes(uint32_t numBits);
uint32_t ceil_log2(uint32_t x);
uint8_t getBit(const uint8_t* array, uint32_t bitNumber);
uint8_t getBitFromWordArray(const uint32_t* array, uint32_t bitNumber);
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val);
void setBitInWordArray(uint32_t* array, uint32_t bitNumber, uint8_t val);
uint8_t parity(uint32_t* data, size_t len);
uint8_t parityBitstring(uint32_t* input, size_t bitlength);
void xor_array(uint32_t* out, const uint32_t * in1, const uint32_t * in2, uint32_t length);
void matrix_mul(uint32_t* output, const uint32_t* state, const uint32_t* matrix, const paramset_t* params);
int arePaddingBitsZero(uint8_t* data, size_t bitLength);
void zeroTrailingBits(uint8_t* data, size_t bitLength);

#endif /* PICNIC_IMPL_H */
