/*! @file picnic2_impl.h
 *  @brief This is the main implementation file of the signature scheme for
 *  the Picnic2 parameter sets.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC2_IMPL_H
#define PICNIC2_IMPL_H

#include <stdint.h>
#include <stddef.h>
#include "picnic_impl.h"

typedef struct proof2_t {
    uint8_t* seedInfo;          // Information required to compute the tree with seeds of of all opened parties
    size_t seedInfoLen;         // Length of seedInfo buffer
    uint8_t* aux;               // Last party's correction bits; NULL if P[t] == N-1
    uint8_t* C;                 // Commitment to preprocessing step of unopened party
    uint8_t* input;             // Masked input used in online execution
    uint8_t* msgs;              // Broadcast messages of unopened party P[t]
} proof2_t;

typedef struct signature2_t {
    uint8_t* salt;
    uint8_t* iSeedInfo;         // Info required to recompute the tree of all initial seeds
    size_t iSeedInfoLen;
    uint8_t* cvInfo;            // Info required to check commitments to views (reconstruct Merkle tree)
    size_t cvInfoLen;
    uint16_t* challengeC;
    uint16_t* challengeP;
    proof2_t* proofs;           // One proof for each online execution the verifier checks
} signature2_t;

int sign_picnic2(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, signature2_t* sig, paramset_t* params);
int verify_picnic2(signature2_t* sig, const uint32_t* pubKey, const uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params);

void allocateSignature2(signature2_t* sig, paramset_t* params);
void freeSignature2(signature2_t* sig, paramset_t* params);

/* Returns the number of bytes written on success, or -1 on error */
int serializeSignature2(const signature2_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);
/* Returns EXIT_SUCCESS on success or EXIT_FAILURE on error */
int deserializeSignature2(signature2_t* sig, const uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);


#endif /* PICNIC2_IMPL_H */
