/*! @file picnic_types.h
 *  @brief Functions to allocate/free data types used in the Picnic signature
 *  scheme implementation.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_TYPES_H
#define PICNIC_TYPES_H

#include "picnic_impl.h"
#include "picnic3_impl.h"

/* Type definitions */
typedef struct randomTape_t {
    uint8_t** tape;
    uint32_t pos;
    size_t nTapes;
} randomTape_t;

typedef struct view_t {
    uint32_t* inputShare;
    uint8_t* communicatedBits;
    uint32_t* outputShare;
} view_t;

typedef struct commitments_t {
    uint8_t** hashes;
    size_t nCommitments;
} commitments_t;

typedef uint8_t** inputs_t;

typedef struct msgs_t {
    uint8_t** msgs;         // One for each player
    size_t pos;
    int unopened;           // Index of the unopened party, or -1 if all parties opened (when signing)
} msgs_t;

typedef struct g_commitments_t {
    uint8_t* G[3];
}g_commitments_t;

typedef struct seeds_t {
    uint8_t** seed;
    uint8_t* iSeed;
} seeds_t;

typedef struct shares_t {
    uint16_t* shares;
    size_t numWords;
} shares_t;



#define UNUSED_PARAMETER(x) (void)(x)

void allocateView(view_t* view, paramset_t* params);
void freeView(view_t* view);

size_t getTapeSizeBytes(const paramset_t* params);
void allocateRandomTape(randomTape_t* tape, paramset_t* params);
void freeRandomTape(randomTape_t* tape);

void allocateProof(proof_t* proof, paramset_t* params);
void freeProof(proof_t* proof);

void allocateProof2(proof2_t* proof, paramset_t* params);
void freeProof2(proof2_t* proof);

void allocateSignature(signature_t* sig, paramset_t* params);
void freeSignature(signature_t* sig, paramset_t* params);

seeds_t* allocateSeeds(paramset_t* params);
void freeSeeds(seeds_t* seeds);

commitments_t* allocateCommitments(paramset_t* params, size_t nCommitments);
void freeCommitments(commitments_t* commitments);

void allocateCommitments2(commitments_t* commitments, paramset_t* params, size_t nCommitments);
void freeCommitments2(commitments_t* commitments);

inputs_t allocateInputs(paramset_t* params);
void freeInputs(inputs_t inputs);

msgs_t* allocateMsgs(paramset_t* params);
void freeMsgs(msgs_t* msgs);

shares_t* allocateShares(size_t count);
void freeShares(shares_t* shares);

view_t** allocateViews(paramset_t* params);
void freeViews(view_t** views, paramset_t* params);

g_commitments_t* allocateGCommitments(paramset_t* params);
void freeGCommitments(g_commitments_t* gs);

#endif /* PICNIC_TYPES_H */
