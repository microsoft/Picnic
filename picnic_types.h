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

/* Type definitions */
typedef struct randomTape_t {
    uint8_t* tape[3];
    uint32_t pos;
} randomTape_t;

typedef struct view_t {
    uint32_t* inputShare;
    uint8_t* communicatedBits;
    uint32_t* outputShare;
} view_t;

typedef struct commitments_t {
    uint8_t* hashes[3];
} commitments_t;

typedef struct g_commitments_t {
    uint8_t* G[3];
}g_commitments_t;

typedef struct seeds_t {
    uint8_t* seed0;
    uint8_t* seed1;
    uint8_t* seed2;
} seeds_t;

#define UNUSED_PARAMETER(x) (void)(x)

void allocateView(view_t* view, paramset_t* params);
void freeView(view_t* view);

void allocateRandomTape(randomTape_t* tape, paramset_t* params);
void freeRandomTape(randomTape_t* tape);

void allocateProof(proof_t* proof, paramset_t* params);
void freeProof(proof_t* proof);

void allocateSignature(signature_t* sig, paramset_t* params);
void freeSignature(signature_t* sig, paramset_t* params);

seeds_t* allocateSeeds(paramset_t* params);
void freeSeeds(seeds_t* seeds);
uint8_t* getSeed(seeds_t* seeds, uint32_t i, uint32_t j);

commitments_t* allocateCommitments(paramset_t* params);
void freeCommitments(commitments_t* commitments);

view_t** allocateViews(paramset_t* params);
void freeViews(view_t** views, paramset_t* params);

g_commitments_t* allocateGCommitments(paramset_t* params);
void freeGCommitments(g_commitments_t* gs);

#endif /* PICNIC_TYPES_H */
