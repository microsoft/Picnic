/*! @file picnic_types.c
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

#include "picnic_types.h"
#include <stdlib.h>
#include <stdio.h>

/* Allocate/free functions for dynamically sized types */
void allocateView(view_t* view, paramset_t* params)
{
    view->inputShare = malloc(params->stateSizeBytes);
    view->communicatedBits = malloc(params->andSizeBytes);
    view->outputShare = malloc(params->stateSizeBytes);
}

void freeView(view_t* view)
{
    free(view->inputShare);
    free(view->communicatedBits);
    free(view->outputShare);
}

void allocateRandomTape(randomTape_t* tape, paramset_t* params)
{
    for (uint8_t i = 0; i < 3; i++) {
        tape->tape[i] = malloc(numBytes(params->numSboxes * 3 * params->numRounds * params->numZKBRounds - 1));
    }
    tape->pos = 0;
}

void freeRandomTape(randomTape_t* tape)
{
    for (uint8_t i = 0; i < 3; i++) {
        free(tape->tape[i]);
    }
}

void allocateProof(proof_t* proof, paramset_t* params)
{
    proof->seed1 = malloc(params->seedSizeBytes);
    proof->seed2 = malloc(params->seedSizeBytes);
    proof->inputShare = malloc(params->stateSizeBytes);
    proof->communicatedBits = malloc(params->andSizeBytes);
    proof->view3Commitment = malloc(params->digestSizeBytes);
    if (params->UnruhGWithInputBytes > 0) {
        proof->view3UnruhG = malloc(params->UnruhGWithInputBytes);
    }
    else {
        proof->view3UnruhG = NULL;
    }
}

void freeProof(proof_t* proof)
{
    free(proof->seed1);
    free(proof->seed2);
    free(proof->inputShare);
    free(proof->communicatedBits);
    free(proof->view3Commitment);
    free(proof->view3UnruhG);
}

void allocateSignature(signature_t* sig, paramset_t* params)
{
    sig->proofs = (proof_t*)malloc(params->numZKBRounds * sizeof(proof_t));

    for (size_t i = 0; i < params->numZKBRounds; i++) {
        allocateProof(&(sig->proofs[i]), params);
    }

    sig->challengeBits = (uint8_t*)malloc(numBytes(2 * params->numZKBRounds));
}

void freeSignature(signature_t* sig, paramset_t* params)
{
    for (size_t i = 0; i < params->numZKBRounds; i++) {
        freeProof(&(sig->proofs[i]));
    }

    free(sig->proofs);
    free(sig->challengeBits);
}


seeds_t* allocateSeeds(paramset_t* params)
{
    seeds_t* seeds = malloc(params->numZKBRounds * sizeof(seeds_t));
    uint8_t* slab = malloc(params->numZKBRounds * 3 * params->seedSizeBytes);

    for (uint32_t i = 0; i < params->numZKBRounds; i++) {
        seeds[i].seed0 = slab;
        slab += params->seedSizeBytes;
        seeds[i].seed1 = slab;
        slab += params->seedSizeBytes;
        seeds[i].seed2 = slab;
        slab += params->seedSizeBytes;
    }

    return seeds;
}

void freeSeeds(seeds_t* seeds)
{
    free(seeds[0].seed0);
    free(seeds);
}

uint8_t* getSeed(seeds_t* seeds, uint32_t i, uint32_t j)
{
    switch (j) {
    case 0:
        return seeds[i].seed0;
    case 1:
        return seeds[i].seed1;
    case 2:
        return seeds[i].seed2;
    default:
        printf("Invalid seed index %d\n", j);
        return NULL;
    }
}

commitments_t* allocateCommitments(paramset_t* params)
{
    commitments_t* commitments = malloc(params->numZKBRounds * sizeof(commitments_t));
    uint8_t* slab = malloc(params->numZKBRounds * 3 * params->digestSizeBytes);

    for (uint32_t i = 0; i < params->numZKBRounds; i++) {
        commitments[i].hashes[0] = slab;
        slab += params->digestSizeBytes;
        commitments[i].hashes[1] = slab;
        slab += params->digestSizeBytes;
        commitments[i].hashes[2] = slab;
        slab += params->digestSizeBytes;
    }

    return commitments;
}

void freeCommitments(commitments_t* commitments)
{
    free(commitments[0].hashes[0]);
    free(commitments);
}

view_t** allocateViews(paramset_t* params)
{
    // 3 views per round
    view_t** views = malloc(params->numZKBRounds * sizeof(view_t *));

    for (size_t i = 0; i < params->numZKBRounds; i++) {
        views[i] = malloc(3 * sizeof(view_t));
        for (size_t j = 0; j < 3; j++) {
            allocateView(&views[i][j], params);
            //last byte of communiated bits will not nec get set so need to zero it out
            views[i][j].communicatedBits[params->andSizeBytes - 1] = 0;
        }
    }

    return views;
}

void freeViews(view_t** views, paramset_t* params)
{
    for (size_t i = 0; i < params->numZKBRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            freeView(&views[i][j]);
        }
        free(views[i]);
    }

    free(views);
}

g_commitments_t* allocateGCommitments(paramset_t* params)
{
    g_commitments_t* gs = NULL;

    if (params->transform == TRANSFORM_UR) {
        gs = malloc(params->numZKBRounds * sizeof(g_commitments_t));
        uint8_t* slab = malloc(params->UnruhGWithInputBytes * params->numZKBRounds * 3);
        for (uint32_t i = 0; i < params->numZKBRounds; i++) {
            for (uint8_t j = 0; j < 3; j++) {
                gs[i].G[j] = slab;
                slab += params->UnruhGWithInputBytes;
            }
        }
    }

    return gs;
}

void freeGCommitments(g_commitments_t* gs)
{
    if (gs != NULL) {
        free(gs[0].G[0]);
        free(gs);
    }
}

