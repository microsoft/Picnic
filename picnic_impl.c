/*! @file picnic_impl.c
 *  @brief This is the main file of the signature scheme. All of the LowMC MPC
 *  code is here as well as lower-level versions of sign and verify that are
 *  called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#if defined(__WINDOWS__)
	#include <Windows.h>
	#include <bcrypt.h>
#else
    #include <endian.h>
#endif

#include "picnic_impl.h"
#include "picnic.h"
#include "platform.h"
#include "lowmc_constants.h"
#include "hash.h"
#include "picnic_types.h"

#define MAX(a, b) ((a) > (b)) ? (a) : (b)

#define VIEW_OUTPUTS(i, j) viewOutputs[(i) * 3 + (j)]


/* Helper functions */

void printHex(const char* s, uint8_t* data, size_t len)
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

uint16_t toLittleEndian(uint16_t x)
{
#if defined(__WINDOWS__)
    #if BYTE_ORDER == LITTLE_ENDIAN
		return x;
	#else
		return __builtin_bswap16(x);
    #endif
#else
	return htole16(x);
#endif
}

/* Get one bit from a byte array */
uint8_t getBit(const uint8_t* array, uint32_t bitNumber)
{
    return (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

/* Get one bit from a 32-bit int array */
uint8_t getBitFromWordArray(const uint32_t* array, uint32_t bitNumber)
{
    return getBit((uint8_t*)array, bitNumber);
}

/* Set a specific bit in a byte array to a given value */
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val)
{
    bytes[bitNumber / 8] = (bytes[bitNumber >> 3]
                            & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

/* Set a specific bit in a byte array to a given value */
void setBitInWordArray(uint32_t* array, uint32_t bitNumber, uint8_t val)
{
    setBit((uint8_t*)array, bitNumber, val);
}

static uint8_t parity(uint32_t* data, size_t len)
{
    uint32_t x = data[0];

    for (size_t i = 1; i < len; i++) {
        x ^= data[i];
    }

    /* Compute parity of x using code from Section 5-2 of
     * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
     * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
     */
    uint32_t y = x ^ (x >> 1);
    y ^= (y >> 2);
    y ^= (y >> 4);
    y ^= (y >> 8);
    y ^= (y >> 16);
    return y & 1;
}

uint32_t numBytes(uint32_t numBits)
{
    return (numBits == 0) ? 0 : ((numBits - 1) / 8 + 1);
}

static void xor_array(const uint32_t * in1, const uint32_t * in2, uint32_t * out, uint32_t numBytes)
{
    for (uint32_t i = 0; i < numBytes; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

static void matrix_mul(
    uint32_t* state,
    const uint32_t* matrix,
    uint32_t* output,
    paramset_t* params)
{
    // Use temp to correctly handle the case when state = output
    uint32_t prod[LOWMC_MAX_STATE_SIZE];
    uint32_t temp[LOWMC_MAX_STATE_SIZE];

    for (uint32_t i = 0; i < params->stateSizeBits; i++) {
        for (uint32_t j = 0; j < params->stateSizeWords; j++) {
            size_t index = i * params->stateSizeWords + j;
            prod[j] = (state[j] & matrix[index]);
        }
        setBit((uint8_t*)temp, i, parity(&prod[0], params->stateSizeWords));

    }
    memcpy(output, &temp, params->stateSizeWords * sizeof(uint32_t));
}

static void substitution(uint32_t* state, paramset_t* params)
{
    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {
        uint8_t a = getBitFromWordArray(state, i + 2);
        uint8_t b = getBitFromWordArray(state, i + 1);
        uint8_t c = getBitFromWordArray(state, i);

        setBitInWordArray(state, i + 2, a ^ (b & c));
        setBitInWordArray(state, i + 1, a ^ b ^ (a & c));
        setBitInWordArray(state, i, a ^ b ^ c ^ (a & b));
    }
}

void LowMCEnc(const uint32_t* plaintext, uint32_t* output, uint32_t* key, paramset_t* params)
{
    uint32_t roundKey[LOWMC_MAX_STATE_SIZE / sizeof(uint32_t)];

    if (plaintext != output) {
        /* output will hold the intermediate state */
        memcpy(output, plaintext, params->stateSizeBytes);
    }

    matrix_mul(key, KMatrix(0, params), roundKey, params);
    xor_array(output, roundKey, output, params->stateSizeWords);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        matrix_mul(key, KMatrix(r, params), roundKey, params);
        substitution(output, params);
        matrix_mul(output, LMatrix(r - 1, params), output, params);
        xor_array(output, RConstant(r - 1, params), output, params->stateSizeWords);
        xor_array(output, roundKey, output, params->stateSizeWords);
    }

}

bool createRandomTape(const uint8_t* seed, uint8_t* tape,
                      uint32_t tapeLengthBytes, paramset_t* params)
{
    HashInstance ctx;

    if (tapeLengthBytes < params->digestSizeBytes) {
        return false;
    }

    /* Hash the seed and a constant, store the result in tape. */
    HashInit(&ctx, params, HASH_PREFIX_2);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tape, params->digestSizeBytes);

    /* Expand the hashed seed to create the tape. */
    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, tape, params->digestSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tape, tapeLengthBytes);

    return true;
}

void mpc_xor(uint32_t* state[3], uint32_t* in[3], uint32_t len, int players)
{
    for (uint8_t i = 0; i < players; i++) {
        xor_array(state[i], in[i], state[i], len);
    }
}

/* Compute the XOR of in with the first state vectors. */
void mpc_xor_constant(uint32_t* state[3], const uint32_t* in, uint32_t len)
{
    xor_array(state[0], in, state[0], len);
}

void mpc_xor_constant_verify(uint32_t* state[2], const uint32_t* in, uint32_t len, uint8_t challenge)
{
    /* During verify, where the first share is stored in state depends on the challenge */
    if (challenge == 0) {
        xor_array(state[0], in, state[0], len);
    }
    else if (challenge == 2) {
        xor_array(state[1], in, state[1], len);
    }
}


void Commit(const uint8_t* seed, const view_t view,
            uint8_t* hash, paramset_t* params)
{
    HashInstance ctx;

    /* Hash the seed, store result in `hash` */
    HashInit(&ctx, params, HASH_PREFIX_4);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);

    /* Compute H_0(H_4(seed), view) */
    HashInit(&ctx, params, HASH_PREFIX_0);
    HashUpdate(&ctx, hash, params->digestSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.inputShare, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.communicatedBits, params->andSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.outputShare, params->stateSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);
}

/* This is the random "permuatation" function G for Unruh's transform */
void G(uint8_t viewNumber, const uint8_t* seed, view_t* view, uint8_t* output, paramset_t* params)
{
    HashInstance ctx;
    uint16_t outputBytes = params->seedSizeBytes + params->andSizeBytes;

    /* Hash the seed with H_5, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_5);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, output, params->digestSizeBytes);

    /* Hash H_5(seed), the view, and the length */
    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, output, params->digestSizeBytes);
    if (viewNumber == 2) {
        HashUpdate(&ctx, (uint8_t*)view->inputShare, params->stateSizeBytes);
        outputBytes += (uint16_t)params->stateSizeBytes;
    }
    HashUpdate(&ctx, view->communicatedBits, params->andSizeBytes);

    uint16_t outputBytesLE = toLittleEndian(outputBytes);
    HashUpdate(&ctx, (uint8_t*)&outputBytesLE, sizeof(uint16_t));
    HashFinal(&ctx);
    HashSqueeze(&ctx, output, outputBytes);
}

void setChallenge(uint8_t* challenge, size_t round, uint8_t trit)
{
    /* challenge must have length numBytes(numZKBRounds*2)
     * 0 <= index < numZKBRounds
     * trit must be in {0,1,2} */
    uint32_t roundU32 = (uint32_t)round;

    setBit(challenge, 2 * roundU32, trit & 1);
    setBit(challenge, 2 * roundU32 + 1, (trit >> 1) & 1);
}

uint8_t getChallenge(const uint8_t* challenge, size_t round)
{
    uint32_t roundU32 = (uint32_t)round;

    return (getBit(challenge, 2 * roundU32 + 1) << 1) | getBit(challenge, 2 * roundU32);
}

void H3(const uint32_t* circuitOutput, const uint32_t* plaintext, uint32_t** viewOutputs,
        commitments_t* as,
        uint8_t* challengeBits, const uint8_t* message, size_t messageByteLength,
        g_commitments_t* gs, paramset_t* params)
{
    uint8_t* hash = malloc(params->digestSizeBytes);

    HashInstance ctx;

    /* Depending on the number of rounds, we might not set part of the last
     * byte, make sure it's always zero. */
    challengeBits[numBytes(params->numZKBRounds * 2) - 1] = 0;

    /* Hash input data */
    HashInit(&ctx, params, HASH_PREFIX_1);

    /* Hash the output share from each view */
    for (uint32_t i = 0; i < params->numZKBRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, (uint8_t*)VIEW_OUTPUTS(i, j), params->stateSizeBytes);
        }
    }

    /* Hash all the commitments C */
    for (uint32_t i = 0; i < params->numZKBRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, as[i].hashes[j], params->digestSizeBytes);
        }
    }

    /* Hash all the commitments G */
    if (params->transform == TRANSFORM_UR) {
        for (uint32_t i = 0; i < params->numZKBRounds; i++) {
            for (int j = 0; j < 3; j++) {
                size_t view3UnruhLength = (j == 2) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
                HashUpdate(&ctx, gs[i].G[j], view3UnruhLength);
            }
        }
    }

    HashUpdate(&ctx, (uint8_t*)circuitOutput, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);

    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);

    /* Convert hash to a packed string of values in {0,1,2} */
    size_t round = 0;
    while (1) {
        for (size_t i = 0; i < params->digestSizeBytes; i++) {
            uint8_t byte = hash[i];
            /* iterate over each pair of bits in the byte */
            for (int j = 0; j < 8; j += 2) {
                uint8_t bitPair = ((byte >> (6 - j)) & 0x03);
                if (bitPair < 3) {
                    setChallenge(challengeBits, round, bitPair);
                    round++;
                    if (round == params->numZKBRounds) {
                        goto done;
                    }
                }
            }
        }

        /* We need more bits; hash set hash = H_1(hash) */
        HashInit(&ctx, params, HASH_PREFIX_1);
        HashUpdate(&ctx, hash, params->digestSizeBytes);
        HashFinal(&ctx);
        HashSqueeze(&ctx, hash, params->digestSizeBytes);
    }

done:

    free(hash);
    return;
}

/* Caller must allocate the first parameter */
void prove(proof_t* proof, uint8_t challenge, seeds_t* seeds,
           view_t views[3], commitments_t* commitments, g_commitments_t* gs, paramset_t* params)
{
    if (challenge == 0) {
        memcpy(proof->seed1, seeds->seed0, params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed1, params->seedSizeBytes);
    }
    else if (challenge == 1) {
        memcpy(proof->seed1, seeds->seed1, params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed2, params->seedSizeBytes);
    }
    else if (challenge == 2) {
        memcpy(proof->seed1, seeds->seed2, params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed0, params->seedSizeBytes);
    }
    else {
        assert(!"Invalid challenge");
    }

    if (challenge == 1 || challenge == 2) {
        memcpy(proof->inputShare, views[2].inputShare, params->stateSizeBytes);
    }
    memcpy(proof->communicatedBits, views[(challenge + 1) % 3].communicatedBits, params->andSizeBytes);

    memcpy(proof->view3Commitment, commitments->hashes[(challenge + 2) % 3], params->digestSizeBytes);
    if (params->transform == TRANSFORM_UR) {
        size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
        memcpy(proof->view3UnruhG, gs->G[(challenge + 2) % 3], view3UnruhLength);
    }
}

void mpc_AND_verify(uint8_t in1[2], uint8_t in2[2], uint8_t out[2],
                    randomTape_t* rand, view_t* view1, view_t* view2)
{
    uint8_t r[2] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos) };

    out[0] = (in1[0] & in2[1]) ^ (in1[1] & in2[0]) ^ (in1[0] & in2[0]) ^ r[0] ^ r[1];
    setBit(view1->communicatedBits, rand->pos, out[0]);
    out[1] = getBit(view2->communicatedBits, rand->pos);

    (rand->pos)++;
}

void mpc_substitution_verify(uint32_t* state[2], randomTape_t* rand, view_t* view1,
                             view_t* view2, paramset_t* params)
{
    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {

        uint8_t a[2];
        uint8_t b[2];
        uint8_t c[2];

        for (uint8_t j = 0; j < 2; j++) {
            a[j] = getBitFromWordArray(state[j], i + 2);
            b[j] = getBitFromWordArray(state[j], i + 1);
            c[j] = getBitFromWordArray(state[j], i);
        }

        uint8_t ab[2];
        uint8_t bc[2];
        uint8_t ca[2];

        mpc_AND_verify(a, b, ab, rand, view1, view2);
        mpc_AND_verify(b, c, bc, rand, view1, view2);
        mpc_AND_verify(c, a, ca, rand, view1, view2);

        for (uint8_t j = 0; j < 2; j++) {
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]));
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]));
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
        }
    }
}

void mpc_matrix_mul(uint32_t* state[3], const uint32_t* matrix,
                    uint32_t* output[3], paramset_t* params, size_t players)
{
    for (uint32_t player = 0; player < players; player++) {
        matrix_mul(state[player], matrix, output[player], params);
    }
}

void mpc_LowMC_verify(view_t* view1, view_t* view2,
                      randomTape_t* tapes, uint32_t* tmp,
                      const uint32_t* plaintext, paramset_t* params, uint8_t challenge)
{
    uint32_t* state[2];
    uint32_t* keyShares[2];
    uint32_t* roundKey[2];

    roundKey[0] = tmp;
    roundKey[1] = roundKey[0] + params->stateSizeWords;
    state[0] = roundKey[1] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;

    // initialize both roundkeys to 0. they are contingent
    memset(roundKey[0], 0, 2 * params->stateSizeBytes);

    for (uint32_t i = 0; i < 2; i++) {
        memset(state[i], 0x00, params->stateSizeBytes);
    }
    mpc_xor_constant_verify(state, plaintext, params->stateSizeWords, challenge);

    keyShares[0] = view1->inputShare;
    keyShares[1] = view2->inputShare;

    mpc_matrix_mul(keyShares, KMatrix(0, params), roundKey, params, 2);
    mpc_xor(state, roundKey, params->stateSizeWords, 2);

    for (uint32_t r = 1; r <= params->numRounds; ++r) {
        mpc_matrix_mul(keyShares, KMatrix(r, params), roundKey, params, 2);
        mpc_substitution_verify(state, tapes, view1, view2, params);
        mpc_matrix_mul(state, LMatrix(r - 1, params), state, params, 2);
        mpc_xor_constant_verify(state, RConstant(r - 1, params), params->stateSizeWords, challenge);
        mpc_xor(state, roundKey, params->stateSizeWords, 2);
    }

    memcpy(view1->outputShare, state[0], params->stateSizeBytes);
    memcpy(view2->outputShare, state[1], params->stateSizeBytes);
}

void verifyProof(const proof_t* proof, view_t* view1, view_t* view2,
                 uint8_t challenge, uint8_t* tmp,
                 const uint32_t* plaintext, randomTape_t* tape, paramset_t* params)
{
    memcpy(view2->communicatedBits, proof->communicatedBits, params->andSizeBytes);
    tape->pos = 0;

    bool status = false;
    switch (challenge) {
    case 0:
        // in this case, both views' inputs are derivable from the input share

        status = createRandomTape(proof->seed1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[1], tmp + params->stateSizeBytes, params->andSizeBytes);
        break;

    case 1:
        // in this case view2's input share was already given to us explicitly as
        // it is not computable from the seed. We just need to compute view1's input from
        // its seed
        status = createRandomTape(proof->seed1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, tape->tape[1], params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, proof->inputShare, params->stateSizeBytes);
        break;

    case 2:
        // in this case view1's input share was already given to us explicitly as
        // it is not computable from the seed. We just need to compute view2's input from
        // its seed
        status = createRandomTape(proof->seed1, tape->tape[0], params->andSizeBytes, params);
        memcpy(view1->inputShare, proof->inputShare, params->stateSizeBytes);
        status = status && createRandomTape(proof->seed2, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[1], tmp + params->stateSizeBytes, params->andSizeBytes);
        break;

    default:
        fprintf(stderr, "%s: Invalid Challenge\n", __func__);
        break;
    }

    if (!status) {
        fprintf(stderr, "%s: Failed to generate random tapes, signature verification will fail (but signature may actually be valid)\n", __func__);
    }

    mpc_LowMC_verify(view1, view2, tape, (uint32_t*)tmp, plaintext, params, challenge);
}

int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext,
           const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    commitments_t* as = allocateCommitments(params);
    g_commitments_t* gs = allocateGCommitments(params);

    uint32_t** viewOutputs = malloc(params->numZKBRounds * 3 * sizeof(uint32_t*));
    const proof_t* proofs = sig->proofs;

    const uint8_t* received_challengebits = sig->challengeBits;
    int status = EXIT_SUCCESS;
    uint8_t* computed_challengebits = NULL;
    uint32_t* view3Slab = NULL;

    uint8_t* tmp = malloc(MAX(6 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    randomTape_t* tape = (randomTape_t*)malloc(sizeof(randomTape_t));

    allocateRandomTape(tape, params);

    view_t* view1s = malloc(params->numZKBRounds * sizeof(view_t));
    view_t* view2s = malloc(params->numZKBRounds * sizeof(view_t));

    /* Allocate a slab of memory for the 3rd view's output in each round */
    view3Slab = malloc(params->stateSizeBytes * params->numZKBRounds);
    uint32_t* view3Output = view3Slab;     /* pointer into the slab to the current 3rd view */

    for (size_t i = 0; i < params->numZKBRounds; i++) {
        allocateView(&view1s[i], params);
        allocateView(&view2s[i], params);

        // last bits of communicatedBits may not be set so zero them
        view1s[i].communicatedBits[params->andSizeBytes - 1] = 0;

        verifyProof(&proofs[i], &view1s[i], &view2s[i],
                    getChallenge(received_challengebits, i),
                    tmp, plaintext, tape, params);

        // create ordered array of commitments with order computed based on the challenge
        // check commitments of the two opened views
        uint8_t challenge = getChallenge(received_challengebits, i);
        Commit(proofs[i].seed1, view1s[i], as[i].hashes[challenge], params);
        Commit(proofs[i].seed2, view2s[i], as[i].hashes[(challenge + 1) % 3], params);
        memcpy(as[i].hashes[(challenge + 2) % 3], proofs[i].view3Commitment, params->digestSizeBytes);

        if (params->transform == TRANSFORM_UR) {
            G(challenge, proofs[i].seed1, &view1s[i], gs[i].G[challenge], params);
            G((challenge + 1) % 3, proofs[i].seed2, &view2s[i], gs[i].G[(challenge + 1) % 3], params);
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(gs[i].G[(challenge + 2) % 3], proofs[i].view3UnruhG, view3UnruhLength);
        }

        VIEW_OUTPUTS(i, challenge) = view1s[i].outputShare;
        VIEW_OUTPUTS(i, (challenge + 1) % 3) = view2s[i].outputShare;
        for (size_t j = 0; j < params->stateSizeWords; j++) {
            view3Output[j] = view1s[i].outputShare[j] ^ view2s[i].outputShare[j]
                             ^ pubKey[j];
        }
        VIEW_OUTPUTS(i, (challenge + 2) % 3) = view3Output;
        view3Output += params->stateSizeWords;
    }

    computed_challengebits = malloc(numBytes(2 * params->numZKBRounds));

    H3(pubKey, plaintext, viewOutputs, as,
       computed_challengebits, message, messageByteLength, gs, params);

    if (computed_challengebits != NULL &&
        memcmp(received_challengebits, computed_challengebits,
               numBytes(2 * params->numZKBRounds)) != 0) {
        printf("%s: Invalid signature. Did not verify.\n", __func__);
        status = EXIT_FAILURE;
    }

    free(computed_challengebits);
    free(view3Slab);

    freeCommitments(as);
    for (size_t i = 0; i < params->numZKBRounds; i++) {
        freeView(&view1s[i]);
        freeView(&view2s[i]);
    }
    free(view1s);
    free(view2s);
    free(tmp);
    freeRandomTape(tape);
    free(tape);
    freeGCommitments(gs);
    free(viewOutputs);

    return status;
}

/*** Functions implementing Sign ***/

void mpc_AND(uint8_t in1[3], uint8_t in2[3], uint8_t out[3], randomTape_t* rand,
             view_t views[3])
{
    uint8_t r[3] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos), getBit(rand->tape[2], rand->pos) };

    for (uint8_t i = 0; i < 3; i++) {
        out[i] = (in1[i] & in2[(i + 1) % 3]) ^ (in1[(i + 1) % 3] & in2[i])
                 ^ (in1[i] & in2[i]) ^ r[i] ^ r[(i + 1) % 3];

        setBit(views[i].communicatedBits, rand->pos, out[i]);
    }

    (rand->pos)++;
}

void mpc_substitution(uint32_t* state[3], randomTape_t* rand, view_t views[3],
                      paramset_t* params)
{
    uint8_t a[3];
    uint8_t b[3];
    uint8_t c[3];

    uint8_t ab[3];
    uint8_t bc[3];
    uint8_t ca[3];

    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {

        for (uint8_t j = 0; j < 3; j++) {
            a[j] = getBitFromWordArray(state[j], i + 2);
            b[j] = getBitFromWordArray(state[j], i + 1);
            c[j] = getBitFromWordArray(state[j], i);
        }

        mpc_AND(a, b, ab, rand, views);
        mpc_AND(b, c, bc, rand, views);
        mpc_AND(c, a, ca, rand, views);

        for (uint8_t j = 0; j < 3; j++) {
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]));
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]));
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
        }
    }
}

void mpc_LowMC(randomTape_t* tapes, view_t views[3],
               const uint32_t* plaintext, uint32_t* slab, paramset_t* params)
{
    uint32_t* keyShares[3];
    uint32_t* state[3];
    uint32_t* roundKey[3];

    roundKey[0] = slab;
    roundKey[1] = slab + params->stateSizeWords;
    roundKey[2] = roundKey[1] + params->stateSizeWords;
    state[0] = roundKey[2] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;
    state[2] = state[1] + params->stateSizeWords;

    memset(roundKey[0], 0, 3 * params->stateSizeBytes);
    for (int i = 0; i < 3; i++) {
        keyShares[i] = views[i].inputShare;
        memset(state[i], 0x00, params->stateSizeBytes);
    }
    mpc_xor_constant(state, plaintext, params->stateSizeWords);

    mpc_matrix_mul(keyShares, KMatrix(0, params), roundKey, params, 3);
    mpc_xor(state, roundKey, params->stateSizeWords, 3);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        mpc_matrix_mul(keyShares, KMatrix(r, params), roundKey, params, 3);
        mpc_substitution(state, tapes, views, params);
        mpc_matrix_mul(state, LMatrix(r - 1, params), state, params, 3);
        mpc_xor_constant(state, RConstant(r - 1, params), params->stateSizeWords);
        mpc_xor(state, roundKey, params->stateSizeWords, 3);
    }

    for (int i = 0; i < 3; i++) {
        memcpy(views[i].outputShare, state[i], params->stateSizeBytes);
    }

}

void runMPC(view_t views[3], randomTape_t* rand,
            uint32_t* plaintext, uint32_t* slab, paramset_t* params)
{
    rand->pos = 0;
    mpc_LowMC(rand, views, plaintext, slab, params);
}

#ifdef PICNIC_BUILD_DEFAULT_RNG
int random_bytes_default(uint8_t* buf, size_t len)
{

#if defined(__LINUX__)
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        return -1;
    }

    if (fread(buf, sizeof(uint8_t), len, urandom) != len) {
        return -2;
    }
    fclose(urandom);

    return 0;

#elif defined(__WINDOWS__)
#ifndef ULONG_MAX
#define ULONG_MAX 0xFFFFFFFFULL
#endif
    if (len > ULONG_MAX) {
        return -3;
    }

    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return -4;
    }
    return 0;
#else
    #error "If neither __LINUX__ or __WINDOWS__ are defined, you'll have to implement the random number generator"
#endif

}
#endif /* PICNIC_BUILD_DEFAULT_RNG */

#ifdef SUPERCOP
#include "randombytes.h"
int random_bytes_supercop(uint8_t* buf, size_t len)
{
    randombytes(buf, len); /* returns void */
    return 0;
}
#endif /* SUPERCOP */

seeds_t* computeSeeds(uint32_t* privateKey, uint32_t*
                      publicKey, uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    HashInstance ctx;
    seeds_t* allSeeds = allocateSeeds(params);

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, (uint8_t*)privateKey, params->stateSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);
    HashUpdate(&ctx, (uint8_t*)publicKey, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);
    uint16_t stateSizeBitsLE = toLittleEndian((uint16_t)params->stateSizeBits);
    HashUpdate(&ctx, ((uint8_t*)&stateSizeBitsLE), sizeof(uint16_t));
    HashFinal(&ctx);

    HashSqueeze(&ctx, getSeed(allSeeds, 0, 0), params->seedSizeBytes * 3 * params->numZKBRounds);

    return allSeeds;
}

int sign(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message,
         size_t messageByteLength, signature_t* sig, paramset_t* params)
{
    bool status;

    /* Allocate views and commitments for all parallel iterations */
    view_t** views = allocateViews(params);
    commitments_t* as = allocateCommitments(params);
    g_commitments_t* gs = allocateGCommitments(params);

    /* Compute seeds for all parallel iterations */
    seeds_t* seeds = computeSeeds(privateKey, pubKey, plaintext, message, messageByteLength, params);

    //Allocate a random tape (re-used per parallel iteration), and a temporary buffer
    randomTape_t tape;

    allocateRandomTape(&tape, params);
    uint8_t* tmp = malloc( MAX(9 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    for (uint32_t k = 0; k < params->numZKBRounds; k++) {
        // for first two players get all tape INCLUDING INPUT SHARE from seed
        for (int j = 0; j < 2; j++) {
            status = createRandomTape(getSeed(seeds, k, j), tmp, params->stateSizeBytes + params->andSizeBytes, params);
            if (!status) {
                fprintf(stderr, "%s: createRandomTape failed \n", __func__);
                return EXIT_FAILURE;
            }

            memcpy(views[k][j].inputShare, tmp, params->stateSizeBytes);
            memcpy(tape.tape[j], tmp + params->stateSizeBytes, params->andSizeBytes);
        }
        // Now set third party's wires. The random bits are from the seed, the input is
        // the XOR of other two inputs and the private key
        status = createRandomTape(getSeed(seeds, k, 2), tape.tape[2], params->andSizeBytes, params);
        if (!status) {
            fprintf(stderr, "%s: createRandomTape failed \n", __func__);
            return EXIT_FAILURE;
        }

        for (uint32_t j = 0; j < params->stateSizeWords; j++) {
            views[k][2].inputShare[j] = privateKey[j]
                                        ^ views[k][0].inputShare[j]
                                        ^ views[k][1].inputShare[j];
        }

        runMPC(views[k], &tape, plaintext, (uint32_t*)tmp, params);

        //Committing
        Commit(getSeed(seeds, k, 0), views[k][0], as[k].hashes[0], params);
        Commit(getSeed(seeds, k, 1), views[k][1], as[k].hashes[1], params);
        Commit(getSeed(seeds, k, 2), views[k][2], as[k].hashes[2], params);

        if (params->transform == TRANSFORM_UR) {
            G(0, getSeed(seeds, k, 0), &views[k][0], gs[k].G[0], params);
            G(1, getSeed(seeds, k, 1), &views[k][1], gs[k].G[1], params);
            G(2, getSeed(seeds, k, 2), &views[k][2], gs[k].G[2], params);
        }
    }

    //Generating challenges
    uint32_t** viewOutputs = malloc(params->numZKBRounds * 3 * sizeof(uint32_t*));

    for (size_t i = 0; i < params->numZKBRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            VIEW_OUTPUTS(i, j) = views[i][j].outputShare;
        }
    }

    uint32_t output[LOWMC_MAX_STATE_SIZE];
    for (uint32_t j = 0; j < params->stateSizeWords; j++) {
        output[j] = (VIEW_OUTPUTS(0, 0))[j] ^ (VIEW_OUTPUTS(0, 1))[j] ^ (VIEW_OUTPUTS(0, 2))[j];
    }

    H3(output, plaintext, viewOutputs, as,
       sig->challengeBits, message, messageByteLength, gs, params);

    //Packing Z
    for (size_t i = 0; i < params->numZKBRounds; i++) {
        proof_t* proof = &sig->proofs[i];
        prove(proof, getChallenge(sig->challengeBits, i), &seeds[i],
              views[i], &as[i], (gs == NULL) ? NULL : &gs[i], params);
    }

    free(tmp);

    freeViews(views, params);
    freeCommitments(as);
    freeRandomTape(&tape);
    freeGCommitments(gs);
    free(viewOutputs);
    freeSeeds(seeds);

    return EXIT_SUCCESS;
}

/*** Serialization functions ***/

int serializeSignature(const signature_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params)
{
    const proof_t* proofs = sig->proofs;
    const uint8_t* challengeBits = sig->challengeBits;

    /* Validate input buffer is large enough */
    size_t bytesRequired = numBytes(2 * params->numZKBRounds) +
                           params->numZKBRounds * (2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes + params->digestSizeBytes);

    if (params->transform == TRANSFORM_UR) {
        bytesRequired += params->UnruhGWithoutInputBytes * params->numZKBRounds;
    }

    if (sigBytesLen < bytesRequired) {
        return -1;
    }

    uint8_t* sigBytesBase = sigBytes;

    memcpy(sigBytes, challengeBits, numBytes(2 * params->numZKBRounds));
    sigBytes += numBytes(2 * params->numZKBRounds);

    for (size_t i = 0; i < params->numZKBRounds; i++) {

        uint8_t challenge = getChallenge(challengeBits, i);

        memcpy(sigBytes, proofs[i].view3Commitment, params->digestSizeBytes);
        sigBytes += params->digestSizeBytes;

        if (params->transform == TRANSFORM_UR) {
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(sigBytes, proofs[i].view3UnruhG, view3UnruhLength);
            sigBytes += view3UnruhLength;
        }

        memcpy(sigBytes, proofs[i].communicatedBits, params->andSizeBytes);
        sigBytes += params->andSizeBytes;

        memcpy(sigBytes, proofs[i].seed1, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        memcpy(sigBytes, proofs[i].seed2, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        if (challenge == 1 || challenge == 2) {
            memcpy(sigBytes, proofs[i].inputShare, params->stateSizeBytes);
            sigBytes += params->stateSizeBytes;
        }


    }

    return (int)(sigBytes - sigBytesBase);
}


static size_t computeInputShareSize(const uint8_t* challengeBits, size_t stateSizeBytes, paramset_t* params)
{
    /* When the FS transform is used, the input share is included in the proof
     * only when the challenge is 1 or 2.  When dersializing, to compute the
     * number of bytes expected, we must check how many challenge values are 1
     * or 2. The parameter stateSizeBytes is the size of an input share. */
    size_t inputShareSize = 0;

    for (size_t i = 0; i < params->numZKBRounds; i++) {
        uint8_t challenge = getChallenge(challengeBits, i);
        if (challenge == 1 || challenge == 2) {
            inputShareSize += stateSizeBytes;
        }
    }
    return inputShareSize;
}

int deserializeSignature(signature_t* sig, const uint8_t* sigBytes,
                         size_t sigBytesLen, paramset_t* params)
{
    proof_t* proofs = sig->proofs;
    uint8_t* challengeBits = sig->challengeBits;

    /* Validate input buffer is large enough */
    if (sigBytesLen < numBytes(2 * params->numZKBRounds)) {     /* ensure the input has at least the challenge */
        return EXIT_FAILURE;
    }
    size_t inputShareSize = computeInputShareSize(sigBytes, params->stateSizeBytes, params);
    size_t bytesExpected = numBytes(2 * params->numZKBRounds) +
                           params->numZKBRounds * (2 * params->seedSizeBytes + params->andSizeBytes + params->digestSizeBytes) + inputShareSize;
    if (params->transform == TRANSFORM_UR) {
        bytesExpected += params->UnruhGWithoutInputBytes * params->numZKBRounds;
    }
    if (sigBytesLen < bytesExpected) {
        return EXIT_FAILURE;
    }

    memcpy(challengeBits, sigBytes, numBytes(2 * params->numZKBRounds));
    sigBytes += numBytes(2 * params->numZKBRounds);

    for (size_t i = 0; i < params->numZKBRounds; i++) {

        uint8_t challenge = getChallenge(challengeBits, i);

        memcpy(proofs[i].view3Commitment, sigBytes, params->digestSizeBytes);
        sigBytes += params->digestSizeBytes;

        if (params->transform == TRANSFORM_UR) {
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(proofs[i].view3UnruhG, sigBytes, view3UnruhLength);
            sigBytes += view3UnruhLength;
        }

        memcpy(proofs[i].communicatedBits, sigBytes, params->andSizeBytes);
        sigBytes += params->andSizeBytes;

        memcpy(proofs[i].seed1, sigBytes, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        memcpy(proofs[i].seed2, sigBytes, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        if (challenge == 1 || challenge == 2) {
            memcpy(proofs[i].inputShare, sigBytes, params->stateSizeBytes);
            sigBytes += params->stateSizeBytes;
        }

    }

    return EXIT_SUCCESS;
}




