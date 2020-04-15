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
#endif

#include "picnic_impl.h"
#include "picnic3_impl.h"
#include "picnic.h"
#include "platform.h"
#include "lowmc_constants.h"
#include "picnic_types.h"
#include "hash.h"

#define MAX(a, b) ((a) > (b)) ? (a) : (b)

#define VIEW_OUTPUTS(i, j) viewOutputs[(i) * 3 + (j)]


/* Helper functions */

void printHex(const char* s, const uint8_t* data, size_t len)
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
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

void zeroTrailingBits(uint8_t* data, size_t bitLength)
{
    size_t byteLength = numBytes(bitLength);
    for (size_t i = bitLength; i < byteLength * 8; i++) {
        setBit(data, i, 0);
    }
}

uint8_t parity(uint32_t* data, size_t len)
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

void xor_array(uint32_t* out, const uint32_t * in1, const uint32_t * in2, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}
void xor_three(uint32_t* output, const uint32_t* in1, const uint32_t* in2, const uint32_t* in3, size_t lenBytes)
{
    uint8_t* out = (uint8_t*)output;
    const uint8_t* i1 = (uint8_t*)in1;
    const uint8_t* i2 = (uint8_t*)in2;
    const uint8_t* i3 = (uint8_t*)in3;

    size_t wholeWords = lenBytes/sizeof(uint32_t);
    for(size_t i = 0; i < wholeWords; i++) {
        output[i] = in1[i] ^ in2[i] ^ in3[i];
    }
    for(size_t i = wholeWords*sizeof(uint32_t); i < lenBytes; i++) {
        out[i] = i1[i] ^ i2[i] ^ i3[i]; 
    }
}


#if 0
/* Matrix multiplication that works bitwise. Simpler, but much slower than the
 * word-wise implementation below. */
void matrix_mul(
    uint32_t* output,
    const uint32_t* state,
    const uint32_t* matrix,
    const paramset_t* params)
{
    // Use temp to correctly handle the case when state = output
    uint8_t prod;
    uint32_t temp[LOWMC_MAX_WORDS]; 
    temp[params->stateSizeWords-1] = 0;

    for (uint32_t i = 0; i < params->stateSizeBits; i++) {
        prod = 0;
        for (uint32_t j = 0; j < params->stateSizeBits; j++) {
            size_t index = i * params->stateSizeWords*WORD_SIZE_BITS + j;            
            prod ^= (getBitFromWordArray(state,j) & getBitFromWordArray(matrix, index));
        }
        setBit((uint8_t*)temp, i, prod);
    }
    memcpy((uint8_t*)output, (uint8_t*)temp, params->stateSizeWords * sizeof(uint32_t));
}
#else
static uint8_t parity32(uint32_t x)
{
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

void matrix_mul(
    uint32_t* output,
    const uint32_t* state,
    const uint32_t* matrix,
    const paramset_t* params)
{
    // Use temp to correctly handle the case when state = output
    uint32_t prod;
    uint32_t temp[LOWMC_MAX_WORDS];
    temp[params->stateSizeWords-1] = 0;

    uint32_t wholeWords = params->stateSizeBits/WORD_SIZE_BITS;
    for (uint32_t i = 0; i < params->stateSizeBits; i++) {
        prod = 0;
        for (uint32_t j = 0; j < wholeWords; j++) {
            size_t index = i * params->stateSizeWords + j;
            prod ^= (state[j] & matrix[index]);
        }
        for(uint32_t j = wholeWords*WORD_SIZE_BITS; j < params->stateSizeBits; j++) {
            size_t index = i * params->stateSizeWords*WORD_SIZE_BITS + j;
            uint8_t bit = (getBitFromWordArray(state,j) & getBitFromWordArray(matrix, index));
            prod ^= bit;
        }

        setBit((uint8_t*)temp, i, parity32(prod));
    }
    memcpy((uint8_t*)output, (uint8_t*)temp, params->stateSizeWords * sizeof(uint32_t));
}
#endif

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
    uint32_t roundKey[LOWMC_MAX_WORDS];

    if (plaintext != output) {
        /* output will hold the intermediate state */
        memcpy(output, plaintext, params->stateSizeWords*(sizeof(uint32_t)));
    }

    matrix_mul(roundKey, key, KMatrix(0, params), params);
    xor_array(output, output, roundKey, params->stateSizeWords);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        matrix_mul(roundKey, key, KMatrix(r, params), params);
        substitution(output, params);
        matrix_mul(output, output, LMatrix(r - 1, params), params);
        xor_array(output, output, RConstant(r - 1, params), params->stateSizeWords);
        xor_array(output, output, roundKey, params->stateSizeWords);
    }
}


bool createRandomTape(const uint8_t* seed, const uint8_t* salt, uint16_t roundNumber, uint16_t playerNumber,
                      uint8_t* tape, uint32_t tapeLengthBytes, paramset_t* params)
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

    /* Expand the hashed seed, salt, round and player indices, and output
     * length to create the tape. */
    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, tape, params->digestSizeBytes);        // Hash the hashed seed
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, roundNumber);
    HashUpdateIntLE(&ctx, playerNumber);
    HashUpdateIntLE(&ctx, tapeLengthBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tape, tapeLengthBytes);

    return true;
}

void mpc_xor(uint32_t* state[3], uint32_t* in[3], uint32_t len, int players)
{
    for (uint8_t i = 0; i < players; i++) {
        xor_array(state[i], state[i], in[i], len);
    }
}

/* Compute the XOR of in with the first state vectors. */
void mpc_xor_constant(uint32_t* state[3], const uint32_t* in, uint32_t len)
{
    xor_array(state[0], state[0], in, len);
}

void mpc_xor_constant_verify(uint32_t* state[2], const uint32_t* in, uint32_t len, uint8_t challenge)
{
    /* During verify, where the first share is stored in state depends on the challenge */
    if (challenge == 0) {
        xor_array(state[0], state[0], in, len);
    }
    else if (challenge == 2) {
        xor_array(state[1], state[1], in, len);
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
    /* challenge must have length numBytes(numMPCRounds*2)
     * 0 <= index < numMPCRounds
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
        commitments_t* as, uint8_t* challengeBits, const uint8_t* salt,
        const uint8_t* message, size_t messageByteLength,
        g_commitments_t* gs, paramset_t* params)
{
    uint8_t* hash = malloc(params->digestSizeBytes);
    HashInstance ctx;

    /* Depending on the number of rounds, we might not set part of the last
     * byte, make sure it's always zero. */
    challengeBits[numBytes(params->numMPCRounds * 2) - 1] = 0;

    HashInit(&ctx, params, HASH_PREFIX_1);

    /* Hash the output share from each view */
    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, (uint8_t*)VIEW_OUTPUTS(i, j), params->stateSizeBytes);
        }
    }

    /* Hash all the commitments C */
    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, as[i].hashes[j], params->digestSizeBytes);
        }
    }

    /* Hash all the commitments G */
    if (params->transform == TRANSFORM_UR) {
        for (uint32_t i = 0; i < params->numMPCRounds; i++) {
            for (int j = 0; j < 3; j++) {
                size_t view3UnruhLength = (j == 2) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
                HashUpdate(&ctx, gs[i].G[j], view3UnruhLength);
            }
        }
    }

    /* Hash the public key */
    HashUpdate(&ctx, (uint8_t*)circuitOutput, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);

    /* Hash the salt & message */
    HashUpdate(&ctx, salt, params->saltSizeBytes);
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
                    if (round == params->numMPCRounds) {
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
        memcpy(proof->seed1, seeds->seed[0], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[1], params->seedSizeBytes);
    }
    else if (challenge == 1) {
        memcpy(proof->seed1, seeds->seed[1], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[2], params->seedSizeBytes);
    }
    else if (challenge == 2) {
        memcpy(proof->seed1, seeds->seed[2], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[0], params->seedSizeBytes);
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

void mpc_matrix_mul(uint32_t* output[3], uint32_t* state[3], const uint32_t* matrix,
                    paramset_t* params, size_t players)
{
    for (uint32_t player = 0; player < players; player++) {
        matrix_mul(output[player], state[player], matrix, params);
    }
}

void mpc_LowMC_verify(view_t* view1, view_t* view2,
                      randomTape_t* tapes, uint32_t* tmp,
                      const uint32_t* plaintext, paramset_t* params, uint8_t challenge)
{
    uint32_t* state[2];
    uint32_t* keyShares[2];
    uint32_t* roundKey[2];

    memset(tmp, 0, 4 * params->stateSizeWords * sizeof(uint32_t));
    roundKey[0] = tmp;
    roundKey[1] = roundKey[0] + params->stateSizeWords;
    state[0] = roundKey[1] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;

    mpc_xor_constant_verify(state, plaintext, params->stateSizeWords, challenge);

    keyShares[0] = view1->inputShare;
    keyShares[1] = view2->inputShare;

    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 2);
    mpc_xor(state, roundKey, params->stateSizeWords, 2);

    for (uint32_t r = 1; r <= params->numRounds; ++r) {
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 2);
        mpc_substitution_verify(state, tapes, view1, view2, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 2);
        mpc_xor_constant_verify(state, RConstant(r - 1, params), params->stateSizeWords, challenge);
        mpc_xor(state, roundKey, params->stateSizeWords, 2);
    }

    memcpy(view1->outputShare, state[0], params->stateSizeBytes);
    memcpy(view2->outputShare, state[1], params->stateSizeBytes);
}

void verifyProof(const proof_t* proof, view_t* view1, view_t* view2,
                 uint8_t challenge, uint8_t* salt, uint16_t roundNumber, uint8_t* tmp,
                 const uint32_t* plaintext, randomTape_t* tape, paramset_t* params)
{
    memcpy(view2->communicatedBits, proof->communicatedBits, params->andSizeBytes);
    tape->pos = 0;

    bool status = false;
    switch (challenge) {
    case 0:
        // in this case, both views' inputs are derivable from the input share
        status = createRandomTape(proof->seed1, salt, roundNumber, 0, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
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
        status = createRandomTape(proof->seed1, salt, roundNumber, 1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 2, tape->tape[1], params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, proof->inputShare, params->stateSizeBytes);
        break;

    case 2:
        // in this case view1's input share was already given to us explicitly as
        // it is not computable from the seed. We just need to compute view2's input from
        // its seed
        status = createRandomTape(proof->seed1, salt, roundNumber, 2, tape->tape[0], params->andSizeBytes, params);
        memcpy(view1->inputShare, proof->inputShare, params->stateSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 0, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[1], tmp + params->stateSizeBytes, params->andSizeBytes);
        break;

    default:
        PRINT_DEBUG(("Invalid Challenge"));
        break;
    }

    if (!status) {
        PRINT_DEBUG(("Failed to generate random tapes, signature verification will fail (but signature may actually be valid)\n"));
    }

    /* When input shares are read from the tapes, and the length is not a whole number of bytes, the trailing bits must be zero */
    zeroTrailingBits((uint8_t*)view1->inputShare, params->stateSizeBits);
    zeroTrailingBits((uint8_t*)view2->inputShare, params->stateSizeBits);

    mpc_LowMC_verify(view1, view2, tape, (uint32_t*)tmp, plaintext, params, challenge);
}

int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext,
           const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    commitments_t* as = allocateCommitments(params, 0);
    g_commitments_t* gs = allocateGCommitments(params);

    uint32_t** viewOutputs = malloc(params->numMPCRounds * 3 * sizeof(uint32_t*));
    const proof_t* proofs = sig->proofs;

    const uint8_t* received_challengebits = sig->challengeBits;
    int status = EXIT_SUCCESS;
    uint8_t* computed_challengebits = NULL;
    uint32_t* view3Slab = NULL;

    uint8_t* tmp = malloc(MAX(6 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    randomTape_t* tape = (randomTape_t*)malloc(sizeof(randomTape_t));

    allocateRandomTape(tape, params);

    view_t* view1s = malloc(params->numMPCRounds * sizeof(view_t));
    view_t* view2s = malloc(params->numMPCRounds * sizeof(view_t));

    /* Allocate a slab of memory for the 3rd view's output in each round */
    view3Slab = calloc(params->stateSizeBytes, params->numMPCRounds);
    uint32_t* view3Output = view3Slab;     /* pointer into the slab to the current 3rd view */

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        allocateView(&view1s[i], params);
        allocateView(&view2s[i], params);

        verifyProof(&proofs[i], &view1s[i], &view2s[i],
                    getChallenge(received_challengebits, i), sig->salt, i,
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
        xor_three(view3Output, view1s[i].outputShare,  view2s[i].outputShare, pubKey, params->stateSizeBytes); 
        VIEW_OUTPUTS(i, (challenge + 2) % 3) = view3Output;
        view3Output = (uint32_t*) ((uint8_t*)view3Output + params->stateSizeBytes);
    }

    computed_challengebits = malloc(numBytes(2 * params->numMPCRounds));

    H3(pubKey, plaintext, viewOutputs, as,
       computed_challengebits, sig->salt, message, messageByteLength, gs, params);

    if (computed_challengebits != NULL &&
        memcmp(received_challengebits, computed_challengebits, numBytes(2 * params->numMPCRounds)) != 0) {
        PRINT_DEBUG(("Invalid signature. Did not verify\n"));
        status = EXIT_FAILURE;
    }

    free(computed_challengebits);
    free(view3Slab);

    freeCommitments(as);
    for (size_t i = 0; i < params->numMPCRounds; i++) {
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

#if 0   /* Debugging helper: reconstruct a secret shared value and print it */
void print_reconstruct(const char* label, uint32_t* s[3], size_t lengthBytes)
{
    uint32_t temp[LOWMC_MAX_WORDS] = {0};
    xor_three(temp, s[0], s[1], s[2], lengthBytes);
#if 0
    printf("\n");
    printHex("s0", (uint8_t*)s[0], lengthBytes); 
    printHex("s1", (uint8_t*)s[1], lengthBytes); 
    printHex("s2", (uint8_t*)s[2], lengthBytes); 
#endif
    printHex(label, (uint8_t*)temp, lengthBytes);
}
#endif

void mpc_LowMC(randomTape_t* tapes, view_t views[3],
               const uint32_t* plaintext, uint32_t* slab, paramset_t* params)
{
    uint32_t* keyShares[3];
    uint32_t* state[3];
    uint32_t* roundKey[3];

    memset(slab, 0x00, 6 * params->stateSizeWords * sizeof(uint32_t));
    roundKey[0] = slab;
    roundKey[1] = slab + params->stateSizeWords;
    roundKey[2] = roundKey[1] + params->stateSizeWords;
    state[0] = roundKey[2] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;
    state[2] = state[1] + params->stateSizeWords;

    for (int i = 0; i < 3; i++) {
        keyShares[i] = views[i].inputShare;
    }
    mpc_xor_constant(state, plaintext, params->stateSizeWords);
    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 3);
    mpc_xor(state, roundKey, params->stateSizeWords, 3);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 3);
        mpc_substitution(state, tapes, views, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 3);
        mpc_xor_constant(state, RConstant(r - 1, params), params->stateSizeWords);
        mpc_xor(state, roundKey, params->stateSizeWords, 3);
    }

    for (int i = 0; i < 3; i++) {
        memcpy(views[i].outputShare, state[i], params->stateSizeBytes);
    }
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
    HashUpdateIntLE(&ctx, params->stateSizeBits);
    HashFinal(&ctx);

    // Derive the N*T seeds + 1 salt
    HashSqueeze(&ctx, allSeeds[0].seed[0], params->seedSizeBytes * (params->numMPCParties * params->numMPCRounds) + params->saltSizeBytes);

    return allSeeds;
}


int sign_picnic1(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message,
                 size_t messageByteLength, signature_t* sig, paramset_t* params)
{
    bool status;

    /* Allocate views and commitments for all parallel iterations */
    view_t** views = allocateViews(params);
    commitments_t* as = allocateCommitments(params, 0);
    g_commitments_t* gs = allocateGCommitments(params);

    /* Compute seeds for all parallel iterations */
    seeds_t* seeds = computeSeeds(privateKey, pubKey, plaintext, message, messageByteLength, params);

    memcpy(sig->salt, seeds[params->numMPCRounds].iSeed, params->saltSizeBytes);

    //Allocate a random tape (re-used per parallel iteration), and a temporary buffer
    randomTape_t tape;

    allocateRandomTape(&tape, params);
    uint8_t* tmp = malloc( MAX(9 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    for (uint32_t k = 0; k < params->numMPCRounds; k++) {
        // for first two players get all tape INCLUDING INPUT SHARE from seed
        for (int j = 0; j < 2; j++) {
            status = createRandomTape(seeds[k].seed[j], sig->salt, k, j, tmp, params->stateSizeBytes + params->andSizeBytes, params);
            if (!status) {
                PRINT_DEBUG(("createRandomTape failed \n"));
                return EXIT_FAILURE;
            }
            memcpy(views[k][j].inputShare, tmp, params->stateSizeBytes);
            zeroTrailingBits((uint8_t*)views[k][j].inputShare, params->stateSizeBits);
            memcpy(tape.tape[j], tmp + params->stateSizeBytes, params->andSizeBytes);
        }

        // Now set third party's wires. The random bits are from the seed, the input is
        // the XOR of other two inputs and the private key
        status = createRandomTape(seeds[k].seed[2], sig->salt, k, 2, tape.tape[2], params->andSizeBytes, params);
        if (!status) {
            PRINT_DEBUG(("createRandomTape failed \n"));
            return EXIT_FAILURE;
        }


        xor_three(views[k][2].inputShare, privateKey, views[k][0].inputShare, views[k][1].inputShare, params->stateSizeBytes);
        tape.pos = 0;
        mpc_LowMC(&tape, views[k], plaintext, (uint32_t*)tmp, params);

        uint32_t temp[LOWMC_MAX_WORDS] = {0};
        xor_three(temp, views[k][0].outputShare, views[k][1].outputShare, views[k][2].outputShare, params->stateSizeBytes);
        if(memcmp(temp, pubKey, params->stateSizeBytes) != 0) {
            PRINT_DEBUG(("Simulation failed; output does not match public key (round = %u)\n", k));
            return EXIT_FAILURE;
        }

        //Committing
        Commit(seeds[k].seed[0], views[k][0], as[k].hashes[0], params);
        Commit(seeds[k].seed[1], views[k][1], as[k].hashes[1], params);
        Commit(seeds[k].seed[2], views[k][2], as[k].hashes[2], params);

        if (params->transform == TRANSFORM_UR) {
            G(0, seeds[k].seed[0], &views[k][0], gs[k].G[0], params);
            G(1, seeds[k].seed[1], &views[k][1], gs[k].G[1], params);
            G(2, seeds[k].seed[2], &views[k][2], gs[k].G[2], params);
        }
    }

    //Generating challenges
    uint32_t** viewOutputs = malloc(params->numMPCRounds * 3 * sizeof(uint32_t*));
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            VIEW_OUTPUTS(i, j) = views[i][j].outputShare;
        }
    }

    H3(pubKey, plaintext, viewOutputs, as,
       sig->challengeBits, sig->salt, message, messageByteLength, gs, params);

    //Packing Z
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        proof_t* proof = &sig->proofs[i];
        prove(proof, getChallenge(sig->challengeBits, i), &seeds[i],
              views[i], &as[i], (gs == NULL) ? NULL : &gs[i], params);
    }


#if 0   /* Self-test, verify the signature we just created */
    printf("\n-----------\n"); 
    int ret = verify(sig, pubKey, plaintext, message, messageByteLength, params);
    if(ret != EXIT_SUCCESS) {
        printf("Self-test of signature verification failed\n");
        exit(-1);
    }
    else {
        printf("Self-test succeeded\n");
    }
    printf("\n-----------\n"); 
#endif


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
    size_t bytesRequired = numBytes(2 * params->numMPCRounds) + params->saltSizeBytes +
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes + params->digestSizeBytes);

    if (params->transform == TRANSFORM_UR) {
        bytesRequired += params->UnruhGWithoutInputBytes * params->numMPCRounds;
    }

    if (sigBytesLen < bytesRequired) {
        return -1;
    }

    uint8_t* sigBytesBase = sigBytes;

    memcpy(sigBytes, challengeBits, numBytes(2 * params->numMPCRounds));
    sigBytes += numBytes(2 * params->numMPCRounds);

    memcpy(sigBytes, sig->salt, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numMPCRounds; i++) {

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

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        uint8_t challenge = getChallenge(challengeBits, i);
        if (challenge == 1 || challenge == 2) {
            inputShareSize += stateSizeBytes;
        }
    }
    return inputShareSize;
}

static int isChallengeValid(uint8_t* challengeBits, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        uint8_t challenge = getChallenge(challengeBits, i);
        if (challenge > 2) {
            return 0;
        }
    }
    return 1;
}

int arePaddingBitsZero(uint8_t* data, size_t bitLength)
{
    size_t byteLength = numBytes(bitLength); 
    for (size_t i = bitLength; i < byteLength * 8; i++) {
        uint8_t bit_i = getBit(data, i);
        if (bit_i != 0) {
            return 0;
        }
    }
    return 1;
}

int deserializeSignature(signature_t* sig, const uint8_t* sigBytes,
                         size_t sigBytesLen, paramset_t* params)
{
    proof_t* proofs = sig->proofs;
    uint8_t* challengeBits = sig->challengeBits;

    /* Validate input buffer is large enough */
    if (sigBytesLen < numBytes(2 * params->numMPCRounds)) {     /* ensure the input has at least the challenge */
        return EXIT_FAILURE;
    }

    size_t inputShareSize = computeInputShareSize(sigBytes, params->stateSizeBytes, params);
    size_t bytesExpected = numBytes(2 * params->numMPCRounds) + params->saltSizeBytes +
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->andSizeBytes + params->digestSizeBytes) + inputShareSize;

    if (params->transform == TRANSFORM_UR) {
        bytesExpected += params->UnruhGWithoutInputBytes * params->numMPCRounds;
    }
    if (sigBytesLen < bytesExpected) {
        return EXIT_FAILURE;
    }

    memcpy(challengeBits, sigBytes, numBytes(2 * params->numMPCRounds));
    sigBytes += numBytes(2 * params->numMPCRounds);

    if (!isChallengeValid(challengeBits, params)) {
        return EXIT_FAILURE;
    }

    memcpy(sig->salt, sigBytes, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numMPCRounds; i++) {

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
            if(!arePaddingBitsZero((uint8_t*)proofs[i].inputShare, params->stateSizeBits)) {
                return EXIT_FAILURE;
            }
        }

    }

    return EXIT_SUCCESS;
}




