/*! @file LowMCEnc.h
 *  @brief Header file for LowMcEnc.c, the C implementation of LowMC.
 *
 *  This file is part of the reference implementation of the Picnic and Fish
 *  signature schemes, described in the paper:
 *
 *  Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives
 *  Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi and
 *  Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg
 *  Zaverucha
 *  Cryptology ePrint Archive: Report 2017/279
 *  http://eprint.iacr.org/2017/279
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *
 */

#ifndef LowMCEnc_h
#define LowMCEnc_h

#include <stdint.h>
#include "LowMCConstants.h"


/** Encrypt one block of data with the specified LowMC parameter set
 *
 * @param plaintext[in]  The plaintext to encrypt, must have length STATE_SIZE_BYTES
 * @param ciphertext[in,out] The output ciphertext, must have length STATE_SIZE_BYTES
 * @param key[in]  The key to use for encryption. Must have length STATE_SIZE_BYTES
 * @param parameters[in] The LowMC parameter set to be used
 *
 * @remark Before encryption, readLookupTables must be called, and afterwards
 * freeLookupTables should be called to free memory.
 */
void LowMCEnc(const uint32_t* plaintext, uint32_t* ciphertext,
              const uint32_t* key, lowmcparams_t* parameters);

/** Read precomputed data required by LowMCEnc() from processedMatrices.bin */
int readLookupTables(lowmcparams_t* params);

/** Free memory allocated by readLookupTables */
void freeLookupTables();

#endif /* LowMcEnc_h */
