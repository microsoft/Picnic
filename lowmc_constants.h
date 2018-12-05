/*! @file lowmc_constants.h
 *  @brief Constants needed to implement the LowMC block cipher.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef LOWMCCONSTANTS_H
#define LOWMCCONSTANTS_H

#include <stdint.h>
#include <stddef.h>
#include "picnic_impl.h"

#define WORD_SIZE_BITS 32 // the word size for the implementation. Not a LowMC parameter
#define LOWMC_MAX_STATE_SIZE 64
#define LOWMC_MAX_KEY_BITS 256
#define LOWMC_MAX_AND_GATES (3*38*10 + 4)   /* Rounded to nearest byte */

/* Return the LowMC linear matrix for this round */
const uint32_t* LMatrix(uint32_t round, paramset_t* params);

/* Return the LowMC key matrix for this round */
const uint32_t* KMatrix(uint32_t round, paramset_t* params);

/* Return the LowMC round constant for this round */
const uint32_t* RConstant(uint32_t round, paramset_t* params);



#endif /* LOWMCCONSTANTS_H */




