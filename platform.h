/*! @file platform.h
 *  @brief Platform-specific defines.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */


/* __FUNCTION__ generates a warning on Linux with -Wpedantic and newer versions
 * of GCC (tested with 5.4).  So we use __func__ in all source and define it on
 * Windows.
 */
#if defined (__WINDOWS__)
    #define __func__ __FUNCTION__
#endif
