/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef OPSICK_KEYS_H
#define OPSICK_KEYS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ed25519.h>
#include <cecies/keygen.h>

/**
 * @file keys.h
 * @author Raphael Beck
 * @brief Opsick key handling.
 */

/**
 * Initialize opsick keygen.
 */
void opsick_keys_init();

/**
 * Free opsick keys and turn off keygen.
 */
void opsick_keys_free();

/**
 * An Ed25519 keypair containing both hex-encoded string representations
 * as well as raw byte arrays of the opsick signing keys.
 */
struct opsick_ed25519_keypair
{
    char public_key_hexstr[64 + 1];
    char private_key_hexstr[128 + 1];
    uint8_t public_key[32];
    uint8_t private_key[64];
};

/**
 * Gets the currently used opsick signing keypair (used for signing/verifying opsick HTTP responses).
 * @param out Where to write the keypair into.
 */
void opsick_keys_get_ed25519_keypair(struct opsick_ed25519_keypair* out);

/**
 * Gets the currently used opsick encryption keypair (used for communicating with the server over non-secure protocols (e.g. plain HTTP)).
 * @param out Where to write the keypair into.
 */
void opsick_keys_get_curve448_keypair(struct cecies_curve448_keypair* out);

/**
 * Get readily formatted JSON containing Opsick server public keys.
 * @param out A writable output char buffer that is at least 256B big!
 * @param outlen Where to write the written output json string's length into.
 */
void opsick_keys_get_public_keys_json(char* out, size_t* outlen);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_KEYS_H
