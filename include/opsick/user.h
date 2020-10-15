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

#ifndef OPSICK_USER_H
#define OPSICK_USER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file user.h
 * @author Raphael Beck
 * @brief Contains the opsick_user_metadata struct.
 */

#include <stdint.h>
#include <cecies/types.h>

/**
 * Everything about an opsick user except his or her content body.
 */
struct opsick_user_metadata
{
    /**
     * User ID (unsigned 64-bit integer, DB primary key for the users table).
     */
    uint64_t id;

    /**
     * A user's password (or rather, its salted, hashed and encoded representation).
     */
    char pw[256];

    /**
     * 2FA secret that the user will use to generate TOTPs. This will only be presented exactly ONCE on enable!
     */
    char totps[48 + 1];

    /**
     * The Unix timestamp of when the user account was created.
     */
    uint64_t iat_utc;

    /**
     * Unix timestamp of when the user account will expire (become read-only).
     */
    uint64_t exp_utc;

    /**
     * Unix timestamp of when the user last posted an update of any form.
     */
    uint64_t lastmod_utc;

    /**
     * The NUL-terminated, hex-encoded string of the user's body, hashed using SHA2-512.
     */
    char body_sha512[128 + 1];

    /**
     * The user's public Ed25519 key (the opsick server will use this to verify the user's request signatures).
     */
    struct cecies_curve25519_key public_key_ed25519;

    /**
     * The user's private Ed25519 key (this is encrypted client-side, and is used by the user to sign requests to the server).
     */
    char encrypted_private_key_ed25519[256];

    /**
     * The user's public Curve448 key (the opsick server will use this to encrypt HTTP responses for the user).
     */
    struct cecies_curve448_key public_key_curve448;

    /**
     * The user's private Ed25519 key (this is encrypted client-side, and is used by the user to decrypt encrypted HTTP responses sent by the server).
     */
    char encrypted_private_key_curve448[256];
};

/**
 * Check whether a given user has 2FA enabled or not.
 * @param user_metadata The user to check.
 * @return boolean: <c>0</c> for false; <c>1</c> for true.
 */
static inline int opsick_user_has_2fa_enabled(struct opsick_user_metadata* user_metadata)
{
    if (!user_metadata)
    {
        return 0;
    }

    for (int i = 0; i < sizeof(user_metadata->totps); i++)
    {
        if (user_metadata->totps[i] != '\0')
        {
            return 1;
        }
    }

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USER_H
