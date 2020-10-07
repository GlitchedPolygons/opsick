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

#ifndef OPSICK_CONSTANTS_H
#define OPSICK_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file constants.h
 * @author Raphael Beck
 * @brief Opsick constants (pre-processor #defines).
 */

/**
 * Opsick current version number.
 */
#define OPSICK_SERVER_VERSION 100

/**
 * Opsick current version number string.
 */
#define OPSICK_SERVER_VERSION_STR "1.0.0"

/**
 * The user config file path (must be a <c>.toml</c> file!).
 */
#define OPSICK_CONFIG_FILE_PATH "config.toml"

/**
 * The maximum length of the instance's user creation endpoint password.
 */
#define OPSICK_MAX_USER_CREATION_PASSWORD_LENGTH 1024

/**
 * Maximum amount of threads to allow for usage by Argon2.
 */
#define OPSICK_MAX_ARGON2_PARALLELISM 16

#pragma region HASHES

/**
 * The seed value to use for the MurmurHash v3 algo.
 * Since all of the hash lookups are only correlated
 * to endpoint routing, this value needn't be secret.
 */
#define OPSICK_MURMUR3_SEED 133769420

/**
 * <c>
 * murmur3("/")
 * </c>
 */
#define OPSICK_HOME_PATH_HASH 2818192833

/**
 * <c>
 * murmur3("/favicon.ico")
 * </c>
 */
#define OPSICK_FAVICON_PATH_HASH 1051445893

/**
 * <c>
 * murmur3("/pubkey")
 * </c>
 */
#define OPSICK_PUBKEY_PATH_HASH 3855421118

/**
 * <c>
 * murmur3("/users/prvkey")
 * </c>
 */
#define OPSICK_PRVKEY_PATH_HASH 944329335

/**
 * <c>
 * murmur3("/users/passwd")
 * </c>
 */
#define OPSICK_PASSWD_PATH_HASH 2697305887

/**
 * <c>
 * murmur3("/users/create")
 * </c>
 */
#define OPSICK_USERADD_PATH_HASH 4242582731

/**
 * <c>
 * murmur3("/users/delete")
 * </c>
 */
#define OPSICK_USERDEL_PATH_HASH 1184612068

/**
 * <c>
 * murmur3("/users/extend")
 * </c>
 */
#define OPSICK_USEREXT_PATH_HASH 628309221

/**
 * <c>
 * murmur3("/users/body")
 * </c>
 */
#define OPSICK_USERBODY_PATH_HASH 413204006

/**
 * <c>
 * murmur3("/users/2fa")
 * </c>
 */
#define OPSICK_USER2FA_PATH_HASH 2196777087

/**
 * <c>
 * murmur3("/version")
 * </c>
 */
#define OPSICK_VERSION_PATH_HASH 692047655

#pragma endregion

#pragma region Pre-allocated string IDs

/**
 * Pre-allocated string ID for "ed25519-signature".
 */
#define OPSICK_PREALLOCATED_STRING_ID_ED25519_SIGNATURE 0

#pragma endregion

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONSTANTS_H
