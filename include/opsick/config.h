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

#ifndef OPSICK_CONFIG_H
#define OPSICK_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "opsick/constants.h"

/**
 * @file config.h
 * @author Raphael Beck
 * @brief Opsick configuration tools/functions/structures.
 */

/**
 * Opens the opsick config table,
 * reads the user-defined preferences/settings in it
 * and loads them into memory.
 * @return Whether loading the opsick config from db succeeded ( \c 1 ) or not ( \c 0 ).
 */
int opsick_config_load();

/**
 * The host section of the opsick config file (port number, max. HTTP header size, etc...).
 */
struct opsick_config_hostsettings
{
    /**
     * The port number on which opsick should listen for requests. <p>
     * [DEFAULT] <c>6677</c>
     */
    uint16_t port;

    /**
     * The number of threads to dedicate to opsick. <p>
     * [DEFAULT] <c>2</c>
     */
    uint8_t threads;

    /**
     * The maximum number of clients that are allowed to connect concurrently. <p>
     * [DEFAULT] Computed automatically by facil.io (if this value is left at <c>0</c>).
     */
    uint64_t max_clients;

    /**
     * The maximum HTTP header size. <p>
     * [DEFAULT] <c>16KB</c> (<c>1024 * 16B</c>).
     */
    uint64_t max_header_size;

    /**
     * The maximum request body size (use this to protect your db from growing too big!). <p>
     * [DEFAULT] <c>16MB</c> (<c>1024 * 1024 * 16 B</c>).
     */
    uint64_t max_body_size;
};

/**
 * Gets the current host settings from the <c>[host]</c> section inside the opsick config file (as a copy, so it's read-only).
 * @param out An opsick_config_hostsettings instance into which to write the parsed config values. If retrieval fails in any way, this is left untouched!
 * @return \c 1 if retrieval succeeded; \c 0 if retrieval failed due to invalid arguments (e.g. <c>NULL</c>).
 */
int opsick_config_get_hostsettings(struct opsick_config_hostsettings* out);

// ---------------------------------------------------------------------------------------------------

/**
 * The admin section of the opsick config file.
 */
struct opsick_config_adminsettings
{
    /**
     * The maximum amount of users the opsick instance is allowed to have
     * (if this limit is reached, the registration endpoint is disabled). <p>
     * [DEFAULT] <c>0</c> (which means unlimited).
     */
    uint64_t max_users;

    /**
     * Set this to a non-zero value if you want to let the home endpoint (reachable under "/")
     * serve the index.html file that's located inside the directory where the opsick executable resides. <p>
     * You could for example modify that \c index.html file and customize it to your needs,
     * add some sort of welcome screen to your users and basically do whatever you like with it. <p>
     * If set to <c>0</c>, the \c "/" endpoint just returns a plain HTTP status code 200 ("OK").
     * In that case, the whole opsick instance would act as a plain Web API without any visual feedback/interface. <p>
     * [DEFAULT] \c 1
     */
    uint8_t use_index_html;

    /**
     * Define the interval (in hours) at which the opsick server keys are auto-replaced with freshly generated ones. <p>
     * These keys (one pair of public and private key) are used by the server to sign HTTP responses (private key),
     * and by the clients to verify the HTTP responses' signature (public key). <p>
     * [DEFAULT] <c>72</c> (after 72 hours the server keys are regenerated and the old ones discarded).
     */
    uint64_t key_refresh_interval_hours;

    /**
     * The user registration password is an Argon2 encoded hash of the password that the API master needs to additionally pass to the opsick server as a request parameter when trying to create a new user. <p>
     * [DEFAULT] <code>argon2id("opsick_registration_password")</code>
     */
    char user_registration_password[OPSICK_MAX_USER_CREATION_PASSWORD_LENGTH];

    /**
     * Time cost parameter for the Argon2 hashing (the higher this iteration count, the slower the hashing, the safer the passwords).
     */
    uint32_t argon2_time_cost;

    /**
     * Memory cost parameter for the Argon2 hashing (higher == slower == safer).
     */
    uint32_t argon2_memory_cost;

    /**
     * Amount of threads to use for the Argon2 hashing.
     */
    uint32_t argon2_parallelism;

    /**
     * The algorithm ID for the API key.
     */
    uint8_t api_key_algo;

    /**
     * The public key to use for verifying requests that come from the API master,
     * who signs the requests using this key's private counterpart. <p>
     * The API master is whoever has the private key for signing requests to this backend to create and extend users. It's kinda like an admin.
     */
    uint8_t api_key_public[32];

    /**
     * The hex-encoded #api_key_public string (NUL-terminated). <p>
     * It's the hex-encoded Ed25519 key with which to verify API requests
     * such as user creation and user extension (the API master needs to sign his request's body with the private counterpart of that key).
     */
    char api_key_public_hexstr[64 + 1];
};

/**
 * Gets the current admin settings from the <c>[admin]</c> section inside the opsick config file (as a copy, so it's read-only).
 * @param out An opsick_config_adminsettings instance into which to write the parsed config values. If retrieval fails in any way, this is left untouched!
 * @return <c>1</c> if retrieval succeeded; <c>0</c> if retrieval failed due to invalid arguments (e.g. <c>NULL</c>).
 */
int opsick_config_get_adminsettings(struct opsick_config_adminsettings* out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONFIG_H
