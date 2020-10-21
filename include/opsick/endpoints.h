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

#ifndef OPSICK_ENDPOINTS_H
#define OPSICK_ENDPOINTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file endpoints.h
 * @author Raphael Beck
 * @brief Opsick server endpoints.
 */

/**
 * Initializes all opsick endpoints.
 */
void opsick_endpoints_init();

/**
 * Free opsick keys and turn off keygen.
 */
void opsick_endpoints_free();

/**
 * GET request to home (path "/").
 * @param request The HTTP request.
 */
void opsick_get_home(http_s* request);

/**
 * GET request to "/pubkey". <p>
 * Gets the server's public key and returns it in the HTTP response body.
 * @param request The HTTP request.
 */
void opsick_get_pubkey(http_s* request);

/**
 * POST request to "/users/create". <p> <strong>Requires API Key</strong> <p>
 * Creates a new user on the opsick server.
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_users_create(http_s* request);

/**
 * POST request to "/users/body". <p>
 * @param request The HTTP request.
 */
void opsick_post_users_body(http_s* request);

/**
 * POST request to "/users/passwd". <p>
 * User password change request, containing the old pw, the new pw as well as a TOTP (if 2FA is enabled).
 * @param request The HTTP request.
 */
void opsick_post_users_passwd(http_s* request);

/**
 * POST request to "/users/2fa". <p>
 * @param request The HTTP request.
 */
void opsick_post_users_2fa(http_s* request);

/**
 * POST request to "/users/delete". <p>
 * Deletes a user from the opsick server (irreversibly!).
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_users_delete(http_s* request);

/**
 * POST request to "/users/extend". <p> <strong>Requires API Key</strong> <p>
 * Extends a user account on the opsick server. This request needs to be signed by the API master with the API key.
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_users_extend(http_s* request);

/**
 * POST request to "/users". <p>
 * Gets a user's metadata from the server db. <p>
 * This is POST because the request requires a body, but technically it's a "get" operation.
 * @param request The HTTP request.
 */
void opsick_post_users(http_s* request);

/**
 * POST request to "/users/keys". <p>
 * Gets a user's encrypted private keys from the server db. <p>
 * This is POST because the request requires a body, but technically it's a "get" operation.
 * @param request The HTTP request.
 */
void opsick_post_users_keys(http_s* request);

/**
 * POST request to "/users/keys/update". <p>
 * Submits a new set of fresh user keypairs to the opsick server (clients are allowed to regenerate their keys at will). <p>
 * This is POST because the request requires a body, but technically it's a "get" operation.
 * @param request The HTTP request.
 */
void opsick_post_users_keys_update(http_s* request);

/**
 * GET request to "/version". <p>
 * Gets the server's version number and schema version number and returns it in the HTTP response body.
 * @param request The HTTP request.
 */
void opsick_get_version(http_s* request);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_ENDPOINTS_H
