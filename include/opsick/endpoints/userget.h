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

#ifndef OPSICK_USERGET_H
#define OPSICK_USERGET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file userget.h
 * @author Raphael Beck
 * @brief User metadata fetch endpoint.
 */

/**
 * Initializes the "/users" endpoint.
 */
void opsick_init_endpoint_userget();

/**
 * POST request to "/users". <p>
 * Gets a user's metadata from the server db.
 * @param request The HTTP request.
 */
void opsick_get_user(http_s* request);

/**
 * POST request to "/users/keys". <p>
 * Gets a user's encrypted private keys from the server db.
 * @param request The HTTP request.
 */
void opsick_get_user_keys(http_s* request);

/**
 * Frees the "/users" endpoint resources.
 */
void opsick_free_endpoint_userget();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USERGET_H
