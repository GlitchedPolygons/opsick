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

#ifndef OPSICK_USERDEL_H
#define OPSICK_USERDEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file userdel.h
 * @author Raphael Beck
 * @brief User account deletion endpoint.
 */

/**
 * Initializes the "/users/delete" endpoint.
 */
void opsick_init_endpoint_userdel();

/**
 * POST request to "/users/delete". <p>
 * Deletes a user from the opsick server (irreversibly!).
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_userdel(http_s* request);

/**
 * Frees the "/users/delete" endpoint resources.
 */
void opsick_free_endpoint_userdel();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USERDEL_H