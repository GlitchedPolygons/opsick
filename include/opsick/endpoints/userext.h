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

#ifndef OPSICK_USEREXT_H
#define OPSICK_USEREXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file userext.h
 * @author Raphael Beck
 * @brief User account extension endpoint.
 */

/**
 * Initializes the "/users/extend" endpoint.
 */
void opsick_init_endpoint_userext();

/**
 * POST request to "/users/extend". <p>
 * Extends a user account on the opsick server. This request needs to be signed by the API master with the API key.
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_userext(http_s* request);

/**
 * Frees the "/users/extend" endpoint resources.
 */
void opsick_free_endpoint_userext();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USEREXT_H
