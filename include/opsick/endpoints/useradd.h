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

#ifndef OPSICK_USERADD_H
#define OPSICK_USERADD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * Initializes the "/users/create" endpoint.
 */
void opsick_init_endpoint_useradd();

/**
 * POST request to "/users/create". <p>
 * Creates a new user on the opsick server.
 * The user ID + other parameters should be passed in the request body.
 * @param request The HTTP request.
 */
void opsick_post_useradd(http_s* request);

/**
 * Frees the "/users/create" endpoint resources.
 */
void opsick_free_endpoint_useradd();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USERADD_H
