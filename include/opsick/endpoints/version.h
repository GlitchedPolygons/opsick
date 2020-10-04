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

#ifndef OPSICK_VERSION_H
#define OPSICK_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * Initializes the "/pubkey" endpoint.
 */
void opsick_init_endpoint_version();

/**
 * GET request to "/version". <p>
 * Gets the server's version number and schema version number and returns it in the HTTP response body.
 * @param request The HTTP request.
 */
void opsick_get_version(http_s* request);

/**
 * Frees the "/version" endpoint resources.
 */
void opsick_free_endpoint_version();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_VERSION_H
