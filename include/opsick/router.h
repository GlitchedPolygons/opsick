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

#ifndef OPSICK_ROUTER_H
#define OPSICK_ROUTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * Pre-allocates values that are used often, reads user config,
 * initializes the HTTP request router, starts listening to HTTP requests
 * on the user-defined port and starts facil.io.
 */
void opsick_router_init();

/**
 * Disables and deallocates the HTTP request router.
 */
void opsick_router_free();

/**
 * Callback for handling HTTP requests.
 * @param request The HTTP request that was obtained (this will be processed based on path, params, etc...).
 */
void opsick_on_request(http_s* request);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_ROUTER_H
