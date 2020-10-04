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

#ifndef OPSICK_USER2FA_H
#define OPSICK_USER2FA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * Initializes the "/users/2fa" endpoint.
 */
void opsick_init_endpoint_user2fa();

/**
 * POST request to "/users/2fa". <p>
 * @param request The HTTP request.
 */
void opsick_post_user2fa(http_s* request);

/**
 * Frees the "/users/2fa" endpoint resources.
 */
void opsick_free_endpoint_user2fa();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USER2FA_H
