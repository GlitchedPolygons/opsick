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

#ifndef OPSICK_PASSWD_H
#define OPSICK_PASSWD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file passwd.h
 * @author Raphael Beck
 * @brief User account password change endpoint.
 */

/**
 * Initializes the "/users/passwd" endpoint.
 */
void opsick_init_endpoint_passwd();

/**
 * POST request to "/users/passwd". <p>
 * User password change request, containing the old pw, the new pw as well as a TOTP (if 2FA is enabled).
 * @param request The HTTP request.
 */
void opsick_post_passwd(http_s* request);

/**
 * Frees the "/users/passwd" endpoint resources.
 */
void opsick_free_endpoint_passwd();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_PASSWD_H
