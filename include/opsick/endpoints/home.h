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

#ifndef OPSICK_HOME_H
#define OPSICK_HOME_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

/**
 * @file home.h
 * @author Raphael Beck
 * @brief Opsick home endpoint ("/").
 */

/**
* Initializes the "/" endpoint.
*/
void opsick_init_endpoint_home();

/**
 * GET request to home (path "/").
 * @param request The HTTP request.
 */
void opsick_get_home(http_s* request);

/**
 * Frees the "/" endpoint resources.
 */
void opsick_free_endpoint_home();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_HOME_H
