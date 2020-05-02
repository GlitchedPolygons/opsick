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

#ifndef OPSICK_CONSTANTS_H
#define OPSICK_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"

int _opsick_constants_initialized = 0;
FIOBJ HTTP_HEADER_X_DATA;

void opsick_init_constants()
{
    if (_opsick_constants_initialized)
    {
        return;
    }
    _opsick_constants_initialized = 1;

    HTTP_HEADER_X_DATA = fiobj_str_new("X-Data", 6);
}

void opsick_free_constants()
{
    if (!_opsick_constants_initialized)
    {
        return;
    }
    _opsick_constants_initialized = 0;

    fiobj_free(HTTP_HEADER_X_DATA);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONSTANTS_H
