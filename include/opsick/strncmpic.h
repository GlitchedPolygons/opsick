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

#ifndef OPSICK_STRNCMPIC_H
#define OPSICK_STRNCMPIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <string.h>
#include <limits.h>

/**
 * Compares two strings ignoring UPPER vs. lowercase.
 * @param str1 String to compare.
 * @param str2 String to compare to.
 * @param n How many characters of the string should be compared (starting from index 0)?
 * @return If the strings are equal, <code>0</code> is returned. Otherwise, something else.
 */
int opsick_strncmpic(const char* str1, const char* str2, size_t n);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_STRNCMPIC_H
