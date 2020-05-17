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

#ifndef OPSICK_KEYS_H
#define OPSICK_KEYS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <mbedtls/pk.h>

/**
 * Gets the currently used key context (a copy of the internally used MbedTLS pk_context struct).
 */
mbedtls_pk_context opsick_keys_get_pk_context();

/**
 * Gets the PEM-formatted public key string from the currently used opsick keypair (use this to verify opsick HTTP response signatures).
 * @param out The <c>char[]</c> array into which to write the PEM-formatted key string.
 * @param out_len The maximum output array size (must be at least 4KB)
 * @return <c>0</c> if retrieval succeeds, <c>1</c> if the output array pointer was <c>NULL</c>, <c>2</c> if the output array is not big enough (please allocate at least 4KB).
 */
int opsick_keys_get_pubkey_pem(char* out, size_t out_len);

/**
 * Gets the PEM-formatted private key string from the currently used opsick keypair (use this to sign opsick HTTP responses).
 * @param out The <c>char[]</c> array into which to write the PEM-formatted key string.
 * @param out_len The maximum output array size (must be at least 4KB)
 * @return <c>0</c> if retrieval succeeds, <c>1</c> if the output array pointer was <c>NULL</c>, <c>2</c> if the output array is not big enough (please allocate at least 4KB).
 */
int opsick_keys_get_prvkey_pem(char* out, size_t out_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_KEYS_H
