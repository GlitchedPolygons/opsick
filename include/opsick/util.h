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

#ifndef OPSICK_UTIL_H
#define OPSICK_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file util.h
 * @author Raphael Beck
 * @brief Opsick utility functions and pre-allocated content.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <http.h>
#include <sqlite3.h>

/**
 * <c>x < y ? x : y</c>
 */
#define OPSICK_MIN(x, y) (((x) < (y)) ? (x) : (y))

/**
 * <c>x > y ? x : y</c>
 */
#define OPSICK_MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * Gets a pre-allocated string (e.g. for response header names).
 * @param id The string id to use for retrieval.
 * @return The pre-allocated string.
 */
FIOBJ opsick_get_preallocated_string(uint32_t id);

/**
 * Initialize the Opsick utility functions.
 */
void opsick_util_init();

/**
 * Deallocate the Opsick utility functions (freeing their used memory).
 */
void opsick_util_free();

/**
 * Converts a hex string to binary array. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!
 * @param hexstr The hex string to convert.
 * @param hexstr_length Length of the \p hexstr
 * @param output Where to write the converted binary data into.
 * @param output_size Size of the output buffer (make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!).
 * @param output_length [OPTIONAL] Where to write the output array length into. This is always gonna be <c>hexstr_length / 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the hexadecimal string is in an invalid format (e.g. not divisible by 2). <c>3</c> if output buffer size was insufficient (needs to be at least <c>(hexstr_length / 2) + 1</c> bytes).
 */
int opsick_hexstr2bin(const char* hexstr, size_t hexstr_length, uint8_t* output, size_t output_size, size_t* output_length);

/**
 * Converts a byte array to a hex string. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param bin The binary data to convert into hex string.
 * @param bin_length Length of the \p bin array.
 * @param output Where to write the hex string into.
 * @param output_size Maximum capacity of the \p output buffer. Make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param output_length [OPTIONAL] Where to write the output string length into. This is always gonna be <c>bin_length * 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @param uppercase Should the \p output string characters be UPPER- or lowercase? <c>0 == false; anything else == true</c>
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the output buffer size is insufficient: please allocate at least <c>(bin_length * 2) + 1</c> bytes!
 */
int opsick_bin2hexstr(const uint8_t* bin, size_t bin_length, char* output, size_t output_size, size_t* output_length, uint8_t uppercase);

/**
 * Signs a string using the opsick server's private signing key.
 * @param string The NUL-terminated string to sign.
 * @param string_length Length of \p string argument (passing <c>0</c> will result in usage of <c>strlen()</c>).
 * @param out A writable output buffer of at least 129B size (128 characters + 1 NUL-terminator).
 */
void opsick_sign(const char* string, size_t string_length, char* out);

/**
 * Signs a string using the opsick server's private signing key
 * and sets the HTTP response signature header + body accordingly.
 * @param request The HTTP request.
 * @param body The response body to sign and send.
 * @param body_length Length of the passed \p body parameter.
 */
void opsick_sign_and_send(http_s* request, char* body, size_t body_length);

/**
 * Checks whether a given request has a signature header or not.
 * @param request The request to check.
 * @return <c>1</c> if the request has a signature header; <c>0</c> if \p request is <c>NULL</c> or has no signature header.
 */
int opsick_request_has_signature(http_s* request);

/**
 * Verifies an HTTP request's signature.
 * @param request The HTTP request whose body signature you want to verify.
 * @return <c>1</c> if the signature is valid; <c>0</c> if otherwise.
 */
int opsick_verify_api_request_signature(http_s* request);

/**
 * Verifies an HTTP request's signature.
 * @param request The HTTP request whose body signature you want to verify.
 * @param public_key The public key to use for verifying the signature.
 * @return <c>1</c> if the signature is valid; <c>0</c> if otherwise.
 */
int opsick_verify_request_signature(http_s* request, const char* public_key);

/**
 * Decrypts an HTTP request's body that was encrypted for the Opsick server.
 * @param request The HTTP request to decrypt.
 * @param out Where to write the decrypted HTTP request body into (this will be allocated on success, so remember to <c>free()</c> this).
 * @return <c>0</c> if decryption succeeded. Non-zero error code if decryption failed.
 */
int opsick_decrypt(http_s* request, char** out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_UTIL_H
