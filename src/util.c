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

#include "opsick/util.h"
#include "opsick/keys.h"
#include <stdio.h>
#include <ed25519.h>
#include <mbedtls/platform_util.h>

static FIOBJ preallocated_string_table[128] = { 0x00 };

void opsick_util_init()
{
    preallocated_string_table[0] = fiobj_str_new("ed25519-signature", 17);
}

void opsick_util_free()
{
    for (unsigned int i = 0; i < sizeof(preallocated_string_table) / sizeof(FIOBJ); i++)
    {
        FIOBJ ie = preallocated_string_table[i];
        if (!fiobj_type_is(ie, FIOBJ_T_NULL))
        {
            fiobj_free(ie);
        }
    }
}

FIOBJ opsick_get_preallocated_string(uint32_t id)
{
    return preallocated_string_table[id];
}

int opsick_hexstr2bin(const char* hexstr, const size_t hexstr_length, uint8_t* output, const size_t output_size, size_t* output_length)
{
    if (hexstr == NULL || output == NULL || hexstr_length == 0)
    {
        return 1;
    }

    const size_t hl = hexstr[hexstr_length - 1] ? hexstr_length : hexstr_length - 1;

    if (hl % 2 != 0)
    {
        return 2;
    }

    const size_t final_length = hl / 2;

    if (output_size < final_length + 1)
    {
        return 3;
    }

    for (size_t i = 0, ii = 0; ii < final_length; i += 2, ii++)
    {
        output[ii] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

int opsick_bin2hexstr(const uint8_t* bin, const size_t bin_length, char* output, const size_t output_size, size_t* output_length, const uint8_t uppercase)
{
    if (bin == NULL || bin_length == 0 || output == NULL)
    {
        return 1;
    }

    const size_t final_length = bin_length * 2;

    if (output_size < final_length + 1)
    {
        return 2;
    }

    const char* format = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < bin_length; i++)
    {
        sprintf(output + i * 2, format, bin[i]);
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

void opsick_sign(const char* string, char* out)
{
    struct opsick_ed25519_keypair keypair;
    opsick_keys_get_ed25519_keypair(&keypair);

    uint8_t signature[64];
    ed25519_sign(signature, (unsigned char*)string, strlen(string), keypair.public_key, keypair.private_key);

    opsick_bin2hexstr(signature, sizeof(signature), out, 128 + 1, NULL, 0);

    mbedtls_platform_zeroize(signature, sizeof(signature));
    mbedtls_platform_zeroize(&keypair, sizeof(keypair));
}