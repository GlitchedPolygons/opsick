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

#include "opsick/db.h"
#include <string.h>
#include <stdbool.h>
#include <mbedtls/platform_util.h>

static bool initialized = false;
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;
static uint8_t last128B[128];

bool opsick_db_init()
{
    if (initialized)
        return true;

    return initialized = true;
}

uint64_t opsick_db_get_schema_version_number()
{
    if (last_db_schema_version_nr_lookup + 3600 > time(NULL))
    {
        last_db_schema_version_nr_lookup = time(NULL);
        return cached_db_schema_version_nr;
    }

    return 0;
}

uint64_t opsick_db_get_last_used_userid()
{
    return last_used_userid;
}

void opsick_db_last_128_bytes_of_ciphertext(uint8_t out[128])
{
    if (out == NULL)
    {
        return;
    }
    memcpy(out, last128B, 128);
}

time_t opsick_db_get_last_db_schema_version_nr_lookup()
{
    return last_db_schema_version_nr_lookup;
}

void opsick_db_free()
{
    if (!initialized)
        return;

    initialized = false;

    mbedtls_platform_zeroize(last128B, sizeof(last128B));
    mbedtls_platform_zeroize(&last_used_userid, sizeof(last_used_userid));
}