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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include "opsick/constants.h"
#include "opsick/config.h"
#include "opsick/guid.h"
#include "opsick/keys.h"
#include <mbedtls/platform_util.h>
#include <opsick/db.h>

static char firstgen = 1;
static time_t last_key_refresh = 0;

static opsick_ed25519_keypair ed25519_keypair;
static cecies_curve448_keypair curve448_keypair;

static struct opsick_config_hostsettings hostsettings;
static struct opsick_config_adminsettings adminsettings;

static void keyregen()
{
    if (firstgen)
    {
        opsick_config_get_hostsettings(&hostsettings);
        opsick_config_get_adminsettings(&adminsettings);
    }

    if (hostsettings.log)
        printf("Regenerating opsick keypair - time for a pair of fresh keys!\n");

    // TODO: regen here ed25519

    char additional_entropy[256];
    uint8_t sick_randomness[128];
    opsick_db_last_128_bytes_of_ciphertext(sick_randomness);

    sprintf(additional_entropy, "%ld", last_key_refresh);
    sprintf(additional_entropy, "%ld", time(0) + 420 + 1337);
    memcpy(additional_entropy + 128, sick_randomness, 128);
    snprintf(additional_entropy, 128, "%llu-%ld-%ld-%ld-%s", opsick_db_get_last_used_userid(), last_key_refresh, opsick_db_get_last_db_schema_version_nr_lookup(), time(0) + 420 + 1337, opsick_new_guid(true, true).string);

    cecies_generate_curve448_keypair(&curve448_keypair, (unsigned char*)additional_entropy, sizeof(additional_entropy));

    firstgen = 0;
    last_key_refresh = time(0);

    mbedtls_platform_zeroize(additional_entropy, sizeof(additional_entropy));
    mbedtls_platform_zeroize(sick_randomness, sizeof(sick_randomness));
}

static inline void check_freshness()
{
    if (time(0) > last_key_refresh + (adminsettings.key_refresh_interval_hours * 3600))
    {
        keyregen();
    }
}

void opsick_keys_init()
{
    keyregen();
}

void opsick_keys_free()
{
    mbedtls_platform_zeroize(&hostsettings, sizeof(hostsettings));
    mbedtls_platform_zeroize(&adminsettings, sizeof(adminsettings));
    mbedtls_platform_zeroize(&ed25519_keypair, sizeof(ed25519_keypair));
    mbedtls_platform_zeroize(&curve448_keypair, sizeof(curve448_keypair));
}

void opsick_keys_get_ed25519_keypair(opsick_ed25519_keypair* out)
{
    check_freshness();

    if (out == NULL)
    {
        return;
    }

    memcpy(out, &ed25519_keypair, sizeof(ed25519_keypair));
}

void opsick_keys_get_curve448_keypair(cecies_curve448_keypair* out)
{
    check_freshness();

    if (out == NULL)
    {
        return;
    }

    memcpy(out, &curve448_keypair, sizeof(curve448_keypair));
}