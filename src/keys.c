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
#include <sha512.h>
#include <cecies/guid.h>
#include <mbedtls/platform_util.h>

#include "opsick/db.h"
#include "opsick/util.h"
#include "opsick/keys.h"
#include "opsick/config.h"

static char firstgen = 1;
static time_t last_key_refresh = 0;

static struct opsick_ed25519_keypair ed25519_keypair;
static struct cecies_curve448_keypair curve448_keypair;

static struct opsick_config_hostsettings hostsettings;
static struct opsick_config_adminsettings adminsettings;

static char pubkey_outjson[256];
static size_t pubkey_outjson_len = 0;

static void keyregen()
{
    if (firstgen)
    {
        opsick_config_get_hostsettings(&hostsettings);
        opsick_config_get_adminsettings(&adminsettings);
    }

    uint8_t sick_randomness[128];
    opsick_db_last_128_bytes_of_ciphertext(sick_randomness);

    uint8_t additional_entropy[512];
    snprintf((char*)additional_entropy, 128, "%zu-%zu-%zu-%zu-%s", opsick_db_get_last_used_userid(), last_key_refresh, opsick_db_get_last_db_schema_version_nr_lookup(), time(0) + 420 + 1337, cecies_new_guid(true, true).string);
    memcpy(additional_entropy + 128, sick_randomness, 128);
    cecies_dev_urandom(additional_entropy + 256, 256);

    sha512(additional_entropy, sizeof(additional_entropy), additional_entropy);

    uint8_t seed[32];
    ed25519_create_seed(seed);
    ed25519_create_keypair((unsigned char*)ed25519_keypair.public_key, (unsigned char*)ed25519_keypair.private_key, (unsigned char*)seed);
    ed25519_add_scalar((unsigned char*)ed25519_keypair.public_key, (unsigned char*)ed25519_keypair.private_key, (unsigned char*)additional_entropy);

    cecies_generate_curve448_keypair(&curve448_keypair, (unsigned char*)additional_entropy, sizeof(additional_entropy));

    firstgen = 0;
    last_key_refresh = time(0);

    opsick_bin2hexstr(ed25519_keypair.public_key, sizeof(ed25519_keypair.public_key), ed25519_keypair.public_key_hexstr, sizeof(ed25519_keypair.public_key_hexstr), NULL, 0);
    opsick_bin2hexstr(ed25519_keypair.private_key, sizeof(ed25519_keypair.private_key), ed25519_keypair.private_key_hexstr, sizeof(ed25519_keypair.private_key_hexstr), NULL, 0);

    snprintf(pubkey_outjson, sizeof(pubkey_outjson), "{\"public_key_ed25519\":\"%s\",\"public_key_curve448\":\"%s\"}", ed25519_keypair.public_key_hexstr, curve448_keypair.public_key.hexstring);
    pubkey_outjson_len = strlen(pubkey_outjson);

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

void opsick_keys_get_public_keys_json(char* out, size_t* outlen)
{
    check_freshness();
    memcpy(out, pubkey_outjson, pubkey_outjson_len);
    out[pubkey_outjson_len] = 0x00;
    *outlen = pubkey_outjson_len;
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
    mbedtls_platform_zeroize(&last_key_refresh, sizeof(last_key_refresh));
    mbedtls_platform_zeroize(pubkey_outjson, sizeof(pubkey_outjson));
}

void opsick_keys_get_ed25519_keypair(struct opsick_ed25519_keypair* out)
{
    check_freshness();

    if (out == NULL)
    {
        return;
    }

    memcpy(out, &ed25519_keypair, sizeof(ed25519_keypair));
}

void opsick_keys_get_curve448_keypair(struct cecies_curve448_keypair* out)
{
    check_freshness();

    if (out == NULL)
    {
        return;
    }

    memcpy(out, &curve448_keypair, sizeof(curve448_keypair));
}