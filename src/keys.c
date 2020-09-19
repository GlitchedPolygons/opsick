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
#include "opsick/constants.h"
#include "opsick/config.h"
#include "opsick/keys.h"
#include "opsick/guid.h"

static char firstgen = 1;
static char prvkey[8192];
static char pubkey[8192];
static time_t last_key_refresh = 0;
static struct opsick_config_hostsettings hostsettings;
static struct opsick_config_adminsettings adminsettings;

static void keyregen()
{
    int r;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    if (firstgen)
    {
        opsick_config_get_hostsettings(&hostsettings);
        opsick_config_get_adminsettings(&adminsettings);
    }
    else
    {
        mbedtls_pk_free(&pk);
    }

    if (hostsettings.log)
        printf("Regenerating opsick keypair - time for a pair of fresh RSA keys!\n");

    const opsick_guid guid = opsick_new_guid(time(0) % 2, time(0) % 3);
    const char* pe = guid.string;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    if (hostsettings.log)
        printf("Seeding...");

    if ((r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pe, strlen(pe))) != 0)
    {
        fprintf(stderr, " Seeding failed! mbedtls_ctr_drbg_seed returned %d\n", r);
        goto exit;
    }

    if (hostsettings.log)
        printf(" OK\nSetting up key context...");

    if ((r = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
    {
        fprintf(stderr, " Key context setup failed! mbedtls_pk_setup returned %i\n", r);
        goto exit;
    }

    if (hostsettings.log)
        printf(" OK\nGenerating the RSA key [ %d-bit ]...", OPSICK_KEY_SIZE);

    if ((r = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, OPSICK_KEY_SIZE, OPSICK_KEY_EXPONENT)) != 0)
    {
        fprintf(stderr, " Key (re)generation failed! mbedtls_rsa_gen_key returned %d\n", r);
        goto exit;
    }

    if (hostsettings.log)
        printf(" OK\nChecking public/private key validity...");

    if ((r = mbedtls_rsa_check_pubkey(mbedtls_pk_rsa(pk))) != 0)
    {
        fprintf(stderr, " RSA context does not contain an rsa public key; mbedtls_rsa_check_pubkey returned %d \n", r);
        goto exit;
    }

    if (hostsettings.log)
        printf("\nPublic key: OK\n");

    if ((r = mbedtls_rsa_check_privkey(mbedtls_pk_rsa(pk))) != 0)
    {
        fprintf(stderr, " RSA context does not contain an rsa private key; mbedtls_rsa_check_privkey returned %d \n", r);
        goto exit;
    }

    if (hostsettings.log)
        printf("\nPrivate key: OK\n");

    memset(pubkey, '\0', sizeof(pubkey));
    if ((r = mbedtls_pk_write_pubkey_pem(&pk, (unsigned char*)pubkey, sizeof(pubkey))) != 0)
    {
        fprintf(stderr, "\nRSA write public key to string failed; mbedtls_pk_write_pubkey_pem returned %d \n", r);
        goto exit;
    }

    memset(prvkey, '\0', sizeof(prvkey));
    if ((r = mbedtls_pk_write_key_pem(&pk, (unsigned char*)prvkey, sizeof(prvkey))) != 0)
    {
        fprintf(stderr, "\nRSA write private key to string failed; mbedtls_pk_write_key_pem returned %d \n", r);
        goto exit;
    }

    firstgen = 0;
    last_key_refresh = time(0);

exit:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
}

int opsick_keys_get_ed25519_pubkey_hex(char out[64])
{
    if (out == NULL)
    {
        return 1;
    }

    if (time(0) > last_key_refresh + (adminsettings.key_refresh_interval_hours * 3600))
    {
        keyregen();
    }

    snprintf(out, 64, "%s", pubkey);
    return 0;
}

int opsick_keys_get_ed25519_prvkey_hex(char out[128])
{
    if (out == NULL)
    {
        return 1;
    }

    if (time(0) > last_key_refresh + (adminsettings.key_refresh_interval_hours * 3600))
    {
        keyregen();
    }

    snprintf(out, 128, "%s", prvkey);
    return 0;
}
