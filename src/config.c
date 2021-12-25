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

#include <string.h>
#include <stdlib.h>
#include <mbedtls/platform_util.h>

#include "opsick/db.h"
#include "opsick/util.h"
#include "opsick/config.h"

static struct opsick_config_hostsettings hostsettings;
static struct opsick_config_adminsettings adminsettings;

static inline void init()
{
    memset(&hostsettings, 0x00, sizeof(hostsettings));
    memset(&adminsettings, 0x00, sizeof(adminsettings));

    hostsettings.port = 6677;
    hostsettings.threads = 2;
    hostsettings.max_clients = 0;
    hostsettings.max_header_size = 1024 * 16;
    hostsettings.max_body_size = 1024 * 1024 * 16;

    adminsettings.max_users = 0;
    adminsettings.use_index_html = 1;
    adminsettings.key_refresh_interval_hours = 72;
    adminsettings.api_key_algo = 0;
    adminsettings.argon2_time_cost = 16;
    adminsettings.argon2_memory_cost = 65536;
    adminsettings.argon2_parallelism = 2;
    strcpy(adminsettings.api_key_public_hexstr, "F407F5E089CE64002EB417FB683A7302287BE84108BB8E62FD8ED647DC62805C");
    strcpy(adminsettings.user_registration_password, "$argon2id$v=19$m=65536,t=16,p=2$U2pkM195MjMtUTksVw$4K9trCcn0vOyLRvFCK3Srwlzbr+5N6gIcS3omQoMFg0"); // Default user registration password is "opsick_registration_password".
}

static int load_hostsettings(PGconn* dbconn)
{
    uint64_t port = -1;
    parse_toml_uint(table, "port", &port);
    if (port > 0 && port <= 65535)
    {
        hostsettings.port = (uint16_t)port;
    }
    else
    {
        fprintf(stderr, "ERROR: The parsed port number \"%zu\" is not within the range of valid port numbers [0; 65535] - using default value of \"%d\" instead... \n", port, hostsettings.port);
    }

    uint64_t threads = -1;
    parse_toml_uint(table, "threads", &threads);
    if (threads > 0 && threads <= 64)
    {
        hostsettings.threads = (uint8_t)threads;
    }
    else
    {
        fprintf(stderr, "ERROR: The parsed maximum thread count setting \"%zu\" is not within the range of recommended thread count limits [1; 64] - using default thread count of \"%d\" instead... \n", threads, hostsettings.threads);
    }

    parse_toml_uint(table, "max_clients", &hostsettings.max_clients);
    parse_toml_uint(table, "max_header_size", &hostsettings.max_header_size);
    parse_toml_uint(table, "max_body_size", &hostsettings.max_body_size);

    return 1;
}

static int load_adminsettings(PGconn* dbconn)
{
    parse_toml_uint(table, "max_users", &adminsettings.max_users);
    parse_toml_uint(table, "key_refresh_interval_hours", &adminsettings.key_refresh_interval_hours);

    uint64_t argon2_time_cost, argon2_memory_cost, argon2_parallelism;
    parse_toml_uint(table, "argon2_time_cost", &argon2_time_cost);
    parse_toml_uint(table, "argon2_memory_cost_kib", &argon2_memory_cost);
    parse_toml_uint(table, "argon2_parallelism", &argon2_parallelism);

    if (argon2_time_cost > UINT32_MAX)
        argon2_time_cost = UINT32_MAX;

    if (argon2_memory_cost > UINT32_MAX)
        argon2_memory_cost = UINT32_MAX;

    if (argon2_parallelism > OPSICK_MAX_ARGON2_PARALLELISM)
        argon2_parallelism = OPSICK_MAX_ARGON2_PARALLELISM;

    adminsettings.argon2_time_cost = argon2_time_cost;
    adminsettings.argon2_memory_cost = argon2_memory_cost;
    adminsettings.argon2_parallelism = argon2_parallelism;

    adminsettings.use_index_html = opsick_strncmpic(toml_raw_in(table, "use_index_html"), "true", 4) == 0;

    char* user_registration_password = NULL;
    if (toml_rtos(toml_raw_in(table, "user_registration_password"), &user_registration_password) == 0)
    {
        strncpy(adminsettings.user_registration_password, user_registration_password, sizeof(adminsettings.user_registration_password));
    }
    else
    {
        mbedtls_platform_zeroize(adminsettings.user_registration_password, sizeof(adminsettings.user_registration_password));
    }
    free(user_registration_password);

    uint64_t algo = 0;
    parse_toml_uint(table, "api_key_algo", &algo);
    if (algo >= 0 && algo <= UINT8_MAX)
    {
        adminsettings.api_key_algo = (uint8_t)algo;
    }
    else
    {
        fprintf(stderr, "ERROR: The parsed algo id setting \"%zu\" is not within the range of valid algo IDs [0;255] \n", algo);
    }

    char* api_key_public_hexstr = NULL;
    if (toml_rtos(toml_raw_in(table, "api_key_public_hexstr"), &api_key_public_hexstr))
    {
        fprintf(stderr, "ERROR: Failed to parse \"api_key_public\" setting string from the opsick user config file \"%s\". \n", OPSICK_CONFIG_FILE_PATH);
    }
    else
    {
        strncpy(adminsettings.api_key_public_hexstr, api_key_public_hexstr, sizeof(adminsettings.api_key_public_hexstr));
        opsick_hexstr2bin(api_key_public_hexstr, strlen(api_key_public_hexstr), adminsettings.api_key_public, sizeof(adminsettings.api_key_public), NULL);
    }
    free(api_key_public_hexstr);

    return 1;
}

int opsick_config_load()
{
    init();

    int r = 0;

    PGconn* dbconn = opsick_db_connect();

    if (dbconn == NULL)
    {
        goto exit;
    }

    if (!load_hostsettings(dbconn))
    {
        goto exit;
    }

    if (!load_adminsettings(dbconn))
    {
        goto exit;
    }

    r = 1;

exit:
    opsick_db_disconnect(dbconn);
    return r;
}

int opsick_config_get_hostsettings(struct opsick_config_hostsettings* out)
{
    if (out == NULL)
    {
        return 0;
    }

    struct opsick_config_hostsettings t = hostsettings;
    *out = t;
    return 1;
}

int opsick_config_get_adminsettings(struct opsick_config_adminsettings* out)
{
    if (out == NULL)
    {
        return 0;
    }

    struct opsick_config_adminsettings t = adminsettings;
    *out = t;
    return 1;
}
