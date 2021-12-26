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
    mbedtls_platform_zeroize(&hostsettings, sizeof(hostsettings));
    mbedtls_platform_zeroize(&adminsettings, sizeof(adminsettings));

    hostsettings.log = OPSICK_DEFAULT_LOG;
    hostsettings.port = OPSICK_DEFAULT_PORT;
    hostsettings.threads = OPSICK_DEFAULT_THREADS;
    hostsettings.max_clients = OPSICK_DEFAULT_MAX_CLIENTS;
    hostsettings.max_header_size = OPSICK_DEFAULT_MAX_HEADER_SIZE;
    hostsettings.max_body_size = OPSICK_DEFAULT_MAX_BODY_SIZE;

    adminsettings.max_users = OPSICK_DEFAULT_MAX_USERS;
    adminsettings.api_key_algo = OPSICK_DEFAULT_API_KEY_ALGO;
    adminsettings.use_index_html = OPSICK_DEFAULT_USE_INDEX_HTML;
    adminsettings.argon2_time_cost = OPSICK_DEFAULT_ARGON2_TIME_COST;
    adminsettings.argon2_parallelism = OPSICK_DEFAULT_ARGON2_PARALLELISM;
    adminsettings.argon2_memory_cost_kib = OPSICK_DEFAULT_ARGON2_MEMORY_COST_KiB;
    adminsettings.key_refresh_interval_hours = OPSICK_DEFAULT_KEY_REFRESH_INTERVAL_HOURS;
    strcpy(adminsettings.api_key_public_hexstr, OPSICK_DEFAULT_API_KEY_PUBLIC_HEXSTR);
    strcpy(adminsettings.user_registration_password, OPSICK_DEFAULT_USER_CREATION_PASSWORD_ARGON2_HASH); // Default user registration password is "opsick_registration_password".
}

#define OPSICK_PQASSERT(pr, sql, dbconn)                                                                                                                                                                                                                                                                                                                                                                                                                                                                           \
    if (PQresultStatus(pr) != PGRES_TUPLES_OK)                                                                                                                                                                                                                                                                                                                                                                                                                                                                     \
    {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              \
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));                                                                                                                                                                                                                                                                                                                                                                  \
        goto exit;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \
    }

static int load_hostsettings(PGconn* dbconn)
{
    int r = 0;
    char* sql;
    PGresult* pr;

    // Load setting from config that determines whether all HTTP-requests should be logged:

    sql = "SELECT value FROM settings WHERE id = 'log'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        hostsettings.log = *PQgetvalue(pr, 0, 0) != '0';
    }

    // Load port setting from db:

    sql = "SELECT value FROM settings WHERE id = 'port'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        const unsigned long port = strtoul(PQgetvalue(pr, 0, 0), NULL, 10);

        if (port > 0 && port <= 65535)
        {
            hostsettings.port = (uint16_t)port;
        }
        else
        {
            fprintf(stderr, "ERROR: The parsed port number \"%zu\" is not within the range of valid port numbers [0; 65535] - using default value of \"%d\" instead... \n", port, hostsettings.port);
        }
    }

    // Load thread count setting from config:

    sql = "SELECT value FROM settings WHERE id = 'threads'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        const unsigned long threads = strtoul(PQgetvalue(pr, 0, 0), NULL, 10);

        if (threads > 0 && threads <= 64)
        {
            hostsettings.threads = (uint8_t)threads;
        }
        else
        {
            fprintf(stderr, "ERROR: The parsed maximum thread count setting \"%zu\" is not within the range of recommended thread count limits [1; 64] - using default thread count of \"%d\" instead... \n", threads, hostsettings.threads);
        }
    }

    // Load max clients setting from config:

    sql = "SELECT value FROM settings WHERE id = 'max_clients'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        hostsettings.max_clients = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load max header size setting (in bytes) from config:

    sql = "SELECT value FROM settings WHERE id = 'max_header_size'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        hostsettings.max_header_size = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load max body size setting (in bytes) from config:

    sql = "SELECT value FROM settings WHERE id = 'max_body_size'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        hostsettings.max_body_size = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    r = 1;

exit:
    PQclear(pr);
    return r;
}

static int load_adminsettings(PGconn* dbconn)
{
    int r = 0;
    char* sql;
    PGresult* pr;

    // Load API key algo ID setting from config:

    sql = "SELECT value FROM settings WHERE id = 'api_key_algo'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        const unsigned long algo = strtoul(PQgetvalue(pr, 0, 0), NULL, 10);

        if (algo >= 0 && algo <= UINT8_MAX)
        {
            adminsettings.api_key_algo = (uint8_t)algo;
        }
        else
        {
            fprintf(stderr, "%s: ERROR: The parsed algo id setting \"%zu\" is not within the range of valid algo IDs [0;255] \n", __func__, algo);
            goto exit;
        }
    }

    // Load max users limit from config:

    sql = "SELECT value FROM settings WHERE id = 'max_users'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        adminsettings.max_users = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load key regeneration interval (in hours) from config:

    sql = "SELECT value FROM settings WHERE id = 'key_refresh_interval_hours'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        adminsettings.key_refresh_interval_hours = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load Argon2 time cost parameter (iterations) from config:

    uint64_t argon2_time_cost = OPSICK_DEFAULT_ARGON2_TIME_COST;
    uint64_t argon2_memory_cost_kib = OPSICK_DEFAULT_ARGON2_MEMORY_COST_KiB;
    uint64_t argon2_parallelism = OPSICK_DEFAULT_ARGON2_PARALLELISM;

    sql = "SELECT value FROM settings WHERE id = 'argon2_time_cost'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        argon2_time_cost = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load Argon2 memory cost parameter (in KiB) from config:

    sql = "SELECT value FROM settings WHERE id = 'argon2_memory_cost_kib'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        argon2_memory_cost_kib = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    // Load Argon2 parallelism parameter from config:

    sql = "SELECT value FROM settings WHERE id = 'argon2_parallelism'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        argon2_parallelism = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    }

    if (argon2_time_cost > UINT32_MAX)
        argon2_time_cost = UINT32_MAX;

    if (argon2_memory_cost_kib > UINT32_MAX)
        argon2_memory_cost_kib = UINT32_MAX;

    if (argon2_parallelism > OPSICK_MAX_ARGON2_PARALLELISM)
        argon2_parallelism = OPSICK_MAX_ARGON2_PARALLELISM;

    adminsettings.argon2_time_cost = argon2_time_cost;
    adminsettings.argon2_memory_cost_kib = argon2_memory_cost_kib;
    adminsettings.argon2_parallelism = argon2_parallelism;

    // Load the setting that determines whether or not Opsick should serve the index.html file on its home path ("/") from config:

    sql = "SELECT value FROM settings WHERE id = 'use_index_html'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        adminsettings.use_index_html = *PQgetvalue(pr, 0, 0) != '0';
    }

    // Load the user creation password from config:

    sql = "SELECT value FROM settings WHERE id = 'user_registration_password'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        char* user_registration_password = PQgetvalue(pr, 0, 0);

        if (strlen(user_registration_password) > 0)
        {
            if (strstr(user_registration_password, "$argon2id") != user_registration_password)
            {
                fprintf(stderr, "%s: Invalid opsick config value. If a user registration password is desired, it MUST be in the Argon2id encoded hash format!", __func__);
                goto exit;
            }

            strncpy(adminsettings.user_registration_password, user_registration_password, sizeof(adminsettings.user_registration_password));
        }
        else
        {
            mbedtls_platform_zeroize(adminsettings.user_registration_password, sizeof(adminsettings.user_registration_password));
        }
    }

    // Load the API key's public ed25519 key (hex-encoded string) from config:

    sql = "SELECT value FROM settings WHERE id = 'api_key_public_hexstr'";
    pr = PQexec(dbconn, sql);
    OPSICK_PQASSERT(pr, sql, dbconn);

    if (PQntuples(pr) != 0)
    {
        char* api_key_public_hexstr = PQgetvalue(pr, 0, 0);
        const size_t api_key_public_hexstr_length = strlen(api_key_public_hexstr);

        if (api_key_public_hexstr_length == 0 || *api_key_public_hexstr == '\0')
        {
            fprintf(stderr, "%s: ERROR: Failed to parse \"api_key_public\" setting string from the opsick DB's user config table. \n", __func__);
        }
        else
        {
            strncpy(adminsettings.api_key_public_hexstr, api_key_public_hexstr, sizeof(adminsettings.api_key_public_hexstr));
            opsick_hexstr2bin(api_key_public_hexstr, api_key_public_hexstr_length, adminsettings.api_key_public, sizeof(adminsettings.api_key_public), NULL);
        }
    }

    r = 1;
exit:
    PQclear(pr);
    return r;
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

#undef OPSICK_PQASSERT