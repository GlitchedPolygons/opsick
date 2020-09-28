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
#include "opsick/constants.h"
#include "opsick/sql/db_migrations.h"

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <mbedtls/platform_util.h>

static bool initialized = false;
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;
static uint8_t last128B[128];
static sqlite3* db;

static int callback_select_schema_version_nr(void*, int, char**, char**);

#pragma region INIT& FREE

void opsick_db_init()
{
    if (initialized)
        return;

    char* err_msg = NULL;
    int rc = sqlite3_open(OPSICK_SQLITE_DB_FILENAME, &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't open SQLite database file: %s\n", sqlite3_errmsg(db));
        goto error;
    }

    static const char init_sql[] = "SELECT version FROM schema_version WHERE id = true;";

    // The callback also updates the cached_db_schema_version_nr!
    rc = sqlite3_exec(db, init_sql, &callback_select_schema_version_nr, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        cached_db_schema_version_nr = 0;
    }

    for (uint64_t i = cached_db_schema_version_nr; i < opsick_get_schema_version_count() - (cached_db_schema_version_nr != 0); i++)
    {
        rc = sqlite3_exec(db, SQL_MIGRATIONS[i], &callback_select_schema_version_nr, 0, &err_msg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Couldn't initialize SQLite database file: %s\nEventually a bad SQL migration? Please double check!", sqlite3_errmsg(db));
            goto error;
        }
    }

    initialized = true;
    return;

    /*
     * fprintf(stderr, "Couldn't initialize SQLite database file: %s\nEventually a bad migration?", sqlite3_errmsg(db));
     * goto error;
     * */
error:

    sqlite3_free(err_msg);
    sqlite3_close(db);
    exit(EXIT_FAILURE);
}

void opsick_db_free()
{
    if (!initialized)
        return;

    initialized = false;

    sqlite3_close(db);
    mbedtls_platform_zeroize(last128B, sizeof(last128B));
    mbedtls_platform_zeroize(&last_used_userid, sizeof(last_used_userid));
}

#pragma endregion

#pragma region CALLBACKS

static int callback_select_schema_version_nr(void* nop, int argc, char* argv[], char* colname[])
{
    if (argc != 1)
    {
        return -1;
    }

    if (strcmp("version", colname[0]) != 0)
    {
        return -2;
    }

    cached_db_schema_version_nr = (uint64_t)strtoull(argv[0], NULL, 10);
    return 0;
}

#pragma endregion

uint64_t opsick_db_get_schema_version_number()
{
    last_db_schema_version_nr_lookup = time(NULL);
    return cached_db_schema_version_nr;
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