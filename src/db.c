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
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <sqlite3.h>
#include <mbedtls/platform_util.h>

static bool initialized = false;
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;
static uint8_t last128B[128];
static sqlite3* db;

bool opsick_db_init()
{
    if (initialized)
        return true;

    char* err_msg = NULL;
    int rc = sqlite3_open(OPSICK_SQLITE_DB_FILENAME, &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't open SQLite database file: %s\n", sqlite3_errmsg(db));
        goto error;
    }

    static const char* init_sql = "CREATE TABLE IF NOT EXISTS schema_version(id tinyint PRIMARY KEY DEFAULT TRUE, version bigint NOT NULL, last_mod timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP);"
                                  "INSERT INTO schema_version (version) VALUES (1);"
                                  "CREATE TRIGGER single_row_guardian_schema_version "
                                  "BEFORE INSERT ON schema_version "
                                  "WHEN (SELECT COUNT(*) FROM config) >= 1 "
                                  "BEGIN "
                                  "SELECT RAISE(FAIL, 'Only one row allowed inside the schema_version table!'); "
                                  "END;";

    rc = sqlite3_exec(db, init_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't initialize SQLite database file: %s\nEventually a bad migration?", sqlite3_errmsg(db));
        goto error;
    }

    return initialized = true;

error:

    sqlite3_free(err_msg);
    sqlite3_close(db);
    return false;
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

    sqlite3_close(db);
    mbedtls_platform_zeroize(last128B, sizeof(last128B));
    mbedtls_platform_zeroize(&last_used_userid, sizeof(last_used_userid));
}