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
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/sql/users.h"
#include "opsick/sql/db_migrations.h"

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <mbedtls/platform_util.h>
#include <cecies/util.h>

static bool initialized = false;
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;
static uint8_t last128B[128];
static sqlite3* db;
static struct opsick_config_hostsettings hostsettings;
static sqlite3_stmt* useradd_stmt = NULL;
static sqlite3_stmt* userdel_stmt = NULL;
static int callback_select_schema_version_nr(void*, int, char**, char**);

#pragma region INIT AND FREE

void opsick_db_init()
{
    if (initialized)
        return;

    opsick_config_get_hostsettings(&hostsettings);

    char* err_msg = NULL;
    int rc = sqlite3_open(hostsettings.db_file, &db);

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

    for (uint64_t i = cached_db_schema_version_nr + (cached_db_schema_version_nr != 0); i < opsick_get_schema_version_count(); i++)
    {
        rc = sqlite3_exec(db, SQL_MIGRATIONS[i], &callback_select_schema_version_nr, 0, &err_msg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Couldn't initialize SQLite database file: %s\nEventually a bad SQL migration? Please double check!", sqlite3_errmsg(db));
            goto error;
        }
    }

    rc = sqlite3_prepare_v2(db, opsick_sql_create_user, -1, &useradd_stmt, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't compile SQL statement into SQLite byte-code program using \"sqlite3_prepare_v2\": \"%s\"", opsick_sql_create_user);
        goto error;
    }

    rc = sqlite3_prepare_v2(db, opsick_sql_delete_user, -1, &userdel_stmt, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't compile SQL statement into SQLite byte-code program using \"sqlite3_prepare_v2\": \"%s\"", opsick_sql_delete_user);
        goto error;
    }

    cecies_dev_urandom(last128B, 128);
    sqlite3_exec(db, init_sql, &callback_select_schema_version_nr, 0, &err_msg);
    sqlite3_free(err_msg);
    initialized = true;
    return;

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
    mbedtls_platform_zeroize(&hostsettings, sizeof(hostsettings));
    mbedtls_platform_zeroize(&last_used_userid, sizeof(last_used_userid));

    sqlite3_finalize(useradd_stmt);
    sqlite3_finalize(userdel_stmt);
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
    return last_used_userid; // TODO: set this in all functions where possible!
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

int opsick_db_create_user(const char* pw, const time_t exp_utc, const char* body, const char* public_key_ed25519, const char* encrypted_private_key_ed25519, const char* public_key_curve448, const char* encrypted_private_key_curve448, uint64_t* out_user_id)
{
    int rc = sqlite3_bind_text(useradd_stmt, 1, pw, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"pw\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(useradd_stmt, 2, exp_utc);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"exp_utc\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(useradd_stmt, 3, body, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"exp_utc\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(useradd_stmt, 4, public_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"public_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(useradd_stmt, 5, encrypted_private_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"encrypted_private_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(useradd_stmt, 6, public_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"public_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(useradd_stmt, 7, encrypted_private_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"encrypted_private_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(useradd_stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Failure during execution of the \"useradd_stmt\" prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;

    *out_user_id = last_used_userid = opsick_db_get_last_insert_rowid();
    memcpy(last128B, public_key_curve448, OPSICK_MIN(64, strlen(public_key_curve448)));
    memcpy(last128B + 64, body, OPSICK_MIN(64, strlen(body)));

exit:
    sqlite3_reset(useradd_stmt);
    return rc;
}

uint64_t opsick_db_get_last_insert_rowid()
{
    return (uint64_t)sqlite3_last_insert_rowid(db);
}

int opsick_db_delete_user(uint64_t user_id)
{
    // TODO: impl. asap!

    return 0;
}

int opsick_db_get_user_pw_and_totps(uint64_t user_id, char* out_pw, char* out_totps_base32)
{
    // TODO: impl. asap!

    return 0;
}