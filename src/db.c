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
#include <cecies/util.h>
#include <mbedtls/platform_util.h>

static bool initialized = false;
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;
static uint8_t last128B[128];
static struct opsick_config_hostsettings hostsettings;
static int callback_select_schema_version_nr(void*, int, char**, char**);

static sqlite3* connect()
{
    sqlite3* db;
    if (sqlite3_open(hostsettings.db_file, &db) != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't open SQLite database file: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    return db;
}

static void disconnect(sqlite3* db)
{
    if (db != NULL)
    {
        sqlite3_close(db);
    }
}

#pragma region INIT AND FREE

void opsick_db_init()
{
    if (initialized)
        return;

    opsick_config_get_hostsettings(&hostsettings);

    char* err_msg = NULL;
    sqlite3* db = connect();
    if (db == NULL)
    {
        return;
    }

    static const char init_sql[] = "SELECT version FROM schema_version WHERE id = true;";

    // The callback also updates the cached_db_schema_version_nr!
    int rc = sqlite3_exec(db, init_sql, &callback_select_schema_version_nr, 0, &err_msg);
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
            disconnect(db);
            sqlite3_free(err_msg);
            exit(EXIT_FAILURE);
        }
    }

    cecies_dev_urandom(last128B, 128);
    sqlite3_exec(db, init_sql, &callback_select_schema_version_nr, 0, &err_msg);

    disconnect(db);
    sqlite3_free(err_msg);
    initialized = true;
}

void opsick_db_free()
{
    if (!initialized)
        return;

    initialized = false;

    mbedtls_platform_zeroize(last128B, sizeof(last128B));
    mbedtls_platform_zeroize(&hostsettings, sizeof(hostsettings));
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
    sqlite3* db = connect();
    if (db == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_create_user;
    const size_t sql_length = sizeof(opsick_sql_create_user) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, pw, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"pw\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, exp_utc);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"exp_utc\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 3, body, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"body\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 4, public_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"public_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 5, encrypted_private_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"encrypted_private_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 6, public_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"public_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 7, encrypted_private_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"encrypted_private_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_create_user: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;

    *out_user_id = last_used_userid = sqlite3_last_insert_rowid(db);
    memcpy(last128B, public_key_curve448, OPSICK_MIN(64, strlen(public_key_curve448)));
    memcpy(last128B + 64, body, OPSICK_MIN(64, strlen(body)));

exit:
    sqlite3_finalize(stmt);
    disconnect(db);
    return rc;
}

int opsick_db_delete_user(uint64_t user_id)
{
    sqlite3* db = connect();
    if (db == NULL)
    {
        return 1;
    }

    const char* sql = opsick_sql_delete_user;
    const size_t sql_length = sizeof(opsick_sql_delete_user) - 1;

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_delete_user: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    disconnect(db);
    return rc;
}

int opsick_db_get_user_pw_and_totps(uint64_t user_id, char* out_pw, char* out_totps_base32)
{
    sqlite3* db = connect();
    if (db == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_get_user_pw_and_totps;
    const size_t sql_length = sizeof(opsick_sql_get_user_pw_and_totps) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        fprintf(stderr, "opsick_db_get_user_pw_and_totps: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    const char* pw = (const char*)sqlite3_column_text(stmt, 0);
    const char* totps = (const char*)sqlite3_column_text(stmt, 1);

    if (out_pw != NULL)
    {
        snprintf(out_pw, 256, "%s", pw);
    }

    if (out_totps_base32 != NULL && totps != NULL)
    {
        snprintf(out_totps_base32, 49, "%s", totps);
    }

exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    disconnect(db);
    return rc;
}