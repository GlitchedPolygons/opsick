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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <cecies/util.h>
#include <mbedtls/platform_util.h>

static bool initialized = false;

static uint8_t last128B[128];
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static uint64_t last_db_schema_version_nr_lookup = 0;
static struct opsick_config_hostsettings hostsettings;

static int callback_select_schema_version_nr(void*, int, char**, char**);

sqlite3* opsick_db_connect()
{
    sqlite3* db;
    if (sqlite3_open(hostsettings.db_file, &db) != SQLITE_OK)
    {
        fprintf(stderr, "Couldn't open SQLite database file: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    return db;
}

void opsick_db_disconnect(sqlite3* db)
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
    sqlite3* db = opsick_db_connect();
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
            opsick_db_disconnect(db);
            sqlite3_free(err_msg);
            exit(EXIT_FAILURE);
        }
    }

    cecies_dev_urandom(last128B, 128);
    sqlite3_exec(db, init_sql, &callback_select_schema_version_nr, 0, &err_msg);

    opsick_db_disconnect(db);
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
    last_db_schema_version_nr_lookup = (uint64_t)time(NULL);
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

uint64_t opsick_db_get_last_db_schema_version_nr_lookup()
{
    return last_db_schema_version_nr_lookup;
}

int opsick_db_create_user(sqlite3* db, const char* pw, const uint64_t exp_utc, const char* body, const char* public_key_ed25519, const char* encrypted_private_key_ed25519, const char* public_key_curve448, const char* encrypted_private_key_curve448, uint64_t* out_user_id)
{
    if (db == NULL || exp_utc < time(0) || body == NULL || public_key_ed25519 == NULL || encrypted_private_key_ed25519 == NULL || public_key_curve448 == NULL || encrypted_private_key_curve448 == NULL || out_user_id == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_create_user;
    const size_t sql_length = sizeof(opsick_sql_create_user) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, pw, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"pw\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, exp_utc);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"exp_utc\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 3, body, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"body\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 4, public_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"public_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 5, encrypted_private_key_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"encrypted_private_key_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 6, public_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"public_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 7, encrypted_private_key_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure to bind \"encrypted_private_key_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_create_user: opsick_db_create_user: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    *out_user_id = last_used_userid = sqlite3_last_insert_rowid(db);
    memcpy(last128B, public_key_curve448, OPSICK_MIN(64, strlen(public_key_curve448)));
    memcpy(last128B + 64, body, OPSICK_MIN(64, strlen(body)));

    rc = 0;
exit:
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_delete_user(sqlite3* db, uint64_t user_id)
{
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
        fprintf(stderr, "opsick_db_delete_user: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_delete_user: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_delete_user: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_get_user_metadata(sqlite3* db, uint64_t user_id, struct opsick_user_metadata* out_user_metadata)
{
    if (db == NULL || out_user_metadata == NULL)
    {
        return 1;
    }

    const char* sql = opsick_sql_get_user;
    const size_t sql_length = sizeof(opsick_sql_get_user) - 1;

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_get_user_metadata: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_get_user_metadata: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        fprintf(stderr, "opsick_db_get_user_metadata: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    out_user_metadata->id = (uint64_t)sqlite3_column_int64(stmt, 0);
    out_user_metadata->iat_utc = (uint64_t)sqlite3_column_int64(stmt, 3);
    out_user_metadata->exp_utc = (uint64_t)sqlite3_column_int64(stmt, 4);
    out_user_metadata->lastmod_utc = (uint64_t)sqlite3_column_int64(stmt, 5);

    const char* pw = (const char*)sqlite3_column_text(stmt, 1);
    const char* totps = (const char*)sqlite3_column_text(stmt, 2);
    const char* public_key_ed25519 = (const char*)sqlite3_column_text(stmt, 6);
    const char* encrypted_private_key_ed25519 = (const char*)sqlite3_column_text(stmt, 7);
    const char* public_key_curve448 = (const char*)sqlite3_column_text(stmt, 8);
    const char* encrypted_private_key_curve448 = (const char*)sqlite3_column_text(stmt, 9);

    if (pw != NULL)
        snprintf(out_user_metadata->pw, sizeof(out_user_metadata->pw), "%s", pw);

    if (totps != NULL)
        snprintf(out_user_metadata->totps, sizeof(out_user_metadata->totps), "%s", totps);

    if (public_key_ed25519 != NULL)
        snprintf(out_user_metadata->public_key_ed25519.hexstring, sizeof(out_user_metadata->public_key_ed25519), "%s", public_key_ed25519);

    if (encrypted_private_key_ed25519 != NULL)
        snprintf(out_user_metadata->encrypted_private_key_ed25519, sizeof(out_user_metadata->encrypted_private_key_ed25519), "%s", encrypted_private_key_ed25519);

    if (public_key_curve448 != NULL)
        snprintf(out_user_metadata->public_key_curve448.hexstring, sizeof(out_user_metadata->public_key_curve448), "%s", public_key_curve448);

    if (encrypted_private_key_curve448 != NULL)
        snprintf(out_user_metadata->encrypted_private_key_curve448, sizeof(out_user_metadata->encrypted_private_key_curve448), "%s", encrypted_private_key_curve448);

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_set_user_pw(sqlite3* db, uint64_t user_id, const char* new_pw)
{
    if (db == NULL || new_pw == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_set_user_pw;
    const size_t sql_length = sizeof(opsick_sql_set_user_pw) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_pw: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, new_pw, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_pw: Failure to bind \"new_pw\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_pw: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_set_user_pw: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_set_user_totps(sqlite3* db, uint64_t user_id, const char* new_totps)
{
    if (db == NULL || new_totps == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_set_user_totps;
    const size_t sql_length = sizeof(opsick_sql_set_user_totps) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_totps: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, new_totps, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_totps: Failure to bind \"new_totps\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_totps: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_set_user_totps: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_get_user_body(sqlite3* db, uint64_t user_id, char** out_body)
{
    if (db == NULL || out_body == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_get_user_body;
    const size_t sql_length = sizeof(opsick_sql_get_user_body) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_get_user_body: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_get_user_body: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        fprintf(stderr, "opsick_db_get_user_body: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    const char* body = (const char*)sqlite3_column_text(stmt, 0);
    if (body == NULL)
    {
        fprintf(stderr, "opsick_db_get_user_body: The user's body column was empty!");
        goto exit;
    }

    const size_t bodylen = strlen(body);
    *out_body = malloc(bodylen + 1);
    memcpy(*out_body, body, bodylen);
    (*out_body)[bodylen] = '\0';

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_set_user_body(sqlite3* db, uint64_t user_id, const char* body)
{
    if (db == NULL || body == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_set_user_body;
    const size_t sql_length = sizeof(opsick_sql_set_user_body) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_body: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, body, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_body: Failure to bind \"body\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_body: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_set_user_body: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_set_user_exp(sqlite3* db, uint64_t user_id, const uint64_t new_exp)
{
    if (db == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_set_user_exp;
    const size_t sql_length = sizeof(opsick_sql_set_user_exp) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_exp: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 1, new_exp);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_exp: Failure to bind \"new_exp\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 2, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_exp: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_set_user_exp: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}

int opsick_db_set_user_keys(sqlite3* db, uint64_t user_id, const char* new_pubkey_ed25519, const char* new_prvkey_ed25519, const char* new_pubkey_curve448, const char* new_prvkey_curve448)
{
    if (db == NULL || new_pubkey_ed25519 == NULL || new_prvkey_ed25519 == NULL || new_pubkey_curve448 == NULL || new_prvkey_curve448 == NULL)
    {
        return 1;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = opsick_sql_set_user_keys;
    const size_t sql_length = sizeof(opsick_sql_set_user_keys) - 1;

    int rc = sqlite3_prepare_v2(db, sql, sql_length, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure during execution of \"sqlite3_prepare_v2\" on the SQL statement \"%s\".", sql);
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 1, new_pubkey_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure to bind \"new_pubkey_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 2, new_prvkey_ed25519, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure to bind \"new_prvkey_ed25519\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 3, new_pubkey_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure to bind \"new_pubkey_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_text(stmt, 4, new_prvkey_curve448, -1, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure to bind \"new_prvkey_curve448\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_bind_int64(stmt, 5, user_id);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure to bind \"user_id\" value to prepared sqlite3 statement.");
        goto exit;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "opsick_db_set_user_keys: Failure during execution of the prepared sqlite3 statement.");
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    sqlite3_finalize(stmt);
    return rc;
}