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
#include <cecies/util.h>
#include <mbedtls/sha512.h>
#include <mbedtls/platform_util.h>

static int initialized = 0;

static uint8_t last128B[128];
static uint64_t last_used_userid = 0;
static uint64_t cached_db_schema_version_nr = 0;
static uint64_t last_db_schema_version_nr_lookup = 0;
static char connection_string[1024] = { 0x00 };

#pragma region CONNECT AND DISCONNECT

PGconn* opsick_db_connect()
{
    PGconn* dbconn = PQconnectdb(connection_string);

    if (PQstatus(dbconn) == CONNECTION_BAD)
    {
        fprintf(stderr, "ERROR: Connection to database failed: %s \n", PQerrorMessage(dbconn));
        return NULL;
    }

    return dbconn;
}

void opsick_db_disconnect(PGconn* dbconn)
{
    if (dbconn != NULL)
    {
        PQfinish(dbconn);
    }
}

#pragma endregion

#pragma region INIT AND FREE

int opsick_db_init(const char* dbconn_filepath)
{
    if (initialized)
    {
        return 1;
    }

    if (dbconn_filepath == NULL)
    {
        fprintf(stderr, "ERROR: No valid db connection string file specified for Opsick! \n");
        return 0;
    }

    FILE* dbconn_file = fopen(dbconn_filepath, "rb");
    if (dbconn_file == NULL)
    {
        fprintf(stderr, "ERROR: Opsick failed to access the specified db connection string file. Double-check its existence and permissions! \n");
        return 0;
    }

    fread(connection_string, sizeof(char), sizeof(connection_string), dbconn_file);
    fclose(dbconn_file);

    PGconn* dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        fprintf(stderr, "ERROR: Opsick failed to connect to the db! \n");
        return 0;
    }

    int r = 0;
    PGresult* pr = PQexec(dbconn, "SELECT VERSION FROM SCHEMA_VERSION WHERE ID = TRUE;");
    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "ERROR: Opsick failed to retrieve schema version number from the db. \n");
        goto exit;
    }

    cached_db_schema_version_nr = strtoull(PQgetvalue(pr, 0, 0), NULL, 10);

    for (uint64_t i = cached_db_schema_version_nr + (cached_db_schema_version_nr != 0); i < opsick_get_schema_version_count(); ++i)
    {
        PQclear(pr);
        pr = PQexec(dbconn, SQL_MIGRATIONS[i]);

        if (PQresultStatus(pr) != PGRES_COMMAND_OK)
        {
            fprintf(stderr, "ERROR: Failed to apply Opsick DB migration #%zu \n", i);
            goto exit;
        }
    }

    PQclear(pr);
    pr = PQexec(dbconn, "SELECT VERSION FROM SCHEMA_VERSION WHERE ID = TRUE;");
    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "ERROR: Opsick failed to retrieve schema version number from the db. \n");
        PQclear(pr);
        goto exit;
    }

    cached_db_schema_version_nr = strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    cecies_dev_urandom(last128B, 128);

    r = 1;
    initialized = 1;

exit:
    PQclear(pr);
    opsick_db_disconnect(dbconn);
    return r;
}

void opsick_db_free()
{
    if (!initialized)
        return;

    initialized = 0;

    mbedtls_platform_zeroize(last128B, sizeof(last128B));
    mbedtls_platform_zeroize(&last_used_userid, sizeof(last_used_userid));
    mbedtls_platform_zeroize(connection_string, sizeof(connection_string));
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

int opsick_db_does_user_id_exist(PGconn* dbconn, const uint64_t user_id)
{
    int exists = 0;
    const char* sql = opsick_sql_does_user_id_exist;

    const char* paramValues[1];
    int paramLengths[1];
    int paramFormats[1];

    paramValues[0] = (const char*)&user_id;
    paramLengths[0] = sizeof(user_id);
    paramFormats[0] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    exists = strtol(PQgetvalue(pr, 0, 0), NULL, 10) != 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return exists;
}

int opsick_db_create_user(PGconn* dbconn, const char* pw, const uint64_t exp_utc, const char* public_key_ed25519, const char* encrypted_private_key_ed25519, const char* public_key_curve448, const char* encrypted_private_key_curve448, uint64_t* out_user_id)
{
    if (dbconn == NULL || exp_utc < time(0) || public_key_ed25519 == NULL || encrypted_private_key_ed25519 == NULL || public_key_curve448 == NULL || encrypted_private_key_curve448 == NULL || out_user_id == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_create_user;

    const char* paramValues[8];
    int paramLengths[8];
    int paramFormats[8];

    paramValues[0] = pw;
    paramLengths[0] = 0;
    paramFormats[0] = 0;

    paramValues[1] = (char*)&exp_utc;
    paramLengths[1] = sizeof(exp_utc);
    paramFormats[1] = 1;

    paramValues[2] = "NULL";
    paramLengths[2] = 0;
    paramFormats[2] = 0;

    paramValues[3] = "13a7ce3df1606794d001bcc735023f391e42d0ae3add627ab14535492647e9525c4fc583bf21856e322568d70cc6105580e2203331d80e59f0c9db73393dc8b9";
    paramLengths[3] = 0;
    paramFormats[3] = 0;

    paramValues[4] = public_key_ed25519;
    paramLengths[4] = 0;
    paramFormats[4] = 0;

    paramValues[5] = encrypted_private_key_ed25519;
    paramLengths[5] = 0;
    paramFormats[5] = 0;

    paramValues[6] = public_key_curve448;
    paramLengths[6] = 0;
    paramFormats[6] = 0;

    paramValues[7] = encrypted_private_key_curve448;
    paramLengths[7] = 0;
    paramFormats[7] = 0;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    *out_user_id = last_used_userid = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);

    memcpy(last128B, public_key_curve448, OPSICK_MIN(64, strlen(public_key_curve448)));
    memcpy(last128B + 64, encrypted_private_key_curve448, OPSICK_MIN(64, strlen(encrypted_private_key_curve448)));

    rc = 0;
exit:
    PQclear(pr);
    return rc;
}

int opsick_db_delete_user(PGconn* dbconn, uint64_t user_id)
{
    if (dbconn == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_delete_user;

    const char* paramValues[1];
    int paramLengths[1];
    int paramFormats[1];

    paramValues[0] = (char*)&user_id;
    paramLengths[0] = sizeof(user_id);
    paramFormats[0] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_get_user_metadata(PGconn* dbconn, uint64_t user_id, struct opsick_user_metadata* out_user_metadata)
{
    if (dbconn == NULL || out_user_metadata == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_get_user;

    const char* paramValues[1];
    int paramLengths[1];
    int paramFormats[1];

    paramValues[0] = (char*)&user_id;
    paramLengths[0] = sizeof(user_id);
    paramFormats[0] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    out_user_metadata->id = (uint64_t)strtoull(PQgetvalue(pr, 0, 0), NULL, 10);
    out_user_metadata->iat_utc = (uint64_t)strtoull(PQgetvalue(pr, 0, 3), NULL, 10);
    out_user_metadata->exp_utc = (uint64_t)strtoull(PQgetvalue(pr, 0, 4), NULL, 10);
    out_user_metadata->lastmod_utc = (uint64_t)strtoull(PQgetvalue(pr, 0, 5), NULL, 10);

    const char* pw = PQgetvalue(pr, 0, 1);
    const char* totps = PQgetvalue(pr, 0, 2);
    const char* body_sha512 = PQgetvalue(pr, 0, 6);
    const char* public_key_ed25519 = PQgetvalue(pr, 0, 7);
    const char* encrypted_private_key_ed25519 = PQgetvalue(pr, 0, 8);
    const char* public_key_curve448 = PQgetvalue(pr, 0, 9);
    const char* encrypted_private_key_curve448 = PQgetvalue(pr, 0, 10);

    if (pw != NULL)
        snprintf(out_user_metadata->pw, sizeof(out_user_metadata->pw), "%s", pw);

    if (totps != NULL)
        snprintf(out_user_metadata->totps, sizeof(out_user_metadata->totps), "%s", totps);
    else
        memset(out_user_metadata->totps, 0x00, sizeof(out_user_metadata->totps));

    if (body_sha512 != NULL)
        snprintf(out_user_metadata->body_sha512, sizeof(out_user_metadata->body_sha512), "%s", body_sha512);

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
    PQclear(pr);
    return rc;
}

int opsick_db_set_user_pw(PGconn* dbconn, uint64_t user_id, const char* new_pw)
{
    if (dbconn == NULL || new_pw == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_set_user_pw;

    const char* paramValues[2];
    int paramLengths[2];
    int paramFormats[2];

    paramValues[0] = new_pw;
    paramLengths[0] = 0;
    paramFormats[0] = 0;

    paramValues[1] = (char*)&user_id;
    paramLengths[1] = sizeof(user_id);
    paramFormats[1] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_set_user_totps(PGconn* dbconn, uint64_t user_id, const char* new_totps)
{
    if (dbconn == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_set_user_totps;

    const char* paramValues[2];
    int paramLengths[2];
    int paramFormats[2];

    paramValues[0] = new_totps;
    paramLengths[0] = 0;
    paramFormats[0] = 0;

    paramValues[1] = (char*)&user_id;
    paramLengths[1] = sizeof(user_id);
    paramFormats[1] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_get_user_body(PGconn* dbconn, uint64_t user_id, char** out_body, size_t* out_body_length)
{
    if (dbconn == NULL || out_body == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_get_user_body;

    const char* paramValues[1];
    int paramLengths[1];
    int paramFormats[1];

    paramValues[0] = (char*)&user_id;
    paramLengths[0] = sizeof(user_id);
    paramFormats[0] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 0);

    if (PQresultStatus(pr) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "%s: Failure during execution of the SQL statement \"%s\". Error message: %s \n", __func__, sql, PQerrorMessage(dbconn));
        goto exit;
    }

    const char* body = PQgetvalue(pr, 0, 0);
    const size_t bodylen = strlen(body);

    *out_body = malloc(bodylen + 1);
    if (*out_body == NULL)
    {
        fprintf(stderr, "%s: OUT OF MEMORY! \n", __func__);
        goto exit;
    }

    memcpy(*out_body, body, bodylen);
    (*out_body)[bodylen] = '\0';

    if (out_body_length != NULL)
    {
        *out_body_length = bodylen;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_set_user_body(PGconn* dbconn, uint64_t user_id, const char* body)
{
    if (dbconn == NULL || body == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_set_user_body;

    const size_t bodylen = strlen(body);
    unsigned char body_sha512_bytes[64] = { 0x00 };
    mbedtls_sha512((unsigned char*)body, bodylen, body_sha512_bytes, 0);

    char body_sha512[128 + 1] = { 0x00 };
    cecies_bin2hexstr(body_sha512_bytes, sizeof(body_sha512_bytes), body_sha512, sizeof(body_sha512), NULL, true);

    const char* paramValues[3];
    int paramLengths[3];
    int paramFormats[3];

    paramValues[0] = body;
    paramLengths[0] = 0;
    paramFormats[0] = 0;

    paramValues[1] = body_sha512;
    paramLengths[1] = 0;
    paramFormats[1] = 0;

    paramValues[2] = (char*)&user_id;
    paramLengths[2] = sizeof(user_id);
    paramFormats[2] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure during execution of the SQL statement \"%s\". Error message: %s \n", sql, PQerrorMessage(dbconn));
        goto exit;
    }

    rc = 0;
    memcpy(last128B, body_sha512_bytes, 64);
    memcpy(last128B + 64, body, OPSICK_MIN(bodylen, 64));
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_set_user_exp(PGconn* dbconn, uint64_t user_id, const uint64_t new_exp)
{
    if (dbconn == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_set_user_exp;

    const char* paramValues[2];
    int paramLengths[2];
    int paramFormats[2];

    paramValues[0] = (char*)&new_exp;
    paramLengths[0] = sizeof(new_exp);
    paramFormats[0] = 1;

    paramValues[1] = (char*)&user_id;
    paramLengths[1] = sizeof(user_id);
    paramFormats[1] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure during execution of the SQL statement \"%s\". Error message: %s \n", sql, PQerrorMessage(dbconn));
        goto exit;
    }

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}

int opsick_db_set_user_keys(PGconn* dbconn, uint64_t user_id, const char* new_pubkey_ed25519, const char* new_prvkey_ed25519, const char* new_pubkey_curve448, const char* new_prvkey_curve448)
{
    if (dbconn == NULL || new_pubkey_ed25519 == NULL || new_prvkey_ed25519 == NULL || new_pubkey_curve448 == NULL || new_prvkey_curve448 == NULL)
    {
        return 1;
    }

    int rc = 1;
    const char* sql = opsick_sql_set_user_keys;
    const size_t new_pubkey_ed25519_length = strlen(new_pubkey_ed25519);
    const size_t new_pubkey_curve448_length = strlen(new_pubkey_curve448);

    const char* paramValues[5];
    int paramLengths[5];
    int paramFormats[5];

    paramValues[0] = new_pubkey_ed25519;
    paramLengths[0] = 0;
    paramFormats[0] = 0;

    paramValues[1] = new_prvkey_ed25519;
    paramLengths[1] = 0;
    paramFormats[1] = 0;

    paramValues[2] = new_pubkey_curve448;
    paramLengths[2] = 0;
    paramFormats[2] = 0;

    paramValues[3] = new_prvkey_curve448;
    paramLengths[3] = 0;
    paramFormats[3] = 0;

    paramValues[4] = (char*)&user_id;
    paramLengths[4] = sizeof(user_id);
    paramFormats[4] = 1;

    PGresult* pr = PQexecParams(dbconn, sql, 1, NULL, paramValues, paramLengths, paramFormats, 1);

    if (PQresultStatus(pr) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "opsick_db_create_user: Failure during execution of the SQL statement \"%s\". Error message: %s \n", sql, PQerrorMessage(dbconn));
        goto exit;
    }

    unsigned char sha512[64];

    mbedtls_sha512((const unsigned char*)new_pubkey_curve448, new_pubkey_curve448_length, sha512, 0);
    memcpy(last128B, sha512, 64);

    mbedtls_sha512((const unsigned char*)new_pubkey_ed25519, new_pubkey_ed25519_length, sha512, 0);
    memcpy(last128B + 64, sha512, 64);

    rc = 0;
exit:
    last_used_userid = user_id;
    PQclear(pr);
    return rc;
}
