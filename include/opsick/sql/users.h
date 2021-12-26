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

#ifndef OPSICK_USERS_H
#define OPSICK_USERS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file users.h
 * @author Raphael Beck
 * @brief SQL statements for interacting with the Opsick DB's users table (parametrized).
 */

static const char opsick_sql_does_user_id_exist[] = "SELECT count(id) FROM users WHERE id = $1::bigint";
static const char opsick_sql_get_user[] = "SELECT id, pw, totps, iat_utc, exp_utc, lastmod_utc, body_sha512, public_key_ed25519, encrypted_private_key_ed25519, public_key_curve448, encrypted_private_key_curve448 FROM users WHERE id = $1::bigint";
static const char opsick_sql_get_user_body[] = "SELECT body FROM users WHERE id = $1::bigint";

static const char opsick_sql_create_user[] = "INSERT INTO users (pw, exp_utc, body, body_sha512, public_key_ed25519, encrypted_private_key_ed25519, public_key_curve448, encrypted_private_key_curve448) VALUES ($1::text, $2::bigint, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text) RETURNING id";
static const char opsick_sql_delete_user[] = "DELETE FROM users WHERE id = $1::bigint";

static const char opsick_sql_set_user_pw[] = "UPDATE users SET pw = $1::text, lastmod_utc = (SELECT UTC_NOW()) WHERE id = $2::bigint";
static const char opsick_sql_set_user_body[] = "UPDATE users SET body = $1::text, body_sha512 = $2::text, lastmod_utc = (SELECT UTC_NOW()) WHERE id = $3::bigint";
static const char opsick_sql_set_user_exp[] = "UPDATE users SET exp_utc = $1::bigint, lastmod_utc = (SELECT UTC_NOW()) WHERE id = $2::bigint";
static const char opsick_sql_set_user_totps[] = "UPDATE users SET totps = $1::text, lastmod_utc = (SELECT UTC_NOW()) WHERE id = $2::bigint";
static const char opsick_sql_set_user_keys[] = "UPDATE users SET public_key_ed25519 = $1::text, encrypted_private_key_ed25519 = $2::text, public_key_curve448 = $3::text, encrypted_private_key_curve448 = $4::text, lastmod_utc = (SELECT UTC_NOW()) WHERE id = $5::bigint";

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_USERS_H
