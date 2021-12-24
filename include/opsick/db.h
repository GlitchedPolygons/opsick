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

#ifndef OPSICK_DB_H
#define OPSICK_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>
#include <libpq-fe.h>

#include "user.h"

/**
 * @file db.h
 * @author Raphael Beck
 * @brief Opsick DB interaction functions.
 */

/**
 * Initializes the db client, connecting to sqlite and setting up everything that's needed to query the database. This terminates opsick with a status code of <c>-1</c> in case of a failure!
 */
void opsick_db_init();

/**
 * Connects to the opsick db.
 * @return <c>NULL</c> if connection couldn't be established; the #sqlite3 reference otherwise.
 */
sqlite3* opsick_db_connect();

/**
 * Disconnects from the opsick db.
 * @param db The #sqlite3 handle to disconnect.
 */
void opsick_db_disconnect(sqlite3* db);

/**
 * Gets the current DB schema version number (via a SELECT statement). <p>
 * This number is increased with every DB schema migration.
 * @return The current db schema version number.
 */
uint64_t opsick_db_get_schema_version_number();

/**
 * Gets the id of the last active user.
 * @return User ID of the last user who interacted with the server.
 */
uint64_t opsick_db_get_last_used_userid();

/**
 * Gets the last 128B of trafficked ciphertext.
 * @return
 */
void opsick_db_last_128_bytes_of_ciphertext(uint8_t out[128]);

/**
 * When was the last time somebody checked the db schema version number?
 * @return UTC timestamp of the last schema version lookup.
 */
uint64_t opsick_db_get_last_db_schema_version_nr_lookup();

/**
 * Checks whether a given user id exists or not.
 * @param user_id The user id to check.
 * @return \c 0 if the user does not exist in the db; \c 1 if it does exist.
 */
int opsick_db_does_user_id_exist(sqlite3* db, uint64_t user_id);

/**
 * Adds a new user to the DB.
 * @param pw The user's password (hashed).
 * @param exp_utc When the user expires (UTC).
 * @param public_key_ed25519 The user's public Ed25519 key.
 * @param encrypted_private_key_ed25519 The user's encrypted private Ed25519 key.
 * @param public_key_curve448 The user's public Curve448 key.
 * @param encrypted_private_key_curve448 The user's encrypted private Curve448 key.
 * @param out_user_id Where to write the ID of the freshly created user into.
 * @return <c>0</c> on success; error code in case of a failure.
 */
int opsick_db_create_user(sqlite3* db, const char* pw, uint64_t exp_utc, const char* public_key_ed25519, const char* encrypted_private_key_ed25519, const char* public_key_curve448, const char* encrypted_private_key_curve448, uint64_t* out_user_id);

/**
 * Deletes a user from the DB.
 * @param user_id The user ID.
 * @return <c>0</c> on success; <c>1</c> if the user was not found or deletion from db failed for some other unknown reason.
 */
int opsick_db_delete_user(sqlite3* db, uint64_t user_id);

/**
 * Retrieves a user's metadata from the db.
 * @param user_id The user ID.
 * @param out_user_metadata Where to write the found metadata into (this will be left alone if the user wasn't found)
 * @return <c>0</c> on success; <c>1</c> if the user was not found or fetch from db failed for some other unknown reason.
 */
int opsick_db_get_user_metadata(sqlite3* db, uint64_t user_id, struct opsick_user_metadata* out_user_metadata);

/**
 * Changes a user's password in the db.
 * @param user_id User ID whose password you want to change.
 * @param new_pw The new pw hash.
 * @return <c>0</c> on success; <c>1</c> on failure.
 */
int opsick_db_set_user_pw(sqlite3* db, uint64_t user_id, const char* new_pw);

/**
 * Changes a user's TOTPS (TOTP secret for 2FA) in the db.
 * @param user_id User ID whose TOTPS you want to change.
 * @param new_pw The new TOTPS (base32 encoded).
 * @return <c>0</c> on success; <c>1</c> on failure.
 */
int opsick_db_set_user_totps(sqlite3* db, uint64_t user_id, const char* new_totps);

/**
 * Retrieves a user's body from the db.
 * @param user_id User id.
 * @param out_body Pointer to an output body string that will contain the retrieved user body (will be left untouched if the user couldn't be found). This will be malloc'ed on success, so don't forget to free()!
 * @param out_body_length [OPTIONAL] Where to write the output body length into (can be <c>NULL</c> if you don't need it).
 * @return <c>0</c> on success; <c>1</c> if the user was not found or fetch from db failed.
 */
int opsick_db_get_user_body(sqlite3* db, uint64_t user_id, char** out_body, size_t* out_body_length);

/**
 * Updates a user's body in the db.
 * @param user_id User id.
 * @param body The new body to write into the db.
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_body(sqlite3* db, uint64_t user_id, const char* body);

/**
 * Sets a new expiration datetime (UTC) to a user in the db.
 * @param user_id ID of the user whose expiration date needs to be changed.
 * @param new_exp The new UTC timestamp of when the user account will become read-only.
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_exp(sqlite3* db, uint64_t user_id, uint64_t new_exp);

/**
 * Updates a user's key pairs in the db.
 * @param user_id User id.
 * @param new_pubkey_ed25519 The new ed25519 public key (NUL-terminated C-string).
 * @param new_prvkey_ed25519 The new ed25519 encrypted private key (NUL-terminated C-string).
 * @param new_pubkey_curve448 The new curve448 public key (NUL-terminated C-string).
 * @param new_prvkey_curve448 The new curve448 encrypted private key (NUL-terminated C-string).
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_keys(sqlite3* db, uint64_t user_id, const char* new_pubkey_ed25519, const char* new_prvkey_ed25519, const char* new_pubkey_curve448, const char* new_prvkey_curve448);

/**
 * This frees all the related resources.
 */
void opsick_db_free();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_DB_H
