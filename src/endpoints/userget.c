#include "opsick/db.h"
#include "opsick/util.h"
#include "opsick/constants.h"
#include "opsick/endpoints/userget.h"

#include <tfac.h>
#include <argon2.h>
#include <sqlite3.h>
#include <ed25519.h>
#include <cecies/encrypt.h>
#include <mbedtls/platform_util.h>

void opsick_init_endpoint_userget()
{
    // nop
}

void opsick_get_user(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    sqlite3* db = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    db = opsick_db_connect();
    if (db == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);

    if (opsick_db_get_user_metadata(db, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Verify request signature.
    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Check user password.
    if (argon2id_verify(user_metadata.pw, pw_strobj.data, pw_strobj.len) != ARGON2_OK)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Check TOTP (if user has 2FA enabled).
    if (opsick_user_has_totp_active(&user_metadata) && !tfac_verify_totp(user_metadata.totps, totp_obj ? fiobj_obj2cstr(totp_obj).data : "", OPSICK_2FA_STEPS, OPSICK_2FA_HASH_ALGO))
    {
        http_send_error(request, 403);
        goto exit;
    }

    char out_json[1024];
    snprintf(out_json, sizeof(out_json),
            "{\"id\":%zu,\"iat_utc\":%zu,\"exp_utc\":%zu,\"lastmod_utc\":%zu,\"public_key_ed25519\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"public_key_curve448\":\"%s\",\"encrypted_private_key_curve448\":\"%s\"}", //
            user_metadata.id, user_metadata.iat_utc, user_metadata.exp_utc, user_metadata.lastmod_utc, user_metadata.public_key_ed25519.hexstring, user_metadata.encrypted_private_key_ed25519, user_metadata.public_key_curve448.hexstring, user_metadata.encrypted_private_key_curve448 //
    );

    size_t out_enc_len = 0;
    char out_enc[2048];

    if (cecies_curve448_encrypt((unsigned char*)out_json, strlen(out_json), user_metadata.public_key_curve448, (unsigned char*)out_enc, sizeof(out_enc), &out_enc_len, true) != 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    opsick_sign_and_send(request, out_enc, out_enc_len);

    mbedtls_platform_zeroize(out_json, sizeof(out_json));

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(db);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

void opsick_free_endpoint_userget()
{
    // nop
}