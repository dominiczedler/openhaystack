
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "string.h"

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encoded_size(size_t inlen)
{
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

char *b64_encode(const unsigned char *in, size_t len)
{
    char *out;
    size_t elen;
    size_t i;
    size_t j;
    size_t v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out = malloc(elen + 1);
    out[elen] = '\0';

    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        v = in[i];
        v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
        v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        if (i + 1 < len)
        {
            out[j + 2] = b64chars[(v >> 6) & 0x3F];
        }
        else
        {
            out[j + 2] = '=';
        }
        if (i + 2 < len)
        {
            out[j + 3] = b64chars[v & 0x3F];
        }
        else
        {
            out[j + 3] = '=';
        }
    }

    return out;
}

void generateNewPrivateKey(uint8_t *privateKeyBytes)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp224r1);
    if (EC_KEY_generate_key(key) == 0)
    {
        return;
    }

    const BIGNUM *privateKey = EC_KEY_get0_private_key(key);
    size_t keySize = BN_num_bytes(privateKey);
    // Convert to bytes


    size_t size = BN_bn2bin(privateKey, privateKeyBytes);

    EC_KEY_free(key);
    if (size == 0)
    {
        return ;
    }

}

EC_KEY *deriveEllipticCurvePrivateKey(uint8_t *privateKeyBytes, EC_GROUP *group)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp224r1);
    EC_POINT *point = EC_POINT_new(group);

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // Read in the private key data
    BIGNUM *privateKeyNum = BN_bin2bn(privateKeyBytes, strlen(privateKeyBytes), NULL);
    int res = EC_POINT_mul(group, point, privateKeyNum, NULL, NULL, ctx);

    res = EC_KEY_set_public_key(key, point);
    EC_POINT_free(point);

    EC_KEY_set_private_key(key, privateKeyNum);
    BN_free(privateKeyNum);

    // Free
    BN_CTX_free(ctx);

    return key;
}

/// Derive a public key from a given private key
/// @param privateKeyData an EC private key on the P-224 curve
void derivePublicKeyFromPrivateKey(uint8_t *privateKeyBytes, uint8_t *publicKeyBytes)
{
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_secp224r1);
    EC_KEY *key = deriveEllipticCurvePrivateKey(privateKeyBytes, curve);

    const EC_POINT *publicKey = EC_KEY_get0_public_key(key);

    size_t keySize = 28 + 1;

    size_t size = EC_POINT_point2oct(curve, publicKey, POINT_CONVERSION_COMPRESSED, publicKeyBytes, keySize, NULL);

    // Free
    EC_KEY_free(key);
    EC_GROUP_free(curve);
}

void printArray(uint8_t *arr, size_t size)
{
    printf("Length %zd,\n", size);
    for (int i = 0; i < size; i++)
    {
        printf("0x%02x", arr[i] & 0xff);
        if (i < size - 1)
        {
            printf(",");
        }
    }
    printf("\n\n");
}

int generateNewKey(FILE *jsonPtr, FILE *arrayPtr)
{

    char prvBeforeBuf[28] = {};
    generateNewPrivateKey(prvBeforeBuf);

    char *encodedPrivateKey;
    encodedPrivateKey = b64_encode((const unsigned char *)prvBeforeBuf, 28);
    printf("encoded private key: '%s' (%zu) \n", encodedPrivateKey, strlen(prvBeforeBuf));

    if (strlen(encodedPrivateKey) != 40)
    {
        printf("Private key has wrong length. Generating new\n");
        generateNewKey(jsonPtr, arrayPtr);
        return 0;
    }

    /* Public */
    uint8_t publicKey[29] = {};
    derivePublicKeyFromPrivateKey(prvBeforeBuf, publicKey);
    printArray(publicKey, strlen(prvBeforeBuf));

    char *enc = b64_encode((const unsigned char *)publicKey, 29);
    printf("encoded public key: '%s' (%zu)\n", enc, strlen(enc));
    if (strlen(enc) != 40)
    {
        printf("Public key has wrong length. Generating new\n");
        generateNewKey(jsonPtr, arrayPtr);
        return 0;
    }

    printArray(publicKey, 29);

    size_t advSize = 28;
    char adv[advSize];
    int i;

    for (i = 1; i < strlen(publicKey); i++)
    {
        adv[i - 1] = publicKey[i];
    }

    enc = b64_encode((const unsigned char *)adv, advSize);
    printf("encoded advertisement key: '%s' (%zu)\n", enc, strlen(enc));
    if (strlen(enc) != 40)
    {
        printf("Advertisement key has wrong length. Generating new\n");
        generateNewKey(jsonPtr, arrayPtr);
        return 0;
    }
    printArray(adv, advSize);

    unsigned char *d = SHA224(prvBeforeBuf, strlen(prvBeforeBuf), 0);
    fprintf(jsonPtr, "\"id\": ");
    for (i = 0; i < 5; i++)
    {
        fprintf(jsonPtr, "%d", d[i]);
    }
    fprintf(jsonPtr, ",\n");
    fprintf(jsonPtr, "\"name\": \"%s\",\n", "Test Random");

    fprintf(jsonPtr, "\"privateKey\": \"");
    fprintf(jsonPtr, "%s\",\n", encodedPrivateKey);

    fprintf(jsonPtr, "\"isDeployed\": true");

    fprintf(arrayPtr, "{");

    for (i = 0; i < advSize; i++)
    {
        fprintf(arrayPtr, "0x%02x", adv[i] & 0xff);
        if (i < advSize - 1)
        {
            fprintf(arrayPtr, ",");
        }
    }

    fprintf(arrayPtr, "}");
}

int main()
{

    // creating file pointer to work with files
    FILE *jsonPtr, *arrayPtr;

    // opening file in writing mode
    jsonPtr = fopen("release/devices.json", "w");
    arrayPtr = fopen("release/array.txt", "w");
    fprintf(jsonPtr, "[");
    fprintf(arrayPtr, "static uint8_t public_keys[][28] = {");
    int i;
    const int MAX = 10;
    for (i = 0; i < MAX; i++)
    {
        fprintf(jsonPtr, "{");
        generateNewKey(jsonPtr, arrayPtr);
        fprintf(jsonPtr, "}");
        if (i < MAX - 1)
        {
            fprintf(jsonPtr, ",");
            fprintf(arrayPtr, ",");
        }
    }
    fprintf(jsonPtr, "]");
    fprintf(arrayPtr, "};");
    fclose(jsonPtr);
    fclose(arrayPtr);
}