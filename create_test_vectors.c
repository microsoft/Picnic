/*! @file create_test_vectors.c
 *  @brief This program generates a test vector with intermediate values for
 *  the Picnic signature algorithm.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic_impl.h"
#include "picnic.h"
#include <stdio.h>
#include <memory.h>

#define MSG_LEN 500

/* Defined in picni_impl.c */
void printHex(const char* s, const uint8_t* data, size_t len);

int createTestVectors(picnic_params_t parameters)
{
    picnic_publickey_t pk;
    picnic_privatekey_t sk;
    uint8_t buf[PICNIC_MAX_PRIVATEKEY_SIZE + 1];

    printf("Picnic test vector with intermediate values for parameter set: %s\n", picnic_get_param_name(parameters) );

    int ret  = picnic_keygen(parameters, &pk, &sk);
    if (ret != 0) {
        printf("picnic_keygen failed\n");
        exit(-1);
    }

    int skSize = picnic_write_private_key(&sk, buf, sizeof(buf));
    if (skSize <= 0) {
        printf("Failed to serialize private key \n");
        exit(-1);
    }
    /* Omit the parameter set (the first byte) from the output */
    printHex("sk", buf + 1, skSize - 1 );

    int pkSize = picnic_write_public_key(&pk, buf, sizeof(buf));
    if (skSize <= 0) {
        printf("Failed to serialize public key \n");
        exit(-1);
    }
    /* Omit the parameter set (the first byte) from the output */
    printHex("pk", buf + 1, pkSize - 1);
    size_t blocksize = (pkSize - 1) / 2;
    printHex("pk_p", buf + 1, blocksize);
    printHex("pk_C", buf + 1 + blocksize, blocksize);


    uint8_t message[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
    printHex("message", message, sizeof(message));

    size_t signature_len = picnic_signature_size(parameters);
    uint8_t* signature = (uint8_t*)malloc(signature_len);
    if (signature == NULL) {
        printf("failed to allocate signature\n");
        exit(-1);
    }

    ret = picnic_sign(&sk, message, sizeof(message), signature, &signature_len);
    if (ret != 0) {
        printf("picnic_sign failed\n");
        free(signature);
        exit(-1);
    }

    /* signature_len has the exact number of bytes used */
    if (signature_len < picnic_signature_size(parameters)) {
        uint8_t* newsig = realloc(signature, signature_len);
        if (newsig == NULL) {
            printf("failed to re-size signature\n");
            /* Not an error, we can continue with signature */
        }
        else {
            signature = newsig;
        }
    }

    /* Print the serialized siganture */
    printHex("signature", signature, signature_len);
    printf("\n");

    /* Print the parsed signature */
    print_signature(signature, signature_len, parameters);

    printf("verify: ");
    ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
    if (ret != 0) {
        printf("picnic_verify failed\n");
        free(signature);
        exit(-1);
    }
    printf(" success\n");

    free(signature);

    return 1;

}

int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("provide an integer specifying the parameter set\n");
        exit(-1);
    }

    createTestVectors(atoi(argv[1]));

    return 0;
}
