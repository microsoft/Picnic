/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic.h"

#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef KATDIR
#define KATDIR "kats"
#endif
#define PICNIC_CONCAT2(a, b) a##_##b
#define PICNIC_CONCAT(a, b) PICNIC_CONCAT2(a, b)

#define LOWMC_BLOCK_SIZE_Picnic_L1_FS 16
#define LOWMC_BLOCK_SIZE_Picnic_L1_UR 16
#define LOWMC_BLOCK_SIZE_Picnic_L3_FS 24
#define LOWMC_BLOCK_SIZE_Picnic_L3_UR 24
#define LOWMC_BLOCK_SIZE_Picnic_L5_FS 32
#define LOWMC_BLOCK_SIZE_Picnic_L5_UR 32
#define LOWMC_BLOCK_SIZE_Picnic3_L1 17
#define LOWMC_BLOCK_SIZE_Picnic3_L3 24
#define LOWMC_BLOCK_SIZE_Picnic3_L5 32
#define LOWMC_BLOCK_SIZE_Picnic_L1_full 17
#define LOWMC_BLOCK_SIZE_Picnic_L3_full 24
#define LOWMC_BLOCK_SIZE_Picnic_L5_full 32


#define LOWMC_BLOCK_SIZE(p) PICNIC_CONCAT(LOWMC_BLOCK_SIZE, p)

#define MAX_LOWMC_ROUNDS 38
#define MAX_LOWMC_SBOXES 10
#define MAX_ROUNDS 438

#define PICNIC_PRIVATE_KEY_SIZE(p) (1 + 3 * LOWMC_BLOCK_SIZE(p))
#define PICNIC_PUBLIC_KEY_SIZE(p) (1 + 2 * LOWMC_BLOCK_SIZE(p))

typedef struct {
  size_t mlen;
  uint8_t* msg;
  uint8_t pk[PICNIC_MAX_PUBLICKEY_SIZE];
  uint8_t sk[PICNIC_MAX_PRIVATEKEY_SIZE];
  size_t smlen;
  uint8_t* sm;
} test_vector_t;

static void clear_test_vector(test_vector_t* tv) {
  free(tv->msg);
  free(tv->sm);
  memset(tv, 0, sizeof(*tv));
}

static uint8_t parse_hex_c(const char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return 10 + c - 'a';
  } else if (c >= 'A' && c <= 'F') {
    return 10 + c - 'A';
  } else {
    return UINT8_MAX;
  }
}

static int parse_hex(uint8_t* dst, const char* src, size_t len) {
  for (size_t s = 0; s < len; ++s, src += 2, ++dst) {
    uint8_t high = parse_hex_c(src[0]);
    uint8_t low  = parse_hex_c(src[1]);
    if (high == UINT8_MAX || low == UINT8_MAX) {
      printf("parse_hex failed\n");
      return -1;
    }
    *dst = high << 4 | low;
  }
  return 0;
}

static int read_test_vector(FILE* file, test_vector_t* tv, size_t pks, size_t sks) {
  char* line = NULL;
  size_t len = 0;
  ssize_t nread;
  bool expect_data = false;

  while ((nread = getline(&line, &len, file)) != -1) {
    if (nread <= 1 || line[0] == '#') {
      if (expect_data) {
        printf("Expected data.\n");
        goto err;
      }
      // skip empty lines and comments
      continue;
    }

    const size_t uread = nread;
    if (strncmp(line, "count = ", 8) == 0) {
      // skip count
      expect_data = true;
      continue;
    } else if (strncmp(line, "seed = ", 7) == 0) {
      // skip seed
      continue;
    } else if (strncmp(line, "mlen = ", 7) == 0) {
      // read message length
      if (sscanf(line + 7, "%zu", &tv->mlen) != 1) {
        goto err;
      }
    } else if (strncmp(line, "msg = ", 6) == 0 && tv->mlen && uread >= 2 * tv->mlen + 6) {
      // read message
      tv->msg = calloc(1, tv->mlen);
      if (parse_hex(tv->msg, line + 6, tv->mlen) == -1) {
        goto err;
      }
    } else if (strncmp(line, "pk = ", 5) == 0 && uread >= 2 * pks + 5) {
      // read pk
      if (parse_hex(tv->pk, line + 5, pks) == -1) {
        goto err;
      }
    } else if (strncmp(line, "sk = ", 5) == 0 && uread >= 2 * sks + 5) {
      // read sk
      if (parse_hex(tv->sk, line + 5, sks) == -1) {
        goto err;
      }
    } else if (strncmp(line, "smlen = ", 8) == 0) {
      // read signature length
      if (sscanf(line + 8, "%zu", &tv->smlen) != 1) {
        goto err;
      }
    } else if (strncmp(line, "sm = ", 5) == 0 && tv->smlen && uread >= 2 * tv->smlen + 5) {
      // read signature
      tv->sm = calloc(1, tv->smlen);
      if (parse_hex(tv->sm, line + 5, tv->smlen) == -1) {
        goto err;
      }
      break;
    } else {
      printf("Do not know how handle line (len = %zu): %s", uread, line);
      goto err;
    }
  }
  if (!tv->mlen || !tv->smlen || !tv->msg || !tv->sm) {
    goto err;
  }

  free(line);
  return 0;

err:
  free(line);
  clear_test_vector(tv);
  return -1;
}

static int run_picnic_test(const uint8_t* msg, size_t msg_len, const uint8_t* pk, size_t pk_len,
                           const uint8_t* sk, size_t sk_len, const uint8_t* sig, size_t sig_len) {
  picnic_privatekey_t private_key;
  picnic_publickey_t public_key;
  size_t signature_len = sig_len + 5000;

  uint8_t* signature = malloc(signature_len);

  int ret = picnic_read_private_key(&private_key, sk, sk_len);
  if (ret != 0) {
    printf("Unable to read private key.\n");
    goto err;
  }

  ret = picnic_read_public_key(&public_key, pk, pk_len);
  if (ret != 0) {
    printf("Unable to read public key.\n");
    goto err;
  }

  ret = picnic_validate_keypair(&private_key, &public_key);
  if (ret != 0) {
    printf("Key pair does not validate.\n");
    goto err;
  }

  /* Recreate the signature, check it matches */
  ret = picnic_sign(&private_key, msg, msg_len, signature, &signature_len);
  if (ret != 0) {
    printf("Unable to sign.\n");
    goto err;
  }

  if (signature_len != sig_len) {
    printf("Signature length does not match.\n");
    goto err;
  }
  if (memcmp(sig, signature, signature_len) != 0) {
    printf("Signature does not match.\n");
    goto err;
  }

  /* Verify the provided signature */
  ret = picnic_verify(&public_key, msg, msg_len, sig, sig_len);
  if (ret != 0) {
    printf("Signature does not verify.\n");
    goto err;
  }

  free(signature);
  return 1;

err:
  free(signature);
  return 0;
}

static int run_test_vectors_from_file(const char* path, size_t pks, size_t sks) {
  FILE* file = fopen(path, "r");
  if (!file) {
    return 0;
  }

  size_t vectors_run       = 0;
  size_t vectors_succeeded = 0;
  test_vector_t tv         = {0, NULL, {0}, {0}, 0, NULL};
  while (read_test_vector(file, &tv, pks, sks) != -1) {
    // Test vectors generated for NIST have message length and the message at the beginning.
    const size_t offset = tv.mlen + sizeof(uint32_t);

    ++vectors_run;
    vectors_succeeded +=
        run_picnic_test(tv.msg, tv.mlen, tv.pk, pks, tv.sk, sks, tv.sm + offset, tv.smlen - offset);
    clear_test_vector(&tv);
  };
  fclose(file);

  return (vectors_run && vectors_succeeded == vectors_run) ? 1 : 0;
}

static int picnic_test_vector_L1FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l1_fs.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L1_FS),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L1_FS));
}

static int picnic_test_vector_L1UR(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l1_ur.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L1_UR),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L1_FS));
}

static int picnic_test_vector_L3FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l3_fs.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L3_FS),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L3_FS));
}

static int picnic_test_vector_L3UR(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l3_ur.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L3_UR),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L3_FS));
}

static int picnic_test_vector_L5FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l5_fs.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_FS),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_FS));
}

static int picnic_test_vector_L5UR(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l5_ur.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_UR),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_FS));
}

static int picnic3_test_vector_L1FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_picnic3_l1.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic3_L1),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic3_L1));
}

static int picnic3_test_vector_L3FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_picnic3_l3.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic3_L3),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic3_L3));
}

static int picnic3_test_vector_L5FS(void) {
  return run_test_vectors_from_file(KATDIR "/kat_picnic3_l5.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic3_L5),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic3_L5));
}

static int picnic_test_vector_L1full(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l1_full.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L1_full),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L1_full));
}

static int picnic_test_vector_L3full(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l3_full.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L3_full),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L3_full));
}

static int picnic_test_vector_L5full(void) {
  return run_test_vectors_from_file(KATDIR "/kat_l5_full.txt", PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_full),
                                    PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_full));
}


typedef int (*test_fn_t)(void);

#if 1
static const test_fn_t tests[] = { NULL, // 0
    picnic_test_vector_L1FS, // 1
    picnic_test_vector_L1UR, // 2
    picnic_test_vector_L3FS, 
    picnic_test_vector_L3UR,
    picnic_test_vector_L5FS, 
    picnic_test_vector_L5UR,
    picnic3_test_vector_L1FS, //7
    picnic3_test_vector_L3FS,
    picnic3_test_vector_L5FS, 
    picnic_test_vector_L1full, //9
    picnic_test_vector_L3full, 
    picnic_test_vector_L5full};
#endif
//static const test_fn_t tests[] = {picnic3_test_vector_L1FS}; 

static const size_t num_tests = sizeof(tests) / sizeof(tests[0]);

int main(void) {
  int ret = 0;
  for (size_t s = 1; s < num_tests; ++s) {
    const int t = tests[s]();
    if (!t) {
      printf("ERR: Picnic KAT test %s %zu FAILED (%d)\n", picnic_get_param_name(s), s, t );
      ret = -1;
    }
  }

  return ret;
}
