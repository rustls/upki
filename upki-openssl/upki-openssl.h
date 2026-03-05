#ifndef UPKI_OPENSSL_H
#define UPKI_OPENSSL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/x509_vfy.h>

/**
 * This is a function matching OpenSSL's `SSL_verify_cb` type which does
 * revocation checking using upki.
 *
 * The configuration file and data location is found automatically.
 *
 * # Safety
 * Not very.
 */
int upki_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

#endif  /* UPKI_OPENSSL_H */
