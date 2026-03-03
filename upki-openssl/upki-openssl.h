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
 * This function is called by OpenSSL typically, and its correct operation
 * hinges almost entirely on being called properly.  For example, that
 * `x509_ctx` is a valid pointer, or NULL.
 *
 * On unexpected/unrecoverable errors, this function returns 0.
 */
int upki_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

#endif  /* UPKI_OPENSSL_H */
