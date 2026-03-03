#ifndef UPKI_OPENSSL_H
#define UPKI_OPENSSL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/x509_vfy.h>
#include "upki.h"

/**
 * Sets the upki config to use for connections based upon `ctx`.
 *
 * `config` becomes owned by `SSL_CTX`.  If `config` is NULL the previous configuration is
 * freed.
 *
 * # Thread safety
 *
 * This inherits the property of the OpenSSL API, whereby a single `SSL_CTX` cannot be shared
 * between threads.
 *
 * # Safety
 *
 * This does nothing if `ctx` is NULL.  `config` is required to be a valid `upki_config` pointer,
 * or NULL.
 */
void upki_openssl_set_config(SSL_CTX *ctx, const upki_config *config);

/**
 * Checks certificate revocation using upki, matching OpenSSL's `SSL_verify_cb` interface.
 *
 * This function returns 0 if called with 0 for the `preverify_ok` parameter.
 * As a result, it never allows a verification to pass if the previous verification
 * step has failed.
 *
 * If the certificate chain obtained from `x509_ctx` is not included in the revocation data,
 * this function returns `preverify_ok`.
 *
 * # Configuration
 *
 * If ``upki_openssl_set_config()` was previously called against the `SSL_CTX` available
 * from `X509_STORE_CTX`, this configuration is used.
 *
 * Otherwise, if that function wasn't called, or no `SSL_CTX` can be obtained from `X509_STORE_CTX`,
 * the configuration file and data location is found automatically based on defaults.
 *
 * # Errors
 *
 * If the certificate chain obtained from `x509_ctx` is revoked, this function returns 0
 * and sets the `X509_V_ERR_CERT_REVOKED` error on `x509_ctx` (using
 * `X509_STORE_CTX_set_error(3SSL)`).
 *
 * If the revocation status cannot be determined, this function returns 0 and sets
 * the `X509_V_ERR_APPLICATION_VERIFICATION` error on `x509_ctx` (using
 * `X509_STORE_CTX_set_error(3SSL)`).
 *
 * On unexpected/unrecoverable errors, this function returns 0.
 *
 * # Safety
 *
 * This function requires that `x509_ctx` is a valid pointer, or NULL.
 */
int upki_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

#endif  /* UPKI_OPENSSL_H */
