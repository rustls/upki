#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Result type for upki C API functions.
 *
 * Values 0-15 indicate success (with specific status information).
 * Values 16 and above indicate errors.
 */
typedef enum upki_result {
  /**
   * Operation succeeded.
   */
  UPKI_OK = 0,
  /**
   * The certificate is not covered by the revocation data.
   */
  UPKI_REVOCATION_NOT_COVERED = 1,
  /**
   * The certificate has been revoked.
   */
  UPKI_REVOCATION_REVOKED = 2,
  /**
   * The certificate is not revoked.
   */
  UPKI_REVOCATION_NOT_REVOKED = 3,
  /**
   * A null pointer was passed where a valid pointer was required.
   */
  UPKI_ERR_NULL_POINTER = 16,
  /**
   * The config path is not valid UTF-8.
   */
  UPKI_ERR_CONFIG_PATH = 17,
  /**
   * An unknown error variant was added to the library.
   */
  UPKI_ERR_UNKNOWN = 18,
  /**
   * An unexpected panic occurred in the library.
   */
  UPKI_ERR_PANICKED = 19,
  /**
   * Failed to decode configuration file.
   */
  UPKI_ERR_CONFIG_DECODE = 32,
  /**
   * Failed to read configuration file.
   */
  UPKI_ERR_CONFIG_READ = 33,
  /**
   * No cache directory could be found.
   */
  UPKI_ERR_NO_CACHE_DIR = 34,
  /**
   * No configuration directory could be found.
   */
  UPKI_ERR_NO_CONFIG_DIR = 35,
  /**
   * The user's home directory could not be determined.
   */
  UPKI_ERR_NO_HOME_DIR = 36,
  /**
   * Failed to create a directory.
   */
  UPKI_ERR_REVOCATION_CREATE_DIR = 64,
  /**
   * Failed to write a file.
   */
  UPKI_ERR_REVOCATION_FILE_WRITE = 65,
  /**
   * Failed to decode a file.
   */
  UPKI_ERR_REVOCATION_FILE_DECODE = 66,
  /**
   * Failed to read a file.
   */
  UPKI_ERR_REVOCATION_FILE_READ = 67,
  /**
   * A downloaded file did not match the expected hash.
   */
  UPKI_ERR_REVOCATION_HASH_MISMATCH = 68,
  /**
   * Failed to fetch a file over HTTP.
   */
  UPKI_ERR_REVOCATION_HTTP_FETCH = 69,
  /**
   * Invalid base64 encoding.
   */
  UPKI_ERR_REVOCATION_INVALID_BASE64 = 70,
  /**
   * The end-entity certificate was invalid.
   */
  UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT = 71,
  /**
   * An intermediate certificate was invalid.
   */
  UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT = 72,
  /**
   * A base64-decoded value did not have the expected length.
   */
  UPKI_ERR_REVOCATION_INVALID_LENGTH = 73,
  /**
   * Invalid SCT encoding.
   */
  UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING = 74,
  /**
   * An SCT in the end-entity certificate could not be parsed.
   */
  UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT = 75,
  /**
   * A timestamp could not be parsed.
   */
  UPKI_ERR_REVOCATION_INVALID_TIMESTAMP = 76,
  /**
   * Failed to encode a manifest file.
   */
  UPKI_ERR_REVOCATION_MANIFEST_ENCODE = 77,
  /**
   * No issuer found for the end-entity certificate.
   */
  UPKI_ERR_REVOCATION_NO_ISSUER = 78,
  /**
   * Cache is outdated.
   */
  UPKI_ERR_REVOCATION_OUTDATED = 79,
  /**
   * Failed to remove a file.
   */
  UPKI_ERR_REVOCATION_REMOVE_FILE = 80,
  /**
   * Certificate chain must contain at least 2 certificates.
   */
  UPKI_ERR_REVOCATION_TOO_FEW_CERTS = 81,
} upki_result;

/**
 * Opaque type representing a `upki::Config`.
 */
typedef struct upki_config upki_config;

/**
 * A DER-encoded certificate.
 */
typedef struct upki_certificate_der {
  /**
   * Pointer to the DER-encoded certificate data.
   */
  const uint8_t *data;
  /**
   * Length of the certificate data in bytes.
   */
  uintptr_t len;
} upki_certificate_der;

/**
 * Check the revocation status of a certificate.
 *
 * The `certificates` array should contain the end-entity certificate first,
 * followed by any intermediate certificates needed to find the issuer.
 *
 * Returns a `upki_result` indicating success (with revocation status) or an error.
 *
 * # Safety
 *
 * - `config` must be a valid pointer returned by `upki_config_new`.
 * - `certificates` must point to `certificates_len` `upki_certificate` values.
 * - Each `upki_certificate` must have a valid `data` pointer to `len` bytes.
 */
enum upki_result upki_check_revocation(const struct upki_config *config,
                                       const struct upki_certificate_der *certificates,
                                       uintptr_t certificates_len);

/**
 * Create a new `upki_config` by loading it from the file at `path`.
 *
 * On success, writes the config pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the config with `upki_config_free`.
 *
 * # Safety
 *
 * - `out` must not be `NULL`.
 * - `path` must be a valid pointer to a null-terminated UTF-8 string.
 */
enum upki_result upki_config_from_file(const char *path, struct upki_config **out);

/**
 * Create a new `upki_config` with default settings.
 *
 * On success, writes the config pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the config with `upki_config_free`.
 *
 * # Safety
 *
 * - `out` must not be `NULL`.
 */
enum upki_result upki_config_new(struct upki_config **out);

/**
 * Free a `upki_config` created by `upki_config_new`.
 *
 * # Safety
 *
 * `config` must be a valid pointer returned by `upki_config_new`,
 * or null (in which case this is a no-op).
 */
void upki_config_free(struct upki_config *config);
