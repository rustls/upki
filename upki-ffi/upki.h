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
   * Failed to determine platform-specific default directories.
   */
  UPKI_ERR_PLATFORM = 17,
  /**
   * Failed to load the revocation manifest.
   */
  UPKI_ERR_MANIFEST = 18,
  /**
   * Failed to perform the revocation check.
   */
  UPKI_ERR_REVOCATION_CHECK = 19,
  /**
   * The config path is not valid UTF-8.
   */
  UPKI_ERR_CONFIG_PATH = 20,
  /**
   * Failed to load the config file.
   */
  UPKI_ERR_CONFIG_FILE = 21,
} upki_result;

/**
 * Opaque type representing a `upki::Config`.
 */
typedef struct upki_config upki_config;

/**
 * A certificate transparency timestamp.
 */
typedef struct upki_ct_timestamp {
  /**
   * CT log ID (32 bytes).
   */
  uint8_t log_id[32];
  /**
   * Issuance timestamp.
   */
  uint64_t timestamp;
} upki_ct_timestamp;

/**
 * Check the revocation status of a certificate.
 *
 * Returns a `upki_result` indicating success (with revocation status) or an error.
 *
 * # Safety
 *
 * - `config` must be a valid pointer returned by `upki_config_new`.
 * - `serial_ptr` must point to `serial_len` bytes.
 * - `issuer_spki_hash` must point to exactly 32 bytes.
 * - `ct_timestamps` must point to `ct_timestamps_len` `upki_ct_timestamp` values.
 */
enum upki_result upki_check_revocation(const struct upki_config *config,
                                       const uint8_t *serial_ptr,
                                       uintptr_t serial_len,
                                       const uint8_t *issuer_spki_hash,
                                       const struct upki_ct_timestamp *ct_timestamps,
                                       uintptr_t ct_timestamps_len);

/**
 * Create a new `upki_config` by loading it from the file at `path`.
 *
 * On success, writes the config pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the config with `upki_config_free`.
 *
 * # Safety
 *
 * - `out` must be a valid pointer to a `*mut upki_config`.
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
 * `out` must be a valid pointer to a `*mut upki_config`.
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
