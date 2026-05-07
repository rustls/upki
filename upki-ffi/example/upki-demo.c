#include <stdio.h>

#include "../upki.h"
#include "demo-certs.h"

int main() {
  upki_config *config = NULL;
  upki_result e = upki_config_new(NULL, &config);
  if (e != UPKI_OK) {
    fprintf(stderr, "cannot load upki configuration: %d\n", e);
    return 1;
  }

  // Get some certificates from somewhere. For demo purposes, we have some
  // sampled from rustls.dev.  This is not a serious approach, but simplifies
  // this demo.
  upki_certificate_der certs[2] = {
      {.data = CERT_0_DER, .len = CERT_0_DER_LEN},
      {.data = CERT_1_DER, .len = CERT_1_DER_LEN},
  };

  e = upki_check_revocation(config, certs, sizeof(certs) / sizeof(certs[0]));
  upki_config_free(config);

  switch (e) {
  case UPKI_REVOCATION_NOT_REVOKED:
  case UPKI_REVOCATION_NOT_COVERED:
    printf("revocation status: %d\n", e);
    return 0;
  default:
    printf("revocation error: %d\n", e);
    return 1;
  }
}
