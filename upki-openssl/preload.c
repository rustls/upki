#include "upki-openssl.h"
#include <dlfcn.h>
#include <openssl/ssl.h>

typedef SSL *(*ssl_new_fn)(SSL_CTX *);

SSL *SSL_new(SSL_CTX *ctx) {
  void *parent = dlsym(RTLD_NEXT, "SSL_new");
  if (!parent) {
    return NULL;
  }

  SSL *new = ((ssl_new_fn)(parent))(ctx);
  if (!new) {
    return new;
  }

  //  TODO: save and call current too.
  // SSL_verify_cb current = SSL_get_verify_callback(new);
  int mode = SSL_get_verify_mode(new);
  SSL_set_verify(new, mode, upki_openssl_verify_callback);
  return new;
}

// TODO: also hook later calls of SSL_set_verify, SSL_get_verify_callback
