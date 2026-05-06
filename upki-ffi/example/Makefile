LIBDIR = ../../target/release

upki-demo: upki-demo.c demo-certs.h
	$(CC) -o $@ $< -I.. -L$(LIBDIR) -lupki_ffi -Wl,-rpath,$(LIBDIR)

clean:
	rm -f upki-demo
