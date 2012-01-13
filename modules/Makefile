CC=gcc
OUTDIR=../bindir/modules

all:	modscmgit modscmsvn moddnsbind modsendmail modcron

modscmgit:
	mkdir -p $(OUTDIR)
	$(CC) -c -fPIC mod_scm_git.c
	$(CC) -shared -fPIC -o $(OUTDIR)/mod_scm_git.so mod_scm_git.o
	rm -f *.o

modscmsvn:
	mkdir -p $(OUTDIR)
	$(CC) -c -fPIC mod_scm_svn.c
	$(CC) -shared -fPIC -o $(OUTDIR)/mod_scm_svn.so mod_scm_svn.o
	rm -f *.o

moddnsbind:
	mkdir -p $(OUTDIR)
	$(CC) -c -fPIC mod_dns_bind.c
	$(CC) -shared -fPIC -o $(OUTDIR)/mod_dns_bind.so mod_dns_bind.o
	rm -f *.o

modsendmail:
	mkdir -p $(OUTDIR)
	$(CC) -c -fPIC mod_sendmail.c
	$(CC) -shared -fPIC -o $(OUTDIR)/mod_sendmail.so mod_sendmail.o
	rm -f *.o

modcron:
	mkdir -p $(OUTDIR)
	$(CC) -c -fPIC mod_cron.c
	$(CC) -shared -fPIC -o $(OUTDIR)/mod_cron.so mod_cron.o
	rm -f *.o

clean:
	rm -rf $(BINARY)
