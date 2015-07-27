all: deflector bypass

deflector:
	gcc deflector.c common.h -o d

bypass:
	gcc bypass.c common.h -o b


clean:
	rm -f d b


emulab:
	scp pki/ss.crt pki/private.key src/bypass.c src/deflector.c lib/common.h Makefile src/symbiosis_flower.py src/symbiosis_server.py src/symbiosis.py src/diffie_hellman.py esyee@flower.Symbiosis.CAT.emulab.net:/users/esyee/

git:
	cp src/symbiosis.py src/symbiosis_bee.py src/diffie_hellman.py ../symbiosis/bee
	cp src/symbiosis.py src/symbiosis_flower.py src/diffie_hellman.py ../symbiosis/flower
	cp src/symbiosis.py src/symbiosis_server.py src/diffie_hellman.py ../symbiosis/server
	cp lib/common.h src/bypass.c Makefile ../symbiosis/bypass
	cp lib/common.h src/deflector.c Makefile ../symbiosis/deflector
	