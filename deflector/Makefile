all: deflector bypass

deflector:
	gcc deflector.c common.h -o d

bypass:
	gcc bypass.c common.h -o b


clean:
	rm -f d b


install:
	scp bypass.c deflector.c common.h Makefile symbiosis_flower.py symbiosis_server.py symbiosis.py esyee@flower.Symbiosis.CAT.emulab.net:/users/esyee/