# Makefile of the C program of Keep.
#
#   make            keep, the program, and tests/keep-unit, the driver of its parts for the
#                   checks, both static against musl
#   make san        the same two against the system's C library with the sanitizers of the
#                   compiler, as keep-san and tests/keep-unit-san, and the scanner alone with
#                   them, as tests/keyscan-san, beside tests/keyscan, the scanner alone as the
#                   program links it
#   make clean
#
# musl-gcc is the package musl-tools of Debian and Ubuntu. A static program against musl needs
# nothing of the system it runs on, and musl's licence (MIT) lets the file be passed on as it is.
CC       = musl-gcc
SANCC    = cc
WARN     = -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Werror
CFLAGS   = -std=c11 -D_GNU_SOURCE -O2 $(WARN)
SAN      = -g -fsanitize=address,undefined -fno-sanitize-recover=all
PARTS    = src/dm.c src/hash.c src/json.c src/luks.c src/sys.c src/util.c src/volume.c
HEADERS  = Makefile src/dm.h src/hash.h src/json.h src/keyscan.h src/luks.h src/sys.h src/dump.h src/triage.h src/util.h src/volume.h
PROGRAM  = src/main.c src/dump.c src/triage.c $(PARTS)
# the scanner is the file of kcore-keyscan, without its main
SCANNER  = -DKEYSCAN_LIBRARY kcore-keyscan.c

all: keep tests/keep-unit
san: keep-san tests/keep-unit-san tests/keyscan tests/keyscan-san

keep: $(PROGRAM) $(HEADERS) kcore-keyscan.c
	$(CC) -static $(CFLAGS) -o $@ $(PROGRAM) $(SCANNER)

# keep-san is run on the whole memory of a machine, where the search under the sanitizers would
# take eight times as long. So the search is built without them here, and tests/keyscan-san is
# the scanner alone with them, which unit-check.sh runs on the fixtures.
keep-san: $(PROGRAM) $(HEADERS) kcore-keyscan.c
	$(SANCC) $(CFLAGS) -c -o tests/keyscan-plain.o $(SCANNER)
	$(SANCC) $(CFLAGS) $(SAN) -o $@ $(PROGRAM) tests/keyscan-plain.o

tests/keyscan: kcore-keyscan.c src/keyscan.h
	$(CC) -static $(CFLAGS) -o $@ kcore-keyscan.c

tests/keyscan-san: kcore-keyscan.c src/keyscan.h
	$(SANCC) $(CFLAGS) $(SAN) -o $@ kcore-keyscan.c

tests/keep-unit: tests/keep-unit.c $(PARTS) $(HEADERS)
	$(CC) -static $(CFLAGS) -o $@ tests/keep-unit.c $(PARTS)

tests/keep-unit-san: tests/keep-unit.c $(PARTS) $(HEADERS)
	$(SANCC) $(CFLAGS) $(SAN) -o $@ tests/keep-unit.c $(PARTS)

clean:
	rm -f keep keep-san tests/keep-unit tests/keep-unit-san tests/keyscan tests/keyscan-san tests/keyscan-plain.o

.PHONY: all san clean
