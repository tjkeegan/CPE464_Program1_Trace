# Example makefile for CPE464 Trace program
#
# Just links in pcap library, Winter 2026

CC = gcc
LIBS = -lpcap
CFLAGS = -g -Wall -pedantic -std=gnu99


PCAP_DIR := traceFiles_2026_v2
PCAPS := $(wildcard $(PCAP_DIR)/*.pcap)
OUTS  := $(PCAPS:.pcap=_NEW.out)

all:  trace 
outFiles: $(OUTS)

trace: trace.c checksum.c
	$(CC) $(CFLAGS) -o $@ trace.c checksum.c $(LIBS)

# runs trace on all .pcap files in traceFiles_2026_v2 and outputs *_NEW.out files
%_NEW.out: %.pcap
	./trace $< > $@

# compares each *_NEW.out file to the corresponding .out file and reports differences
test: trace outFiles
	@for out in $(OUTS); do \
		expected=$${out%_NEW.out}.out; \
		echo "Comparing $$out to $$expected"; \
		diff "$$expected" "$$out"; \
	done

clean:
	rm -f trace $(OUTS)
