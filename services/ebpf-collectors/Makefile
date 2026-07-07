CC = gcc
CFLAGS = -Wall -Wextra -O2

.PHONY: all clean

all: process_collector network_collector

process_collector: src/process_collector.c
	$(CC) $(CFLAGS) -o $@ $<

network_collector: src/network_collector.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f process_collector network_collector
