# Usage:
# target: dependence1 dependence2 dependence3
# 		$(CC) $(CFLAGS) $@ $<
# 		$(CC) $(CFLAGS) $@ $^
CC = g++
CFLAGS += -Wall -I "./include/" 
LDFLAGS += -lpcap

footprints: main.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.cpp
	$(CC) $(CFLAGS)  -c -o $@ $<
clean:
	rm *.o footprints
