CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -pthread -g 
LFLAGS=-lpcap 
FILES=main.c
PROJ=ipk-sniffer

all : $(PROJ)

$(PROJ) : $(FILES)
		gcc $(CFLAGS) -o $(PROJ) $(FILES) $(LFLAGS)

clean :
	rm -f *.o $(PROJ) 