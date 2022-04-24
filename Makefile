CFLAGS=-std=gnu99 -Wall
LFLAGS=-lpcap 
FILES=main.cpp
PROJ=ipk-sniffer

all : $(PROJ)

$(PROJ) : $(FILES)
		g++ $(CFLAGS) -o $(PROJ) $(FILES) $(LFLAGS)

clean :
	rm -f *.o $(PROJ) 