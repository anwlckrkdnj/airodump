LDLIBS=-lpcap

all: airodump

airodump: main.o airoutil.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
