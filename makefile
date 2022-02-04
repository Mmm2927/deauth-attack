LDLIBS += -lpcap

all: deauth-attack

pcap-test: deauth-attack.cpp

clean:
	rm -f deauth-attack *.o
