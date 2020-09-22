#Makefile
all: pcap-test

pcap-test:
	g++ -o pcap-test main.cpp -lpcap

clean:
	rm -f pcap-test