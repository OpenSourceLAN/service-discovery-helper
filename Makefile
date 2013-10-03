
all: 
	gcc -Wall -g -std=gnu99 -o sdh-proxy sdh-proxy.c timer.c -lpthread -lpcap
