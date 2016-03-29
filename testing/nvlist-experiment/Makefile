all: client server

client: client.c
	cc -g -o client client.c -lnv

server: server.c
	cc -g -o server server.c -lnv

clean:
	rm -f client server