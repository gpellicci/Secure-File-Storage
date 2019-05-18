all: client server
	
server: server.cpp
	g++ -o server server.cpp -lcrypto

client: client.cpp
	g++ -o client client.cpp -lcrypto

clean:
	clear
	rm server client

remake:
	make clean
	clear
	make