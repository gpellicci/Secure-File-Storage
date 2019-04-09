all: client server
	
server: server.cpp
	g++ server.cpp server.h -o server -lcrypto

client: client.cpp
	g++ client.cpp client.h -o client -lcrypto

clean:
	rm server client