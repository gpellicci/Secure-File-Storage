all: client server
	
server: server.cpp
	g++ server.cpp server.h -o server -lcrypto -Wall

client: client.cpp
	g++ client.cpp client.h -o client -lcrypto -Wall

clean:
	rm server client