CC = g++
PTHREAD = -lpthread
SSL = -lssl -lcrypto

CLIENT = client.cpp
CLIENT_NAME = client
SERVER = server.cpp
SERVER_NAME = server

all: client server

client: $(CLIENT)
	$(CC) $(CLIENT) -o $(CLIENT_NAME) $(PTHREAD) $(SSL)
server: $(SERVER)
	$(CC) $(SERVER) -o $(SERVER_NAME) $(PTHREAD) $(SSL)

clean:
	rm $(CLIENT_NAME) $(SERVER_NAME)
