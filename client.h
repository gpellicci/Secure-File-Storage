int connectToServer(const char* ip, unsigned int port){
    struct sockaddr_in serverAddr;

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(client_sock == -1){
        printf("Could not create socket. Error\n");
        return 1;
    }

    //Connect to remote server
    if (connect(client_sock , (struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0)
    {
        printf("Connect failed. Error");
        return 1;
    }

    printf("Connection to the server %s:%d successful\n",  inet_ntoa(serverAddr.sin_addr), port);;
    return client_sock;
}