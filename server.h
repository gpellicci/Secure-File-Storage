#define MAX_CONNECTION 30

bool prepareSocket(struct sockaddr_in& serverAddr, int& server_sock, const char* serverIp, unsigned int serverPort){

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons( serverPort );

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock == -1){
        perror("Could not create socket. Error");
        return false;
    }
    //Bind
    if( bind(server_sock,(struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0){
        //print the error message
        perror("Bind failed. Error");
        return false;
    }

    int listen_ret = listen(server_sock, MAX_CONNECTION); 
    if(listen_ret == -1){
        perror("Could not listen. Error");
        return false;
    }   
    printf("All good, listening...\n");
	return true;
}