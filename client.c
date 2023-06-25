#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#define TIMEOUT 60
#define BUF_SIZE 510

// **********************************************************************
// forward declaration

int setup_tcp_connection(int port);
void init_fd_array();
int set_username();
int set_username_helper(int len);
int process_events();
void input(char *buffer);

// **********************************************************************
// global variables

int SOCKET;
struct pollfd FD_ARRAY[2];
char BUFFER[BUF_SIZE+2];

// **********************************************************************

int main()
{
    int event;

    SOCKET = setup_tcp_connection(3000);
    init_fd_array();

    int error = set_username();
    if (error) {
        close(SOCKET);
        return 1;
    }

    while(1)
    {
        event = poll(FD_ARRAY, 2, TIMEOUT * 1000);

        if (event == -1)
        {
            perror("error in poll function\n");
            close(SOCKET);
            return 1;
        }
        else if (event)
        {
            int stop = process_events();
            if (stop) break;
        }
    }

    close(SOCKET);
    return 0;
}

// **********************************************************************

int setup_tcp_connection(int port)
{
    struct sockaddr_in address;
    int server_fd;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    address.sin_port = htons(port); 

    struct sockaddr *addr = (struct sockaddr*) &address;

    if (connect(server_fd, addr, sizeof(address)) < 0)
    {
        perror("error in connecting to server\n");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

// **********************************************************************

void init_fd_array()
{
    FD_ARRAY[0].fd = STDIN_FILENO;
	FD_ARRAY[0].events = POLLIN;

	FD_ARRAY[1].fd = SOCKET;
	FD_ARRAY[1].events = POLLIN;
}

// **********************************************************************

int set_username()
{
    int not_registered = 1;

    while (not_registered)
    {
        strcpy(BUFFER, "name: ");
        printf("enter username: ");
        input(BUFFER+6);
        int len = strlen(BUFFER);

        not_registered = set_username_helper(len);
        if (not_registered == -1)
            return 1;

        if (not_registered == 0)
            return 0;
    }
}

int set_username_helper(int len)
{
    int sent = send(SOCKET, BUFFER, len, 0);
    if (sent != len) {
        perror("couldn't send data to server!\n");
        return -1;
    }

    int recieved = recv(SOCKET, BUFFER, BUF_SIZE, 0);
    if (recieved == 0) {
        printf("connection lost!\n");
        return -1;
    }
    BUFFER[recieved] = '\0';

    if (!strncmp(BUFFER, "err: ", 5)) {
        printf("%s\n", BUFFER+5);
        return 1;
    }

    return 0;
}

// **********************************************************************

int process_events()
{
    if (FD_ARRAY[0].revents & POLLIN)
    {
        input(BUFFER);
        if (!strcmp(BUFFER, "exit"))
            return 1;

        send(SOCKET, BUFFER, strlen(BUFFER), 0);
    }

    else if (FD_ARRAY[1].revents & POLLIN)
    {
        int recieved = recv(SOCKET, BUFFER, BUF_SIZE, 0);
        if (recieved == 0) {
            printf("connection lost!\n");
            return 1;
        }

        if (BUFFER[recieved-1] != '\n')
            BUFFER[recieved++] = '\n';

        BUFFER[recieved] = '\0';
        printf("%s", BUFFER);
    }

    return 0;
}

// **********************************************************************
// manual input function

void input(char *buffer)
{
    char garbage;
    scanf("%[^\n]", buffer);
    scanf("%c", &garbage);
}