#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#define MAX_USERS 10
#define TIMEOUT 60
#define BUF_SIZE 511
#define MAX_NAME_LENGTH 31
#define MAX_GROUP_COUNT 5

#define MAX_FDS MAX_USERS+2

// **********************************************************************
// data structures

typedef struct _User User;
typedef struct _Group Group;

struct _User
{
    int socket_fd;
    char name[MAX_NAME_LENGTH+1];
    char ip_addr[16];
    int port;
};

struct _Group
{
    char name[MAX_NAME_LENGTH+1];
    int members[MAX_USERS];
};

// **********************************************************************
// forward declaration

void init_data_variables();
int setup_tcp_server(int port);
void init_fd_array();
void terminate_sockets();
int process_events();
void connection_handler();
int insert_fd_to_array(int newfd);
void data_on_socket(int indx);
void terminate_user(int user_indx, int entry);
void process_recieved_data(int user_indx, int data_len);

void set_username(int user_indx, char *name, int length);
void create_group(int user_indx, char *name, int length);
void join_group(int user_indx, char *name, int length);
int insert_user_to_members(int user_indx, int members[]);
void leave_group(int user_indx, char *name, int length);
void private_message(int user_indx, char *data, int length);
void public_message(int user_indx, char *data, int length);
void list_groups(int user_indx);
void list_users(int user_indx);

void input(char *buffer);
int find_empty_group_entry();
int find_group_by_name(char *name);
int find_user_by_name(char *name);
int find_user_in_members(int user_indx, int members[]);

// **********************************************************************
// global variables

int SERVER;

User USERS[MAX_USERS];
Group GROUPS[MAX_GROUP_COUNT];
struct pollfd FD_ARRAY[MAX_FDS];
char IN_BUFFER[BUF_SIZE+1];
char OUT_BUFFER[2*(BUF_SIZE+1)];

// **********************************************************************

int main (void)
{
	int event;
    init_data_variables();
    SERVER = setup_tcp_server(3000);
    init_fd_array();

    while(1)
    {
	    event = poll(FD_ARRAY, MAX_FDS, TIMEOUT * 1000);

        if (event == -1)
        {
            perror("error in poll function\n");
            close(SERVER);
            return 1;
        }
        else if (event)
        {
            int stop = process_events();
            if (stop) break;
        }
        else printf("%d seconds elapsed.\n", TIMEOUT);
    }

    terminate_sockets();
	return 0;
}

// **********************************************************************
// utilities

void init_data_variables()
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        USERS[i].socket_fd = -1;
        USERS[i].name[0] = '\0';
    }

    for (int i = 0; i < MAX_GROUP_COUNT; i++)
    {
        GROUPS[i].name[0] = '\0';
        for (int j = 0; j < MAX_USERS; j++)
            GROUPS[i].members[j] = -1;
    }
}

// **********************************************************************
// sever setup

int setup_tcp_server(int port)
{
    struct sockaddr_in address;
    int yes = 1;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd,
        SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    address.sin_port = htons(port);

    struct sockaddr *addr = (struct sockaddr*) &address;
    bind(server_fd, addr, sizeof(address));
    listen(server_fd, 4);

    return server_fd;
}

// **********************************************************************
// utilities

void init_fd_array()
{
    FD_ARRAY[0].fd = STDIN_FILENO;
	FD_ARRAY[0].events = POLLIN;

	FD_ARRAY[1].fd = SERVER;
	FD_ARRAY[1].events = POLLIN;

    for (int i = 2; i < MAX_FDS; i++)
        FD_ARRAY[i].fd = -1;
}

void terminate_sockets()
{
    for (int i = 1; i < MAX_FDS; i++)
        if(FD_ARRAY[i].fd != -1)
            close(FD_ARRAY[i].fd);
}

// **********************************************************************
// event processor function

int process_events()
{
    if (FD_ARRAY[0].revents & POLLIN)
    {
        input(IN_BUFFER);
        if (!strcmp(IN_BUFFER, "shutdown"))
            return 1;

        else printf("unknown command!\n");
    }

    if (FD_ARRAY[1].revents & POLLIN)
        connection_handler();

    for (int i = 2; i < MAX_FDS; i++)
        if (FD_ARRAY[i].revents & POLLIN)
            data_on_socket(i);

    return 0;
}

// **********************************************************************
// handle new connections

void connection_handler()
{
    struct sockaddr client_address;
    socklen_t len = sizeof(client_address);

    int client_fd = accept(SERVER, &client_address, &len);
    int res = insert_fd_to_array(client_fd);
    if (res == -1)
    {
        send(client_fd, "reject\n", 7, 0);
        close(client_fd);
        printf("new connection attemp rejected!\n");
    }
    else printf("new connection added as entry %d\n", res);

    struct sockaddr_in *addr_in;
    addr_in = (struct sockaddr_in*) &client_address;
    char *ipv4 = inet_ntoa(addr_in->sin_addr);
    int port = addr_in->sin_port;

    int user_indx = res - 2;
    USERS[user_indx].socket_fd = client_fd;
    strncpy(USERS[user_indx].ip_addr, ipv4, 16);
    USERS[user_indx].port = port;

    printf("client address: (%s, %d)\n", ipv4, port);
}

int insert_fd_to_array(int newfd)
{
    for (int i = 2; i < MAX_FDS; i++)
    {
        if (FD_ARRAY[i].fd < 0)
        {
            FD_ARRAY[i].fd = newfd;
            FD_ARRAY[i].events = POLLIN;
            return i;
        }
    }

    return -1;
}

// **********************************************************************
// handle incoming data on a socket

void data_on_socket(int indx)
{
    int socket_fd = FD_ARRAY[indx].fd;
    int bytes_received = recv(socket_fd, IN_BUFFER, BUF_SIZE, 0);
    int user_indx = indx - 2;

    if (bytes_received > 0)
    {
        IN_BUFFER[bytes_received] = '\0';
        process_recieved_data(user_indx, bytes_received);
    }
    if (bytes_received == 0) {
        close(socket_fd);
        FD_ARRAY[indx].fd = -1;
        terminate_user(user_indx, indx);
    }
}

void terminate_user(int user_indx, int entry)
{
    int indx = -1;

    for (int i = 0; i < MAX_GROUP_COUNT; i++)
    {
        indx = find_user_in_members(user_indx, GROUPS[i].members);
        if (indx != -1)
            GROUPS[i].members[indx] = -1;
    }

    if (USERS[user_indx].name[0])
        printf("user (%s) terminated!\n", USERS[user_indx].name);
    
    else printf("connection at entry %d terminated!\n", entry);

    USERS[user_indx].socket_fd = -1;
    USERS[user_indx].name[0] = '\0';
}

// **********************************************************************

void process_recieved_data(int user_indx, int data_len)
{
    int user_fd = USERS[user_indx].socket_fd;

    if (!USERS[user_indx].name[0])
    {
        if(!strncmp(IN_BUFFER, "name: ", 6))
            set_username(user_indx, IN_BUFFER+6, data_len-6);
        
        else send(user_fd, "err: first set a username!", 24, 0);
    }

    else if (!strncmp(IN_BUFFER, "create ", 7))
        create_group(user_indx, IN_BUFFER+7, data_len-7);

    else if (!strncmp(IN_BUFFER, "join ", 5))
        join_group(user_indx, IN_BUFFER+5, data_len-5);

    else if (!strncmp(IN_BUFFER, "leave ", 6))
        leave_group(user_indx, IN_BUFFER+6, data_len-6);

    else if (!strncmp(IN_BUFFER, "private ", 8))
        private_message(user_indx, IN_BUFFER+8, data_len-8);

    else if (!strncmp(IN_BUFFER, "public ", 7))
        public_message(user_indx, IN_BUFFER+7, data_len-7);

    else if (!strncmp(IN_BUFFER, "groups", 6))
        list_groups(user_indx);

    else if (!strncmp(IN_BUFFER, "users", 5))
        list_users(user_indx);

    else send(user_fd, "unknown command!", 16, 0);
}

// **********************************************************************

void set_username(int user_indx, char *name, int length)
{
    int user_fd = USERS[user_indx].socket_fd;

    if (length < 1 || length > MAX_NAME_LENGTH) {
        send(user_fd, "err: username has invalid length!", 33, 0);
        return;
    }

    for (int i = 0; i < MAX_USERS; i++)
    {
        if (!strcmp(USERS[i].name, name)) {
            send(user_fd, "err: this username is taken!", 28, 0);
            return;
        }
    }

    strcpy(USERS[user_indx].name, name);
    printf("username registered (%s)\n", name);
    send(user_fd, "ok", 2, 0);
}

// **********************************************************************

void create_group(int user_indx, char *name, int length)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = 0;

    if (length < 1 || length > MAX_NAME_LENGTH) {
        send(user_fd, "group name has invalid length!", 30, 0);
        return;
    }

    int group_indx = find_empty_group_entry();
    if (group_indx == -1) {
        send(user_fd,
            "server doesn't have enough storage "\
            "to create a new group!", 57, 0);

        return;
    }

    if (find_group_by_name(name) != -1) {
        buf_len = sprintf(
            OUT_BUFFER, "group (%s) already exists!", name);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    strcpy(GROUPS[group_indx].name, name);
    buf_len = sprintf(OUT_BUFFER,
        "group (%s) has been created successfully!", name);
    
    send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************

void join_group(int user_indx, char *name, int length)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = 0;

    if (length < 1 || length > MAX_NAME_LENGTH) {
        send(user_fd, "group name has invalid length!", 30, 0);
        return;
    }

    int group_indx = find_group_by_name(name);
    if (group_indx == -1) {
        buf_len = sprintf(
            OUT_BUFFER, "group (%s) doesn't exist!", name);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    int indx = find_user_in_members(
        user_indx, GROUPS[group_indx].members);

    if (indx != -1) {
        buf_len = sprintf(
            OUT_BUFFER, "you've already joined (%s)!", name);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    insert_user_to_members(user_indx, GROUPS[group_indx].members);
    buf_len = sprintf(
        OUT_BUFFER, "you joined group (%s) successfully!", name);

    send(user_fd, OUT_BUFFER, buf_len, 0);
}

int insert_user_to_members(int user_indx, int members[])
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (members[i] == -1) {
            members[i] = user_indx;
            return i;
        }
    }

    return -1;
}

// **********************************************************************

void leave_group(int user_indx, char *name, int length)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = 0;

    if (length < 1 || length > MAX_NAME_LENGTH) {
        send(user_fd, "group name has invalid length!", 30, 0);
        return;
    }

    int group_indx = find_group_by_name(name);
    if (group_indx == -1) {
        buf_len = sprintf(
            OUT_BUFFER, "group (%s) doesn't exist!", name);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    int member_indx = find_user_in_members(
        user_indx, GROUPS[group_indx].members);
    
    if (member_indx == -1) {
        send(user_fd, "you're not a member of this group!", 34, 0);
        return;
    }

    GROUPS[group_indx].members[member_indx] = -1;
    buf_len = sprintf(
        OUT_BUFFER, "you left group (%s) successfully!", name);

    send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************

void private_message(int user_indx, char *data, int length)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = 0;

    char *message = strstr(data, " ");
    if (message == NULL || message == data) {
        send(user_fd, "command has invalid fields!", 27, 0);
        return;
    }
    int name_len = message-data;
    if (name_len < 1 || name_len > MAX_NAME_LENGTH) {
        send(user_fd, "username has invalid length!", 28, 0);
        return;
    }
    if (length-name_len-1 < 1) {
        send(user_fd, "message field is empty!", 23, 0);
        return;
    }
    *message++ = '\0';

    int reciever_indx = find_user_by_name(data);
    if (reciever_indx == -1) {
        buf_len = sprintf(
            OUT_BUFFER, "user (%s) doesn't exist!", data);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    buf_len = sprintf(OUT_BUFFER, "private message from (%s): %s\n",
        USERS[user_indx].name, message);

    send(USERS[reciever_indx].socket_fd, OUT_BUFFER, buf_len, 0);
    buf_len = sprintf(OUT_BUFFER, "message sent to (%s)!", data);
    send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************

void public_message(int user_indx, char *data, int length)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = 0;

    char *message = strstr(data, " ");
    if (message == NULL || message == data) {
        send(user_fd, "command has invalid fields!", 27, 0);
        return;
    }
    int name_len = message-data;
    if (name_len < 1 || name_len > MAX_NAME_LENGTH) {
        send(user_fd, "group name has invalid length!", 30, 0);
        return;
    }
    if (length-name_len-1 < 1) {
        send(user_fd, "message field is empty!", 23, 0);
        return;
    }
    *message++ = '\0';

    int group_indx = find_group_by_name(data);
    if (group_indx == -1) {
        buf_len = sprintf(
            OUT_BUFFER, "group (%s) doesn't exist!", data);

        send(user_fd, OUT_BUFFER, buf_len, 0);
        return;
    }

    int *members = GROUPS[group_indx].members;
    buf_len = sprintf(OUT_BUFFER, "(%s) in group (%s): %s", 
        USERS[user_indx].name, data, message);

    for (int i = 0; i < MAX_USERS; i++)
        if (members[i] != -1 && members[i] != user_indx)
            send(USERS[members[i]].socket_fd,
                OUT_BUFFER, buf_len, 0);

    buf_len = sprintf(
        OUT_BUFFER, "message sent to group (%s)!", data);

    send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************

void list_groups(int user_indx)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = sprintf(OUT_BUFFER, "available groups:\n");
    int count = 0;

    for (int i = 0; i < MAX_GROUP_COUNT; i++)
    {
        if (GROUPS[i].name[0])
            buf_len += sprintf(OUT_BUFFER+buf_len,
                "%d. %s\n", ++count, GROUPS[i].name);
    }

    if (count == 0)
        send(user_fd, "no groups yet!", 14, 0);
    
    else send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************

void list_users(int user_indx)
{
    int user_fd = USERS[user_indx].socket_fd;
    int buf_len = sprintf(OUT_BUFFER, "online users:\n");
    int count = 0;

    for (int i = 0; i < MAX_USERS; i++)
    {
        if (USERS[i].name[0])
            buf_len += sprintf(OUT_BUFFER+buf_len,
                "%d. %s\n", ++count, USERS[i].name);
    }

    if (count == 0)
        send(user_fd, "no users yet!", 13, 0);
    
    else send(user_fd, OUT_BUFFER, buf_len, 0);
}

// **********************************************************************
// utilities

void input(char *buffer)
{
    char garbage;
    scanf("%[^\n]", buffer);
    scanf("%c", &garbage);
}

int find_empty_group_entry()
{
    for (int i = 0; i < MAX_GROUP_COUNT; i++)
        if (!GROUPS[i].name[0])
            return i;

    return -1;
}

int find_group_by_name(char *name)
{
    for (int i = 0; i < MAX_GROUP_COUNT; i++)
        if (!strcmp(GROUPS[i].name, name))
            return i;

    return -1;
}

int find_user_by_name(char *name)
{
    for (int i = 0; i < MAX_USERS; i++)
        if (!strcmp(USERS[i].name, name))
            return i;
    
    return -1;
}

int find_user_in_members(int user_indx, int members[])
{
    for (int i = 0; i < MAX_USERS; i++)
        if (members[i] == user_indx)
            return i;

    return -1;
}