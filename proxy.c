#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>

#define BUFFER_SIZE 1024
// #define MAX_METHOD_LENGTH 10
// #define MAX_URL_LENGTH 1024
// #define MAX_HOST_LENGTH 256
// #define MAX_PATH_LENGTH 1024

// typedef struct {
//     char method[MAX_METHOD_LENGTH];
//     char url[MAX_URL_LENGTH];
//     char host[MAX_HOST_LENGTH];
//     int port;
//     char path[MAX_PATH_LENGTH];
//     char body[MAX_URL_LENGTH]; // Assuming body can be as large as URL
// } ParsedRequest;

// // Function to parse the request and extract host, port, path, and body
// void parse_request(const char *request, ParsedRequest *parsed) {
//     // Initialize parsed structure
//     memset(parsed, 0, sizeof(ParsedRequest));

//     // Parse method (GET)
//     sscanf(request, "%s %s", parsed->method, parsed->url);

//     // Check if method is GET
//     if (strcmp(parsed->method, "GET") != 0) {
//         fprintf(stderr, "Unsupported HTTP method\n");
//         exit(1);
//     }

//     // Parse URL
//     if (sscanf(parsed->url, "http://%[^:/]:%d/%[^\n]", parsed->host, &parsed->port, parsed->path) == 3) {
//         // Host, port, and path are provided
//     } else if (sscanf(parsed->url, "http://%[^:/]/%[^\n]", parsed->host, parsed->path) == 2) {
//         // Host and path are provided, use default port 80
//         parsed->port = 80;
//     } else {
//         fprintf(stderr, "Invalid URL format\n");
//         exit(1);
//     }
// }
// Function to parse the request and extract host, port, path, and body
void parse_request(char *request, char *host, int *port, char *path, char *body) {
    // Implement your parsing logic here
    // Extract host, port, path, and body from the request
    // Extract method, URL, and HTTP version from the request
    char method[BUFFER_SIZE], url[BUFFER_SIZE], http_version[BUFFER_SIZE];
    sscanf(request, "%s %s %s", method, url, http_version);

    // Check if the method is valid (supporting only GET)
    if (strcmp(method, "GET") != 0) {
        fprintf(stderr, "Error: Unsupported HTTP method\n");
        exit(1);
    }

    // Parse the URL to extract host, port (if specified), and path
    // Assuming the URL format is "http://host:port/path"
    if (strncmp(url, "http://", 7) == 0) {
        char *host_start = url + 7;
        char *port_start = strchr(host_start, ':');
        char *path_start = strchr(host_start, '/');

        if (port_start != NULL) {
            *port_start = '\0'; // Null-terminate the host string
            sscanf(port_start + 1, "%d%s", port, path);
        } else {
            *port = 80; // Default HTTP port
            sscanf(host_start, "%[^/]%s", host, path);
        }

        if (path_start != NULL) {
            strcpy(path, path_start);
        } else {
            strcpy(path, "/");
        }
    } else {
        fprintf(stderr, "Error: Invalid URL format\n");
        exit(1);
    }

    // Ensure that the specified HTTP server exists (resolve hostname)
    struct hostent *server_hostent = gethostbyname(host);
    if (server_hostent == NULL) {
        fprintf(stderr, "Error: Could not resolve hostname\n");
        exit(1);
    }
    printf("host = %s\n",server_hostent->h_name);
}

// Function to handle requests from clients
void *handle_request(void *arg) {
    int client_socket = *((int *)arg);
    char buffer[BUFFER_SIZE];
    char host[BUFFER_SIZE], path[BUFFER_SIZE], body[BUFFER_SIZE];
    int port;

    // Receive request from client
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving request from client");
        close(client_socket);
        pthread_exit(NULL);
    }
    
    // Null-terminate the received data
    buffer[bytes_received] = '\0';

    // Parse the request
    printf("Buffer received from client - %s\n", buffer);
    parse_request(buffer, host, &port, path, body);

    // Create a socket to connect to the server
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating server socket");
        close(client_socket);
        pthread_exit(NULL);
    }

    // Resolve host IP address
    struct hostent *server_hostent = gethostbyname(host);
    if (server_hostent == NULL) {
        perror("Error resolving hostname");
        close(server_socket);
        close(client_socket);
        pthread_exit(NULL);
    }

    // Construct server address struct
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server_hostent->h_addr, server_hostent->h_length);
    server_addr.sin_port = htons(port);

    // Connect to the server
    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(server_socket);
        close(client_socket);
        pthread_exit(NULL);
    }

    // Forward request to server
    if (send(server_socket, buffer, bytes_received, 0) < 0) {
        perror("Error sending request to server");
        close(server_socket);
        close(client_socket);
        pthread_exit(NULL);
    }

    // Receive response from server and relay to client
    ssize_t bytes_sent, total_sent = 0;
    while ((bytes_received = recv(server_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        bytes_sent = send(client_socket, buffer, bytes_received, 0);
        if (bytes_sent < 0) {
            perror("Error sending response to client");
            break;
        }
        total_sent += bytes_sent;
    }

    if (bytes_received < 0) {
        perror("Error receiving response from server");
    }

    // Close sockets
    close(server_socket);
    close(client_socket);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        return 1;
    }

    // Bind socket to port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        return 1;
    }

    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        perror("Error listening");
        return 1;
    }

    printf("Proxy server running on port %d\n", port);

    // Accept incoming connections and handle them in separate threads
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            perror("Error accepting connection");
            continue;
        }

        // Create a new thread to handle the client request
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_request, &client_socket) != 0) {
            perror("Error creating thread");
            close(client_socket);
        }
    }

    // Close server socket
    close(server_socket);

    return 0;
}
