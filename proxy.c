#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <libxml2/libxml/HTMLparser.h>
#include <libxml2/libxml/uri.h>
#include <curl/curl.h>
#include <regex.h>

#define BUFFER_SIZE 1024
#define CACHE_DIR "./cache/"

int timeout; // Timeout value for cached pages

void calculate_md5(const char *url, char *hash) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_md5();  // Get MD5 digest algorithm
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, url, strlen(url));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // Convert the binary digest to hexadecimal representation
    for (int i = 0; i < md_len; i++) {
        sprintf(&hash[i*2], "%02x", md_value[i]);
    }
}
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

// Function to convert a URL into a GET request
char *url_to_get_request(const char *url, char *hostname, int *port, char *path) {
    // Check if the URL starts with "http://"
    printf("Convert url - %s to get request\n", url);
    if (strncmp(url, "http://", 7) != 0) {
        fprintf(stderr, "Error: URL must start with 'http://'\n");
        return NULL;
    }

    // Extract the hostname
    const char *hostname_start = url + 7; // Skip "http://"
    const char *hostname_end = strchr(hostname_start, '/');
    if (hostname_end == NULL) {
        fprintf(stderr, "Error: Invalid URL format (no path)\n");
        return NULL;
    }
    strncpy(hostname, hostname_start, hostname_end - hostname_start);
    hostname[hostname_end - hostname_start] = '\0';

    // Extract the path
    strcpy(path, hostname_end);

    // Set the default port
    *port = 80;

    // Create the GET request
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Connection: close\r\n"
                                        "\r\n",
             path, hostname);

    // Allocate memory for the request string and copy the request into it
    char *get_request = (char *)malloc(strlen(request) + 1);
    if (get_request == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    strcpy(get_request, request);

    return get_request;
}

// Function to check if a cached file exists based on MD5 hash
int is_cached(const char *hash) {
    char cache_path[BUFFER_SIZE];
    sprintf(cache_path, "%s%s", CACHE_DIR, hash);
    return access(cache_path, F_OK) != -1;
}

// Function to check if a URL is dynamic (contains parameters)
int is_dynamic(const char *url) {
    int dynamic = strchr(url, '?') != NULL;
    printf("Is Dynamic page - %d\n", dynamic);
    return dynamic;
}

// Function to check if a cached page has expired
int is_expired(const char *hash) {
    struct stat st;
    char cache_path[BUFFER_SIZE];
    sprintf(cache_path, "%s%s", CACHE_DIR, hash);
    if (stat(cache_path, &st) == -1) {
        perror("Error getting file status");
        return 1; // Treat as expired if file status cannot be retrieved
    }
    time_t current_time = time(NULL);
    char access_time_str[26]; // Buffer to hold the formatted time string
    strftime(access_time_str, 26, "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));

    printf("Last modified time: %s\n", access_time_str);

    int expired = (current_time - st.st_mtime) > timeout;
    if (expired) {
        if (unlink(cache_path) == -1) {
            perror("Error deleting cache file");
        }
        printf("Deleted expired cache file \n");
    }
    return expired;
}

// Function to fetch a page from the remote server and cache it
void fetch_and_cache(int client_socket, const char *url, const char *host, int port, char *buffer1, ssize_t bytes_received1, const char *hash, int dynamic) {
    // Implement fetching logic here
    // This function should establish a connection to the remote server,
    // fetch the requested page, save it to the cache directory, and close the connection.
    // Receive response from the server
    printf("Fetch and cache - %s\n", url);
    // Create a socket to connect to the server
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating server socket");
        // close(client_socket);
        pthread_exit(NULL);
    }

    // Resolve host IP address
    struct hostent *server_hostent = gethostbyname(host);
    if (server_hostent == NULL) {
        perror("Error resolving hostname");
        close(server_socket);
        // close(client_socket);
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
        // close(client_socket);
        pthread_exit(NULL);
    }

    // Forward request to server
    // char request[BUFFER_SIZE];
    if (send(server_socket, buffer1, bytes_received1, 0) < 0) {
        perror("Error sending request to server");
        close(server_socket);
        // close(client_socket);
        pthread_exit(NULL);
    }

    // Set up timeval struct for timeout
    struct timeval timeout;
    timeout.tv_sec = 5; // Timeout set to 5 seconds
    timeout.tv_usec = 0;

    // Set up file descriptor set for select
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_socket, &readfds); // Add server socket to the set

    char buffer[BUFFER_SIZE];
    int cache_fd = -1;
    int bytes_received;
    ssize_t bytes_sent;
    int select_result;

    while (1) {
        // Wait for data to be available on the server socket with timeout
        select_result = select(server_socket + 1, &readfds, NULL, NULL, &timeout);
        if (select_result == -1) {
            perror("Error in select");
            break;
        } else if (select_result == 0) {
            // Timeout occurred
            printf("Timeout occurred\n");
            break;
        }

        // Data is available to read from the server socket
        bytes_received = recv(server_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("Error receiving data from server");
            break;
        } else if (bytes_received == 0) {
            // Connection closed by server
            printf("Connection closed by server\n");
            break;
        }

        if (!dynamic) {
            // printf("Cache the page\n");
            if (cache_fd == -1) {
                char cache_path[BUFFER_SIZE];
                sprintf(cache_path, "%s%s", CACHE_DIR, hash);
                cache_fd = open(cache_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (cache_fd == -1) {
                    perror("Error opening cache file for writing");
                    close(server_socket);
                    return;
                }
            }
            // Write received data to cache file
            if (write(cache_fd, buffer, bytes_received) < 0) {
                perror("Error writing to cache file");
                close(cache_fd);
                close(server_socket);
                return;
            }
            // printf("Done writing to cache\n");
        }
        if (client_socket != 0) {
            bytes_sent = send(client_socket, buffer, bytes_received, 0);
            if (bytes_sent < 0) {
                perror("Error sending response to client");
                break;
            }
        }
    }
    printf("Done sending response to client\n");
    // Close cache file and server socket
    if (cache_fd != -1) {
        close(cache_fd);
    }
    close(server_socket);
    if (client_socket != 0)
        close(client_socket);
    // pthread_exit(NULL);
}

// Global variables for libcurl
CURLM *multi_handle;

// Function to extract the base URL from a given URL
char *get_base_url(const char *url) {
    char *base_url = strdup(url); // Duplicate the input URL to avoid modifying the original string
    char *protocol_end = strstr(base_url, "://"); // Find the end of the protocol part
    if (protocol_end != NULL) {
        char *domain_start = protocol_end + 3; // Move to the character after "://"
        char *slash_after_domain = strchr(domain_start, '/'); // Find the first "/" after the domain part
        if (slash_after_domain != NULL) {
            *slash_after_domain = '\0'; // Replace the first "/" after the domain with the null terminator to truncate the string
        }
    }
    
    printf("Base url -  %s\n", base_url);
    return base_url;
}

// Function to check if a URL is valid and convert relative URLs to absolute ones
int process_url(const char *base_url, char *url) {
    // Check if the URL is a valid HTTP URL or not '#'
    if (strncmp(url, "http://", 7) == 0 ) {
        printf("Valid URL: %s\n", url);
        return 1;
    } else if (strcmp(url, "#") == 0 || strncmp(url, "https://", 8) == 0) {
        printf("Invalid URL: %s\n", url);
        return 0;
    } else {
        if (base_url == NULL)
            return 0;
        // Convert relative URL to absolute URL
        char absolute_url[1024];
        strcpy(absolute_url, base_url);

        // If base_url doesn't end with '/', append it
        if (absolute_url[strlen(absolute_url) - 1] != '/') {
            strcat(absolute_url, "/");
        }

        strcat(absolute_url, url);

        printf("Converted URL: %s\n", absolute_url);
        strcpy(url, absolute_url);
        return 1;
    }
}

// Function to validate a URL using regular expressions
int validate_url(const char *url) {
    regex_t regex;
    int reti;

    // // Regular expression pattern for validating HTTP URLs
    char *pattern = "^http://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}(/\\S*)?$";

    // Compile the regular expression
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Error: Failed to compile regex\n");
        return 0;
    }

    // Execute the regular expression
    reti = regexec(&regex, url, 0, NULL, 0);
    regfree(&regex);

    // Check if the URL matches the pattern
    if (!reti) {
        // // Check if the URL points to a file type
        // const char *file_extensions[] = {".pdf", ".doc", ".docx", ".txt", ".png", ".gif", ".jpg", ".ico", ".css", ".js"}; // Add more file extensions as needed
        // int num_extensions = sizeof(file_extensions) / sizeof(file_extensions[0]);

        // for (int i = 0; i < num_extensions; i++) {
        //     if (strstr(url, file_extensions[i])) {
        //         return 0; // URL points to a file type
        //     }
        // }

        // Construct the url 

        return 1;
    } else if (reti == REG_NOMATCH) {
        return 0; // Invalid URL
    } else {
        fprintf(stderr, "Error: Failed to execute regex\n");
        return 0;
    }
}

// Recursive function to traverse the HTML document tree and extract links
void traverse_and_extract_links(xmlNodePtr node, char **extracted_links, int *num_links, const char *base_url) {
    for (xmlNodePtr curNode = node; curNode; curNode = curNode->next) {
        if (curNode->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(curNode->name, (const xmlChar *)"a") == 0) {
                xmlChar *href = xmlGetProp(curNode, (const xmlChar *)"href");
                if (href != NULL) {
                    // Validate the URL before extracting
                    printf("href - %s\n", href);
                    if (process_url(base_url, (char *)href)) {
                        extracted_links[*num_links] = (char *)malloc((strlen((const char *)href) + 1) * sizeof(char));
                        if (extracted_links[*num_links] != NULL) {
                            strcpy(extracted_links[*num_links], (const char *)href);
                            (*num_links)++;
                        }
                    }
                    xmlFree(href);
                }
            }
            traverse_and_extract_links(curNode->children, extracted_links, num_links, base_url);
        }
    }
}

// Function to parse a page and extract links
char **parse_page(const char *url, const char *page_content, int *num_links) {
    htmlDocPtr doc;
    doc = htmlReadMemory(page_content, strlen(page_content), url, NULL, HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);

    if (doc == NULL) {
        fprintf(stderr, "Error: Failed to parse document\n");
        return NULL;
    }

    xmlNodePtr curNode;
    curNode = xmlDocGetRootElement(doc);

    if (curNode == NULL) {
        fprintf(stderr, "Error: Empty document\n");
        xmlFreeDoc(doc);
        return NULL;
    }

    // Dynamically allocate memory for the array of extracted links
    char **extracted_links = (char **)malloc(BUFFER_SIZE * sizeof(char *));
    if (extracted_links == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        xmlFreeDoc(doc);
        return NULL;
    }

    // Initialize num_links to 0
    *num_links = 0;

    // Traverse the HTML document tree to extract links
    traverse_and_extract_links(xmlDocGetRootElement(doc), extracted_links, num_links, get_base_url(url));

    xmlFreeDoc(doc);

    return extracted_links;
}


// Callback function for libcurl to handle fetched data
size_t my_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    // Assuming that userp points to a buffer
    // You may need to adjust this logic based on your caching mechanism
    size_t real_size = size * nmemb;
    memcpy(userp, contents, real_size);
    return real_size;
}

// Function to cache prefetch link content
void cache_prefetch_link(const char *prefetch_content, const char *prefetch_hash) {
    // Implement your logic to cache the prefetch link content here
    // You may need to modify this logic based on your caching mechanism
    char cache_path[BUFFER_SIZE];
    sprintf(cache_path, "%s%s", CACHE_DIR, prefetch_hash);

    FILE *cache_file = fopen(cache_path, "w");
    if (cache_file == NULL) {
        perror("Error opening cache file for writing");
        return;
    }

    // Write the prefetch content to the cache file
    if (fwrite(prefetch_content, strlen(prefetch_content), 1, cache_file) != 1) {
        perror("Error writing to cache file");
    }

    fclose(cache_file);
}

void *prefetch_links(void *arg) {
    printf("Prefetch Links\n");
    char *url = (char *)arg;
    char cache_path[BUFFER_SIZE];

    // Initialize libcurl multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        fprintf(stderr, "Error initializing libcurl multi handle\n");
        pthread_exit(NULL);
    }

    CURL *curl_handle;
    curl_handle = curl_easy_init();
    if (!curl_handle) {
        fprintf(stderr, "Error initializing libcurl easy handle\n");
        pthread_exit(NULL);
    }

    // Set libcurl options
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, my_curl_write_callback);

    // Fetch the page content from the remote server
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    char page_content[BUFFER_SIZE];
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, page_content);
    CURLcode res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error fetching page content: %s\n", curl_easy_strerror(res));
        pthread_exit(NULL);
    }

    // Parse the page to extract links
    int num_links;
    char **extracted_links = parse_page(url, page_content, &num_links);
    // Print each extracted link
    for (int i = 0; i < num_links; ++i) {
        printf("Extracted link - %s\n", extracted_links[i]);
    }

    if (extracted_links == NULL) {
        fprintf(stderr, "Error extracting links from page\n");
        pthread_exit(NULL);
    }

    // Fetch and cache the extracted links
    for (int i = 0; i < num_links; ++i) {
        // Construct the URL for the prefetch link
        char prefetch_url[BUFFER_SIZE];
        strcpy(prefetch_url, extracted_links[i]);
        printf("Prefetch url - %s\n", prefetch_url);

        // Generate hash for prefetch link URL
        printf("Calculate hash\n");
        char prefetch_hash[MD5_DIGEST_LENGTH * 2 + 1];
        calculate_md5(prefetch_url, prefetch_hash);
        printf("Prefetch hash file - %s\n", prefetch_hash);

        char host[BUFFER_SIZE], path[BUFFER_SIZE], url[BUFFER_SIZE];
        int port;
        // Convert the URL into a GET request
        char *get_request = url_to_get_request(prefetch_url, host, &port, path);
        printf("Url - %s, host - %s, port - %d, path - %s\n", prefetch_url, host, port, path);
        if (get_request == NULL) {
            fprintf(stderr, "Error: Failed to convert URL to GET request\n");
            pthread_exit(NULL);
        }

        fetch_and_cache(0, prefetch_url, host, port, get_request, strlen(get_request), prefetch_hash, is_dynamic(prefetch_url));
    }

    // Clean up libcurl handles
    curl_easy_cleanup(curl_handle);
    curl_multi_cleanup(multi_handle);

    // Free memory allocated for extracted links
    for (int i = 0; i < num_links; ++i) {
        free(extracted_links[i]);
    }
    free(extracted_links);

    pthread_exit(NULL);
}

// Function to serve a cached page to the client
void serve_cached_page(int client_socket, const char *hash) {
    printf("Serve cached page\n");
    char cache_path[BUFFER_SIZE];
    sprintf(cache_path, "%s%s", CACHE_DIR, hash);
    FILE *cache_file = fopen(cache_path, "r");
    if (cache_file == NULL) {
        perror("Error opening cache file");
        close(client_socket);
        pthread_exit(NULL);
    }

    // Read and send the cached page to the client
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, cache_file)) > 0) {
        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            perror("Error sending cached page to client");
            break;
        }
    }
    printf("Done reading the cache file and sent to client\n");

    fclose(cache_file);
    close(client_socket);
    // pthread_exit(NULL);
}

char blocklist[BUFFER_SIZE][BUFFER_SIZE];
int blocklist_size = 0;

void load_blocklist() {
    FILE *file = fopen("blocklist.txt", "r");
    if (file == NULL) {
        perror("Error opening blocklist file");
        exit(1);
    }

    char line[BUFFER_SIZE];
    while (fgets(line, BUFFER_SIZE, file) != NULL) {
        line[strcspn(line, "\n")] = '\0'; 
        strcpy(blocklist[blocklist_size], line);
        blocklist_size++;
    }

    fclose(file);
}

int is_blocked(const char *host) {
    for (int i = 0; i < blocklist_size; i++) {
        if (strcmp(host, blocklist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void send_forbidden(int client_socket) {
    const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
    send(client_socket, forbidden_response, strlen(forbidden_response), 0);
}

// Function to parse the request and extract host, port, path, and body
void parse_request(char *request, char *host, int *port, char *path, char *url) {
    // Implement your parsing logic here
    // Extract host, port, path, and body from the request
    // Extract method, URL, and HTTP version from the request
    char method[BUFFER_SIZE], http_version[BUFFER_SIZE];
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
    char host[BUFFER_SIZE], path[BUFFER_SIZE], url[BUFFER_SIZE];
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
    parse_request(buffer, host, &port, path, url);

    // Check if the requested host is in the blocklist
    if (is_blocked(host)) {
        printf("Host %s is blocked\n", host);
        send_forbidden(client_socket);
        close(client_socket);
        pthread_exit(NULL);
    }

    char hash[MD5_DIGEST_LENGTH * 2 + 1]; // MD5 hash is 16 bytes (128 bits), represented in hex
    calculate_md5(url, hash);
    printf("Hash of url - %s ===> %s\n", url, hash);

    int dynamic = is_dynamic(url);
    // Check if the requested page is in the cache
    if (is_cached(hash) && !dynamic && !is_expired(hash)) {
        printf("Cached copy of %s found\n", url);
        // Serve the cached page to the client
        serve_cached_page(client_socket, hash);
    } else {
        printf("Cached copy of %s not found or expired\n", url);
        // Fetch the page from the remote server and cache it
        fetch_and_cache(client_socket, url, host, port, buffer, bytes_received, hash, dynamic);
    }
    // Start a background thread to prefetch links
    pthread_t prefetch_tid;
    if (pthread_create(&prefetch_tid, NULL, prefetch_links, (void *)url) != 0) {
        perror("Error creating prefetch thread");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> %s <timeout> %s\n", argv[0], argv[1], argv[2]);
        exit(1);
    }
    timeout = atoi(argv[2]);

    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        return 1;
    }

    load_blocklist();

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