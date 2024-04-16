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
#include <stdbool.h>

#define BUFFER_SIZE 1024
#define CACHE_DIR "./cache/"

int timeout; 
static int count = 0;
static int count1 = 0;

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

// Function to convert a URL into a GET request
char *url_to_get_request(const char *url, char *hostname, int *port, char *path) {
    // Check if the URL starts with "http://"
    printf("Convert url - %s to get request\n", url);
    if (strncmp(url, "http://", 7) != 0) {
        fprintf(stderr, "Error: URL must start with 'http://'\n");
        return NULL;
    }

    // Extract the hostname
    const char *hostname_start = url + 7; 
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
    char *get_request = strdup(request);
    count1++;
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
    char access_time_str[26]; 
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
            // Check if cache directory exists, create if not
            struct stat st;
            if (stat(CACHE_DIR, &st) == -1) {
                if (mkdir(CACHE_DIR, 0755) == -1) {
                    perror("Error creating cache directory");
                    close(server_socket);
                    return;
                }
            }
            
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
    char *base_url = strdup(url); 
    if (base_url == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    char *protocol_end = strstr(base_url, "://"); 
    if (protocol_end != NULL) {
        char *domain_start = protocol_end + 3; 
        char *slash_after_domain = strchr(domain_start, '/'); 
        if (slash_after_domain != NULL) {
            *slash_after_domain = '\0'; 
        }
    } else {
        fprintf(stderr, "Invalid URL\n");
        free(base_url); 
        return NULL;
    }
    
    printf("Base url -  %s\n", base_url);
    return base_url;
}

char* filterAndAppendURL(const char* baseUrl, const char* url) {
    // Check if the URL starts with "https" or "#"
    printf("filterAndAppendURL - %s, %s\n", baseUrl, url);
    if (strncmp(url, "https://", 8) == 0 || url[0] == '#') {
        // Return NULL for filtered URLs
        return NULL;
    } 
    
    if (strncmp(url, "http", 4) == 0) {
        // If the URL starts with "http", return it as is
        size_t urlLen = strlen(url);
        char* result = (char*)malloc(urlLen + 1); // +1 for '\0'
        if (result == NULL) {
            // Allocation failed
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        strcpy(result, url);
        return result;
    } 
    
    // Append url to the base url
    size_t baseLen = strlen(baseUrl);
    size_t urlLen = strlen(url);

    // Allocate memory for the resulting URL
    char* result = (char*)malloc(baseLen + urlLen + 2); // 1 for '/' and 1 for '\0'
    if (result == NULL) {
        // Allocation failed
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Copy the base URL to the resulting URL
    strcpy(result, baseUrl);
    
    // Determine if the base URL ends with '/'
    int baseHasSlash = (baseUrl[baseLen - 1] == '/');

    // Determine if the URL starts with '/'
    int urlHasSlash = (url[0] == '/');

    if (baseHasSlash && urlHasSlash) {
        // Skip one slash from the URL
        strcat(result, url + 1);
    } else if (!baseHasSlash && !urlHasSlash) {
        // Add a slash between the base URL and the URL
        strcat(result, "/");
        strcat(result, url);
    } else {
        // No need to adjust, just concatenate
        strcat(result, url);
    }

    return result;
}

// Function to check if content resembles HTML based on tags
bool resemblesHTML(const char *html_content) {
    // Check if HTML-specific tags are present in the content
    return (strstr(html_content, "<html>") != NULL || strstr(html_content, "<head>") != NULL ||
            strstr(html_content, "<body>") != NULL || strstr(html_content, "<a") != NULL);
}

// Function to extract links from HTML content
char** extract_links(const char *html_content, int *num_links, const char *parent_url) {
    // Check if the content is HTML
    if (!resemblesHTML(html_content)) {
        fprintf(stderr, "Input is not HTML content\n");
        *num_links = 0;
        return NULL;
    }

    const char *start_tag = "<a";
    const char *end_tag = "</a>";

    // Allocate memory for an array of strings to store links
    char **links = malloc(sizeof(char *) * 100); // Assuming a maximum of 100 links
    if (links == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        *num_links = 0;
        return NULL;
    }

    int count = 0;
    const char *cursor = html_content;

    char *base_url = get_base_url(parent_url);
    if (base_url != NULL) {
        printf("Base URL: %s\n", base_url);
    }
    char *result_url;
    while ((cursor = strstr(cursor, start_tag)) != NULL) {
        const char *end = strstr(cursor, end_tag);
        if (end != NULL) {
            // Extract the content within <a> tags
            const char *href_start = strstr(cursor, "href=\"");
            if (href_start != NULL && href_start < end) {
                href_start += 6; // Move cursor to start of URL after href="

                const char *href_end = strchr(href_start, '"');
                if (href_end != NULL && href_end < end) {
                    // Extract the URL
                    int url_length = href_end - href_start;
                    char *url = malloc(sizeof(char) * (url_length + 1));
                    if (url != NULL) {
                        strncpy(url, href_start, url_length);
                        url[url_length] = '\0';
                        // Store the URL in the array
                        result_url = filterAndAppendURL(base_url, url);
                        if (result_url != NULL) {
                            links[count] = result_url;
                            count++;
                        } else {
                            // Free the memory allocated for invalid URLs
                            free(url);
                        }
                    } else {
                        fprintf(stderr, "Memory allocation failed\n");
                        // Free previously allocated memory
                        for (int i = 0; i < count; i++) {
                            free(links[i]);
                        }
                        free(links);
                        free(base_url);
                        free(result_url);
                        *num_links = 0;
                        return NULL;
                    }
                }
            }

            // Move cursor past the </a> tag
            cursor = end + strlen(end_tag);
        } else {
            // If no </a> tag found, exit loop
            break;
        }
    }

    *num_links = count;
    free(base_url);
    free(result_url);
    return links;
}

// Struct to hold fetched data
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback function to write fetched data into a buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *data) {
    size_t total_size = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)data;

    // Reallocate memory to fit new data
    mem->memory = realloc(mem->memory, mem->size + total_size + 1);
    if (mem->memory == NULL) {
        printf("Failed to allocate memory\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), ptr, total_size);
    mem->size += total_size;
    mem->memory[mem->size] = '\0'; 
    return total_size;
}

void *prefetch_links(void *arg) {
    printf("Prefetch Links\n");
    char *url = (char *)arg;

    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    struct MemoryStruct fetched_data;
    int num_links;
    char **links;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        fetched_data.memory = malloc(1);
        fetched_data.size = 0;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fetched_data);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        else {
            // Extract links from HTML content
            links = extract_links(fetched_data.memory, &num_links, url);
            if (links != NULL) {
                for (int i = 0; i < num_links; i++) {
                    printf("Extracted Link %d: %s\n", i + 1, links[i]);
                }
                for (int i = 0; i < num_links; ++i) {
                    char prefetch_url[BUFFER_SIZE];
                    strcpy(prefetch_url, links[i]);
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

                    if (!is_cached(prefetch_hash) || is_expired(prefetch_hash)) {
                        fetch_and_cache(0, prefetch_url, host, port, get_request, strlen(get_request), prefetch_hash, is_dynamic(prefetch_url));
                    } else {
                        printf("Already in cache - %s\n", prefetch_url);
                    }
                    printf("Get request - %s\n", get_request);
                    free(get_request);
                    count1--;
                    get_request = NULL;
                }
                printf("Gehna\n");
            } else {
                fprintf(stderr, "Failed to extract links\n");
            }
        }

        if (links != NULL) {
            for (int i = 0; i < num_links; i++) {
                free(links[i]);
            }
            free(links);
        }
        free(fetched_data.memory);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
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

void send_error_response(int client_socket, int error_code, const char *error_message) {
    char response[BUFFER_SIZE];
    snprintf(response, BUFFER_SIZE, "HTTP/1.1 %d %s\r\nContent-Length: %lu\r\n\r\n%s",
             error_code, error_message, strlen(error_message), error_message);
    send(client_socket, response, strlen(response), 0);
}

// Function to parse the request and extract host, port, path, and body
int parse_request(int client_socket, char *request, char *host, int *port, char *path, char *url) {
    char method[BUFFER_SIZE], http_version[BUFFER_SIZE];
    sscanf(request, "%s %s %s", method, url, http_version);

    if (strcmp(method, "CONNECT") == 0) {
        printf("Ignoring this request as not supported\n\n");
        send_error_response(client_socket, 400, "Bad Request");
        return 0;
    }

    // Check if the method is valid (supporting only GET)
    if (strcmp(method, "GET") != 0) {
        fprintf(stderr, "Error: Unsupported HTTP method\n");
        send_error_response(client_socket, 400, "Bad Request");
        return 0;
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
        send_error_response(client_socket, 400, "Bad Request");
        return 0;
    }

    // Ensure that the specified HTTP server exists (resolve hostname)
    struct hostent *server_hostent = gethostbyname(host);
    if (server_hostent == NULL) {
        fprintf(stderr, "Error: Could not resolve hostname\n");
        send_error_response(client_socket, 404, "Not Found");
        return 0;
    }
    printf("host = %s\n",server_hostent->h_name);
    return 1;
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
    if (!parse_request(client_socket, buffer, host, &port, path, url)) {
        pthread_exit(NULL);
    }
    
    // Check if the requested host is in the blocklist
    if (is_blocked(host)) {
        printf("Host %s is blocked\n", host);
        send_error_response(client_socket, 403, "Forbidden");
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
    pthread_exit(NULL);
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