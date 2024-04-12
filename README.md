# Proxy-Server

## Compile Program
gcc proxy.c -o proxy -pthread -lssl -lcrypto -lxml2 -lcurl -I/usr/include/libxml2

## Testing command
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null

### With Response Time
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n"

### Send Simultaneous Requests
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n" & curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n" &

http://netsys.cs.colorado.edu/
## Pending to implement
1. Cache file should expire from last accessed time
2. Link prefetch