# Proxy-Server

## Compile Program
gcc proxy.c -o proxy -pthread -lssl -lcrypto -lxml2 -lcurl -I/usr/include/libxml2

## Testing command
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null

### With Response Time
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n"

### Send Simultaneous Requests
curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n" & curl --proxy http://localhost:8080 http://www.google.com -ivk -o /dev/null -w "Response time: %{time_total} seconds\n" &

curl --proxy http://localhost:8080 http://netsys.cs.colorado.edu/ -ivk -o /dev/null -w "Response time: %{time_total} seconds\n"