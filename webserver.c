#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
struct tuple resources[MAX_RESOURCES] = {
  {"/static/foo", "Foo", sizeof "Foo" - 1},
  {"/static/bar", "Bar", sizeof "Bar" - 1},
  {"/static/baz", "Baz", sizeof "Baz" - 1}};

struct tosend{
  uint8_t msg_type;
  uint16_t hash_id;
  uint16_t node_id;
  uint32_t node_ip;
  uint16_t node_port;
};

struct coll_sockets {
  int socket_self;
  int socket_tcp;
  int socket_succ;
  int socket_pred;
  struct sockaddr_in self;
  struct sockaddr_in succ;
  struct sockaddr_in pred;
};

struct node {
  uint16_t NODE_ID;
  uint16_t PRED_ID;
  uint16_t SUCC_ID;
  char *PRED_IP;
  char *SUCC_IP;
  uint16_t PRED_PORT;
  uint16_t SUCC_PORT;
  char *NODE_IP;
  uint16_t NODE_PORT;
};
uint16_t hash(const char *str) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256((uint8_t *)str, strlen(str), digest);
  return htons(*((uint16_t *)digest)); // We only use the first two bytes here
}
/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request
 * information.
 */
void send_reply(int conn, struct request *request) {

  // Create a buffer to hold the HTTP reply
  char buffer[HTTP_MAX_SIZE];
  char *reply = buffer;

  fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
      request->method, request->uri, request->payload_length);

  if (strcmp(request->method, "GET") == 0) {
    // Find the resource with the given URI in the 'resources' array.
    size_t resource_length;
    const char *resource =
      get(request->uri, resources, MAX_RESOURCES, &resource_length);

    if (resource) {
      sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
          resource_length, (int)resource_length, resource);
    } else {
      reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    }
  } else if (strcmp(request->method, "PUT") == 0) {
    // Try to set the requested resource with the given payload in the
    // 'resources' array.
    if (set(request->uri, request->payload, request->payload_length, resources,
          MAX_RESOURCES)) {
      reply = "HTTP/1.1 204 No Content\r\n\r\n";
    } else {
      reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    }
  } else if (strcmp(request->method, "DELETE") == 0) {
    // Try to delete the requested resource from the 'resources' array
    if (delete (request->uri, resources, MAX_RESOURCES)) {
      reply = "HTTP/1.1 204 No Content\r\n\r\n";
    } else {
      reply = "HTTP/1.1 404 Not Found\r\n\r\n";
    }
  } else {
    reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
  }

  // Send the reply back to the client
  if (send(conn, reply, strlen(reply), 0) == -1) {
    perror("send");
    close(conn);
  }
}

char *uri_to_hash(struct request *request) {
  char *uri = strdup(request->uri);
  char *to_return;
  uri = strstr(uri, "/");
  to_return = strdup(uri);

  return to_return;
}

// process an incoming packet received by UDP
size_t process_packet_udp(int conn, struct coll_sockets *combination,
    char *buffer, size_t n, struct node *input, struct tosend *result) {
  struct request request = {
    .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};
  char *path;
  uint16_t path_hashed;
  ssize_t bytes_processed = parse_request(buffer, n, &request);
  struct in_addr sock;
  struct in_addr sock_o;
  char buf[50];

  char temp[HTTP_MAX_SIZE];
  char *reply = temp;
  char udp_another[11];
  int numbytes;
  int retry_attempt = 0;
  int retry_after = 1;
  inet_pton(AF_INET, input->NODE_IP, &(sock));
  inet_ntop(AF_INET,&sock,buf, INET_ADDRSTRLEN);
  udp_another[0] = 0; 
  udp_another[3] = (input->NODE_ID>>8) & 0xFF;
  udp_another[4] = input->NODE_ID & 0xFF;
  udp_another[5] = sock.s_addr & 0xFF;   
  udp_another[6] = (sock.s_addr >>8) & 0xFF;
  udp_another[7] = (sock.s_addr >> 16) & 0xFF;
  udp_another[8] = (sock.s_addr >> 24) & 0xFF;
  udp_another[9] = (input->NODE_PORT>>8) & 0xFF;
  udp_another[10] = (input->NODE_PORT) & 0xFF;

  if (bytes_processed > 0) {
    path = uri_to_hash(&request);
    path_hashed = hash(path);

    udp_another[1] = (path_hashed >>8) &0xFF;
    udp_another[2] = (path_hashed ) &0xFF; 
    if (input->NODE_ID < path_hashed && path_hashed <= input->SUCC_ID ) {
      sprintf(reply,
          "HTTP/1.1 303 See Other\r\nLocation: "
          "http://%s:%d%s\r\nContent-Length: 0\r\n\r\n",
          input->SUCC_IP, input->SUCC_PORT, request.uri);
      if ((numbytes = send(conn, reply, strlen(reply), 0)) > -1) {
        return numbytes;
      }
    }else if(result->hash_id < path_hashed && path_hashed <= result->node_id){

      sprintf(reply,
          "HTTP/1.1 303 See Other\r\nLocation: "
          "http://%s:%d%s\r\nContent-Length: 0\r\n\r\n",
          buf, result->node_port, request.uri);
      if ((numbytes = send(conn, reply, strlen(reply), 0)) > -1) {
        return numbytes;
      }
    } else {
      if(input->SUCC_ID == input->PRED_ID ){

        const string bad_req = "HTTP/1.1 404 Not Found\r\nContent-Length:0\r\n\r\n"; 
        numbytes = send(conn, bad_req, strlen(bad_req),0);
      }else{
        sprintf(reply,
            "HTTP/1.1 503 Service Unavailable\r\nRetry-After: "
            "%d\r\nContent-Length: 0\r\n\r\n",
            retry_after);

        if ((numbytes = send(conn, reply, strlen(reply), 0)) > -1) {
          //sprintf(udp_another,
          //    "%u%u%u%u%u"
          //    ,msg_lookup, htons(path_hashed), htons(input->NODE_ID), htonl(sock.sin_addr.s_addr), htons(input->NODE_PORT));
          sendto(combination->socket_self, udp_another, sizeof(udp_another), 0,
              (struct sockaddr *)&combination->succ,
              sizeof(combination->succ));
          
        }
      }
    }
    // pake uri_to_hash utk dpt pathnya nnt di
  } else if (bytes_processed == -1) {
    // If the request is malformed or an error occurs during processing, send a
    // 400 Bad Request response to the client. const string bad_request =
    // "HTTP/1.1 400 Bad Request\r\n\r\n"; sendto(conn, bad_request,
    // strlen(bad_request), 0, (struct sockaddr *) &addr, sizeof(addr));
    printf("Received malformed request, terminating connection.\n");
    close(conn);
    return -1;
  }

  return bytes_processed;
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the
 * return value indicates the number of bytes processed. If the packet is
 * malformed or an error occurs during processing, the return value is -1.
 *
 */
size_t process_packet(int conn, char *buffer, size_t n) {
  struct request request = {
    .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};

  ssize_t bytes_processed = parse_request(buffer, n, &request);

  if (bytes_processed > 0) {
    send_reply(conn, &request);

    // Check the "Connection" header in the request to determine if the
    // connection should be kept alive or closed.
    const string connection_header = get_header(&request, "Connection");
    if (connection_header && strcmp(connection_header, "close")) {
      return -1;
    }
  } else if (bytes_processed == -1) {
    // If the request is malformed or an error occurs during processing, send a
    // 400 Bad Request response to the client.
    const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
    send(conn, bad_request, strlen(bad_request), 0);
    printf("Received malformed request, terminating connection.\n");
    close(conn);
    return -1;
  }

  return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock) {
  // Set the socket descriptor for the new connection in the connection_state
  // structure.
  state->sock = sock;

  // Set the 'end' pointer of the state to the beginning of the buffer.
  state->end = state->buffer;

  // Clear the buffer by filling it with zeros to avoid any stale data.
  memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded
 * bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the
 * discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep) {
  memmove(buffer, buffer + discard, keep);
  memset(buffer + keep, 0, discard); // invalidate buffer
  return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the
 * connection state.
 * @return Returns true if the connection and data processing were successful,
 * false otherwise. If an error occurs while receiving data from the socket, the
 * function exits the program.
 */
bool handle_connection(struct connection_state *state,
    struct node *input, struct tosend *result,
    struct coll_sockets *combination, int udp) {
  // Calculate the pointer to the end of the buffer to avoid buffer overflow
  struct sockaddr_storage addr;
  const char *buffer_end = state->buffer + HTTP_MAX_SIZE;
  // Check if an error occurred while receiving data from the socket
  ssize_t bytes_read =
    recv(state->sock, state->end, buffer_end - state->end, 0);
  if (bytes_read == -1) {
    perror("recv");
    close(state->sock);
    exit(EXIT_FAILURE);
  } else if (bytes_read == 0) {
    return false;
  }
  char *window_start = state->buffer;
  char *window_end = state->end + bytes_read;

  ssize_t bytes_processed = 0;
  if (udp == 1) {
    while ((bytes_processed =
          process_packet_udp(state->sock, combination, window_start,
            window_end - window_start, input, result)) > 0) {

      window_start += bytes_processed;
    }

  } else {
    while ((bytes_processed = process_packet(state->sock, window_start,
            window_end - window_start)) > 0) {
      window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
      return false;
    }
  }
  state->end = buffer_discard(state->buffer, window_start - state->buffer,
      window_end - window_start);
  return true;
}

int recvfrom_after(char* buffer, struct coll_sockets *combination, struct node *input, struct tosend *received){
  char udp_another[11];
  struct in_addr sock;
  inet_pton( AF_INET, input->NODE_IP, &sock);
  received->msg_type = buffer[0];
  received->hash_id =(uint16_t) (buffer[1] << 8) | (uint16_t)buffer[2];
  received->node_id =(uint16_t) (buffer[3] << 8) | (uint16_t)buffer[4];
  received->node_ip =(uint32_t) (buffer[5]<<24) | (uint32_t)(buffer[6] << 16) | 
    (uint32_t)(buffer[7] <<8) | (uint32_t)buffer[8];
  received->node_port = (uint16_t) (buffer[9] << 8) | (uint16_t)buffer[10];
  if(received->msg_type == 0){
    if (input->NODE_ID < received->hash_id && received->hash_id <= input->SUCC_ID ) {
      udp_another[0] = 1;
      udp_another[1] = (input->NODE_ID >>8) &0xFF;
      udp_another[2] = input->NODE_ID & 0xFF;
      udp_another[3] = (input->SUCC_ID >> 8) &0xFF;
      udp_another[4] = input->SUCC_ID & 0xFF;
      udp_another[5] = sock.s_addr &0xFF;
      udp_another[6] = (sock.s_addr >> 8) & 0xFF;
      udp_another[7] = (sock.s_addr >> 16) &0xFF;
      udp_another[8] = (sock.s_addr >> 24) & 0xFF;
      udp_another[9] = (input->SUCC_PORT >> 8) & 0xFF;
      udp_another[10] = input->SUCC_PORT &0xFF;

      sendto(combination->socket_self, udp_another, sizeof(udp_another), 0,
          (struct sockaddr *)&combination->pred,
          sizeof(combination->pred));
      return 2;
    }else{
      udp_another[0] = buffer[0];
      udp_another[1] = buffer[1]; 
      udp_another[2] = buffer[2];
      udp_another[3] = buffer[3];
      udp_another[4] = buffer[4];
      udp_another[5] = buffer[5];
      udp_another[6] = buffer[6];
      udp_another[7] = buffer[7];
      udp_another[8] = buffer[8];
      udp_another[9] = buffer[9];
      udp_another[10] =buffer[10];

      sendto(combination->socket_self, udp_another, sizeof(udp_another), 0,
          (struct sockaddr *)&combination->succ,
          sizeof(combination->succ));
      return 1;
    }
  }else{

  }
  return 0;
}
/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network
 * address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from
 * the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
  struct addrinfo *result_info;
  struct addrinfo hints = {
    .ai_family = AF_INET,
  };
  // Resolve the host (IP address or hostname) into a list of possible
  // addresses.
  int returncode = getaddrinfo(host, port, &hints, &result_info);
  if (returncode) {
    fprintf(stderr, "Error parsing host/port");
    exit(EXIT_FAILURE);
  }

  // Copy the sockaddr_in structure from the first address in the list
  struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

  // Free the allocated memory for the result_info
  freeaddrinfo(result_info);
  return result;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of
 * the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr, int tcp) {
  const int enable = 1;
  const int backlog = 1;
  int sock;
  // Create a socket
  if (tcp == 1) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
      perror("socket");
      exit(EXIT_FAILURE);
    }
  } else {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
      perror("socket");
      exit(EXIT_FAILURE);
    }
  }

  // Avoid dead lock on connections that are dropped after poll returns but
  // before accept is called
  if (tcp == 1) {
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
      perror("fcntl");
      exit(EXIT_FAILURE);
    }
  }

  // Set the SO_REUSEADDR socket option to allow reuse of local addresses
  if (tcp == 1) {
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
        -1) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }
  }

  // Bind socket to the provided address
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind");
    close(sock);
    exit(EXIT_FAILURE);
  }
  // Start listening on the socket with maximum backlog of 1 pending connection
  if (tcp == 1) {
    if (listen(sock, backlog)) {
      perror("listen");
      exit(EXIT_FAILURE);
    }
  }

  return sock;
}
bool env_to_node(struct node *node, uint16_t node_id, char *port, char *ip) {
  node->PRED_ID = safe_strtoul(getenv("PRED_ID"), NULL, 10, "PRED_ID");
  node->SUCC_ID = safe_strtoul(getenv("SUCC_ID"), NULL, 10, "PRED_ID");
  node->PRED_IP = getenv("PRED_IP");
  node->SUCC_IP = getenv("SUCC_IP");
  node->PRED_PORT = safe_strtoul(getenv("PRED_PORT"), NULL, 10, "PRED_ID");
  node->SUCC_PORT = safe_strtoul(getenv("SUCC_PORT"), NULL, 10, "PRED_ID");
  node->NODE_ID = node_id;
  node->NODE_IP = ip;
  node->NODE_PORT = safe_strtoul(port, NULL, 10, "NODE_PORT");
  return true;
}
/**
 *  The program expects 3; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 */
int main(int argc, char **argv) {
  struct node *input = calloc(1, sizeof(struct node));
  int udp;
  if (argv[3] != NULL) {
    udp = 1;
  } else {
    udp = 0;
  }

  struct coll_sockets combination;
  char *succ_port;
  char *pred_port;
  if (argc > 3) {
    char *argv3 = strdup(argv[3]);
    int self_node = safe_strtoul(argv3, NULL, 10, "self");
    succ_port = getenv("SUCC_PORT");
    pred_port = getenv("PRED_PORT");

    env_to_node(input, self_node, argv[2], argv[1]);
    combination.succ = derive_sockaddr(NULL, succ_port);
    combination.pred = derive_sockaddr(NULL, pred_port);
  }
  combination.self = derive_sockaddr(NULL, argv[2]);
  struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);
  // Set up a server socket.
  //combination.socket_pred = setup_server_socket(combination.pred, 0);
  combination.socket_self = setup_server_socket(combination.self, 0);
  //  combination.socket_succ = setup_server_socket(combination.succ, 0);
  combination.socket_tcp = setup_server_socket(addr, 1);
  // Create an array of pollfd structures to monitor sockets.
  struct pollfd sockets[3] = {
    {.fd = combination.socket_tcp, .events = POLLIN},
    {.fd = -1, .events = 0},  
    {.fd = combination.socket_self, .events = POLLIN | POLLPRI},
  };

  struct tosend result={0};
  struct connection_state state = {0};
  struct connection_state state_udp = {0};
  struct connection_state state_succ = {0};
  while (true) {
    connection_setup(&state_udp, combination.socket_self);
    connection_setup(&state_succ, combination.socket_succ);
    // handle_connection_udp(&state_udp, input, addr_udp);
    //  Use poll() to wait for events on the monitored sockets.
    int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
    if (ready == -1) {
      perror("poll");
      exit(EXIT_FAILURE);
    }

    // Process events on the monitored sockets.
    for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i += 1) {
      if (sockets[i].revents != POLLIN) {
        // If there are no POLLIN events on the socket, continue to the next
        // iteration.
        continue;
      }
      int s = sockets[i].fd;

      if (s == combination.socket_tcp) {

        // If the event is on the server_socket, accept a new connection from a
        // client.
        int connection = accept(combination.socket_tcp, NULL, NULL);
        if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
          close(combination.socket_tcp);
          perror("accept");
          exit(EXIT_FAILURE);
        } else {
          connection_setup(&state, connection);

          // limit to one connection at a time
          sockets[0].events = 0;
          sockets[1].fd = connection;
          sockets[1].events = POLLIN;
        }
      } else if(s == state.sock){
        // Call the 'handle_connection' function to process the incoming data on
        // the socket.
        bool cont = handle_connection(&state, input, &result,
            &combination, udp);
        if (!cont) { // get ready for a new connection
          sockets[0].events = POLLIN;
          sockets[1].events = 0;
          sockets[1].fd = -1;
        }
      }else{
        if(sockets[2].revents & (POLLERR | POLLHUP | POLLNVAL)){
          continue;
        }else if(sockets[2].revents & (POLLIN | POLLPRI)){
          struct sockaddr_storage xd;
          socklen_t xdd = sizeof(xd);
          char buf[500];
          int bytes = recvfrom(combination.socket_self, buf, sizeof(buf), 0, (struct sockaddr *)&xd, &xdd);
          //tinggal kirim
          if(bytes != -1){
            int returnfromrecv = recvfrom_after(buf, &combination, input, &result);
          }
        }
      }

    }
  }
  free(input);

  return EXIT_SUCCESS;
}
