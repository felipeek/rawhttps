#ifndef RAWHTTPS_SERVER_H
#define RAWHTTPS_SERVER_H

typedef struct {
	int sockfd;
	int port;
	int initialized;
} rawhttps_server;

// Initializes a new rawhttps_server struct. This function will not start the server.
//
// server (input/output): Struct to be initialized. Must be provided.
// port (input): The port that the server will use, when started
// Return value: 0 if success, -1 if error
int rawhttps_server_init(rawhttps_server* server, int port);
// Destroys an initialized rawhttps_server struct. If the server is listening, this function will also shutdown the server and release resources.
// rawhttps_server_init must have been called before calling this function.
//
// server (input): Reference to the server to be destroyed
// Return value: 0 if success, -1 if error
int rawhttps_server_destroy(rawhttps_server* server);
// Starts listening for HTTP calls. This function is the one that opens the server
// This function blocks!
// If you are implementing a more 'serious' code, please consider creating a separate thread to call this function, and then
// call rawhttp_server_destroy to shutdown the server when exiting
//
// server (input): Initialized rawhttp_server
int rawhttps_server_listen(rawhttps_server* server);
#endif