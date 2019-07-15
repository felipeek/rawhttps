#ifndef RAWHTTPS_SERVER_H
#define RAWHTTPS_SERVER_H
#include "http/http_handler_tree.h"
#include "linux/limits.h"

typedef struct {
	int sockfd;
	int port;
	int initialized;
	rawhttp_handler_tree handlers;
	char certificate_path[PATH_MAX];
	char private_key_path[PATH_MAX];
} rawhttps_server;

// Initializes a new rawhttps_server struct. This function will not start the server.
//
// server (input/output): Struct to be initialized. Must be provided.
// port (input): The port that the server will use, when started
// Return value: 0 if success, -1 if error
int rawhttps_server_init(rawhttps_server* server, int port, const char* certificate_path, int certificate_path_length,
	const char* private_key_path, int private_key_path_length);
// Destroys an initialized rawhttps_server struct. If the server is listening, this function will also shutdown the server and release resources.
// rawhttps_server_init must have been called before calling this function.
//
// server (input): Reference to the server to be destroyed
// Return value: 0 if success, -1 if error
int rawhttps_server_destroy(rawhttps_server* server);
// Register a new handle. Must be called before calling rawhttp_server_listen.
// The pattern defines how rawhttp will treat the handle. If the pattern ends with a slash (/), the handle will be called
// regardless of what comes after the slash, unless there is a more specific handler registered.
// If, however, the pattern doesn't end with a slash (/), the handle will only be called for its specific endpoint.
// Example: if you register 3 handlers using these 3 different patterns:
// #1: /bar
// #2: /foo/
// #3: /foo/bar
// Then, the following endpoint calls will invoke the following handlers:
// your-server:80/bar -> invokes #1 (/bar)
// your-server:80/bar/ -> no handler associated.
// your-server:80/foo/ -> invokes #2 (/foo/)
// your-server:80/foo/dummy -> invokes #2 (/foo/)
// your-server:80/foo/bar -> invokes #3 (/foo/bar)
// your-server:80/foo/bar/dummy -> invokes #2 (/foo/)
//
// server (input): Initialized rawhttp_server
// pattern (input): The pattern to be registered.
// pattern_size (input): The size, in bytes, of the pattern being registered
// handle (input): The callback function that rawhttp will call when this handle is triggered
int rawhttp_server_register_handle(rawhttps_server* server, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle);
// Starts listening for HTTP calls. This function is the one that opens the server
// This function blocks!
// If you are implementing a more 'serious' code, please consider creating a separate thread to call this function, and then
// call rawhttp_server_destroy to shutdown the server when exiting
//
// server (input): Initialized rawhttp_server
int rawhttps_server_listen(rawhttps_server* server);
#endif