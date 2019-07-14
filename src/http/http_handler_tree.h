#ifndef RAWHTTPS_HTTP_HANDLER_TREE_H
#define RAWHTTPS_HTTP_HANDLER_TREE_H
#include "http_request.h"
#include "http_response.h"
// This is the callback function you must implement for each handler you register. All action happens inside this function.
// Use rawhttp_server_register_handle to register a new handler.
// connection: used internally by rawhttp. You just need to forward this parameter to rawhttp_response_flush
// request: has information about the HTTP request. See rawhttp_request struct for more details
// response: allows you to set the HTTP response. See rawhttp_response struct for more details
typedef void (*rawhttp_server_handle_func)(const void* connection, const rawhttp_request* request, rawhttp_response* response);
typedef struct {
	rawhttp_server_handle_func handle;
} rawhttp_server_handler;
typedef struct {
	rawhttp_server_handler handler;
	int valid;
	int has_handler;
	int subtree_root;
	const char* pattern;
	long long pattern_size;
	long long next;
	long long child;
} rawhttp_handler_tree_element;

typedef struct {
	rawhttp_handler_tree_element* elements;
	long long num_elements;
	long long capacity;
} rawhttp_handler_tree;

int rawhttp_handler_tree_create(rawhttp_handler_tree* tree, long long capacity);
void rawhttp_handler_tree_destroy(rawhttp_handler_tree* tree);
int rawhttp_handler_tree_put(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle);
const rawhttp_server_handler* rawhttp_handler_tree_get(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size);
#endif