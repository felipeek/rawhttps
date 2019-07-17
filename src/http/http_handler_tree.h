#ifndef RAWHTTPS_HTTP_HANDLER_TREE_H
#define RAWHTTPS_HTTP_HANDLER_TREE_H
#include "http_request.h"
#include "http_response.h"
// This is the callback function you must implement for each handler you register. All action happens inside this function.
// Use rawhttps_server_register_handle to register a new handler.
// connection: used internally by rawhttps. You just need to forward this parameter to rawhttps_response_flush
// request: has information about the HTTP request. See rawhttps_request struct for more details
// response: allows you to set the HTTP response. See rawhttps_response struct for more details
typedef void (*rawhttps_server_handle_func)(const void* connection, const rawhttps_request* request, rawhttps_response* response);
typedef struct {
	rawhttps_server_handle_func handle;
} rawhttps_server_handler;
typedef struct {
	rawhttps_server_handler handler;
	int valid;
	int has_handler;
	int subtree_root;
	const char* pattern;
	long long pattern_size;
	long long next;
	long long child;
} rawhttps_handler_tree_element;

typedef struct {
	rawhttps_handler_tree_element* elements;
	long long num_elements;
	long long capacity;
} rawhttps_handler_tree;

int rawhttps_handler_tree_create(rawhttps_handler_tree* tree, long long capacity);
void rawhttps_handler_tree_destroy(rawhttps_handler_tree* tree);
int rawhttps_handler_tree_put(rawhttps_handler_tree* tree, const char* pattern, long long pattern_size, rawhttps_server_handle_func handle);
const rawhttps_server_handler* rawhttps_handler_tree_get(rawhttps_handler_tree* tree, const char* pattern, long long pattern_size);
#endif