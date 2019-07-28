#ifndef RAWHTTPS_H
#define RAWHTTPS_H
#include <sys/types.h>
typedef enum
{
	HTTP_GET,
	HTTP_HEAD,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_TRACE,
	HTTP_OPTIONS,
	HTTP_CONNECT,
	HTTP_PATCH
} rawhttps_method;

typedef struct
{
	void* elements;
	long long capacity;
	long long element_size;
} rawhttps_hash_table;

typedef struct
{
	rawhttps_hash_table ht;
} rawhttps_header;

// Struct received in the handler callback used to fetch information about the HTTP request.
// method: http method (duh)
// data: this is a pointer to the raw HTTP request data. You don't need to directly access this field
// uri: the received URI, also known as the endpoint...
// uri_size: size of the uri in bytes
// header: all received headers. Please use the function rawhttp_header_get to retrieve the headers, since this is actually a hash table
// connected_socket: connection socket's file descriptor, managed internally by rawhttp
typedef struct {
	rawhttps_method method;
	const char* data;
	const char* uri;
	long long uri_size;
	rawhttps_header header;
	int connected_socket;
} rawhttps_request;

typedef struct {
	const char* header;
	long long header_size;
	const char* value;
	long long value_size;
} rawhttps_response_header;

// Struct received in the handler callback used to set information about the HTTP response you want to send.
// headers: all response headers. Use the function rawhttp_response_add_header to add new headers here.
// headers_size: size of headers, used internally by rawhttp
// headers_capacity: capacity of headers, used internally by rawhttp
// response_content: a pointer to the response body. You need to set this field before calling rawhttp_response_flush!
// response_content_size: size, in bytes, of response_content. You also need to set this field before calling rawhttp_response_flush!
// status_code: response's status code. Default value is 200, feel free to change it.
typedef struct {
	rawhttps_response_header* headers;
	long long headers_size;
	long long headers_capacity;
	char* response_content;
	long long response_content_size;
	int status_code;
} rawhttps_response;

// This is the callback function you must implement for each handler you register. All action happens inside this function.
// Use rawhttp_server_register_handle to register a new handler.
// connection: used internally by rawhttp. You just need to forward this parameter to rawhttp_response_flush
// request: has information about the HTTP request. See rawhttp_request struct for more details
// response: allows you to set the HTTP response. See rawhttp_response struct for more details
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

typedef struct {
	int sockfd;
	int port;
	int initialized;
	rawhttps_handler_tree handlers;
} rawhttps_server;

typedef struct
{
	const char* value;
	long long value_size;
} rawhttps_header_value;

typedef enum
{
    RAWHTTPS_LOG_LEVEL_DISABLED = 0,
    RAWHTTPS_LOG_LEVEL_DEBUG = 1,
    RAWHTTPS_LOG_LEVEL_INFO = 2,
    RAWHTTPS_LOG_LEVEL_WARNING = 3,
    RAWHTTPS_LOG_LEVEL_ERROR = 4,
} rawhttps_log_level;

// Initializes rawhttps logging system. This function must be called to activate logging.
//
// level (input): Log level.
void rawhttps_logger_init(rawhttps_log_level level);
// Destroys rawhttps logging system. This function should only be called if rawhttps_logger_init was called before.
void rawhttps_logger_destroy();
// Initializes a new rawhttp_server struct. This function will not start the server.
//
// server (input/output): Struct to be initialized. Must be provided.
// port (input): The port that the server will use, when started
// certificate_path (input): The path to the PEM certificate
// private_key_path (input): The path to the PEM private key
// Return value: 0 if success, -1 if error
int rawhttps_server_init(rawhttps_server* server, int port, const char* certificate_path, const char* private_key_path);
// Destroys an initialized rawhttp_server struct. If the server is listening, this function will also shutdown the server and release resources.
// rawhttp_server_init must have been called before calling this function.
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
int rawhttps_server_register_handle(rawhttps_server* server, const char* pattern, long long pattern_size, rawhttps_server_handle_func handle);
// Starts listening for HTTP calls. This function is the one that opens the server
// This function blocks!
// If you are implementing a more 'serious' code, please consider creating a separate thread to call this function, and then
// call rawhttp_server_destroy to shutdown the server when exiting
//
// server (input): Initialized rawhttp_server
int rawhttps_server_listen(rawhttps_server* server);
// Flushes the HTTP response to the client.
// This function must ONLY be called inside the rawhttp_server_handle_func callback, which is registered via rawhttp_server_register_handle
// Also, this function can only be called a single time, otherwise multiple HTTP packets will be sent.
// You must set response->response_content before calling this function. This value will be used as the response body to the client.
// Please also set response->response_content_size with the size of your content.
//
// _connection (input): the connection parameter received in the callback must be sent here. This is used internally by rawhttp.
// response (input): struct containing the response information. It is also received in the callback. However, you should modify it.
ssize_t rawhttps_response_flush(const void* _connection, rawhttps_response* response);
// Add a new header to the HTTP response.
// This function must ONLY be called inside the rawhttp_server_handle_func callback, which is registered via rawhttp_server_register_handle
// You must call this function before rawhttp_response_flush
// Please use this function to add headers. Do not modify the response struct directly
//
// response (input): struct containing the response information. It is received in the callback.
// header (input): The new header name
// header_size (input): Size of header name
// value (input): Value of header
// header_size (input): Size of the value of header
void rawhttps_response_add_header(rawhttps_response* response, const char* header, long long header_size, const char* value, long long value_size);
// Retrieve the value of a header received in the HTTP request
// This function must ONLY be called inside the rawhttp_server_handle_func callback, which is registered via rawhttp_server_register_handle
//
// http_header (input): This field is accessible via request->header. The request struct is received as a parameter in the callback
// header (input): The name of the header
// header_size (input): The size of the name of the header
const rawhttps_header_value* rawhttps_header_get(const rawhttps_header* http_header, const char* header, long long header_size);

#endif