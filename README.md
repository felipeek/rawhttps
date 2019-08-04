# rawhttps

Library to create a https server for Linux.

## Usage

To compile rawhttps to a static library, run `Makefile`. The static library will be available in `bin/rawhttps.a`.

To use the library, link `rawhttps.a` to your project and include `rawhttps.h` in your source files.

The goal of rawhttp is to be extremely simple and easy to use. To open a server, you will always:

    Call rawhttps_server_init to initialize a rawhttps_server struct.
    Implement a callback function for each handle you want to register.
    Call rawhttps_server_register_handle for each handle you decided to register.
    Call rawhttps_server_listen to start listening.
    For a more serious implementation, call rawhttps_server_destroy to stop the server and release resources.

To avoid duplicate documentation, all functions are documented directly in `rawhttps.h`. However, one can understand the library completely just by looking at the code snippets showed this document.

## A complete example

```C
#include "rawhttps.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

rawhttps_server server;

void root_handle(const void* connection, const rawhttps_request* request, rawhttps_response* response)
{
	// Just for fun, we check if we received the header Secret-Header:Secret-Value
	char secret_header[] = "Secret-Header";
	char secret_header_expected_value[] = "Secret-Value";
	const rawhttps_header_value* secret_header_value = rawhttps_header_get(&request->header, secret_header, sizeof(secret_header) - 1);
	if (secret_header_value != NULL && sizeof(secret_header_expected_value) - 1 == secret_header_value->value_size && !strncmp(secret_header_value->value, secret_header_expected_value, sizeof(secret_header_expected_value) - 1))
	{
		// If we received this header, we send this secret response
		char buf[] = "<h1>You used the secret header!</h1>";
		response->response_content = buf;
		response->response_content_size = sizeof(buf) - 1;

		// And also set a secret response header
		char secret_response_header[] = "Secret-Response-Header";
		char secret_response_header_value[] = "Secret-Value";
		rawhttps_response_add_header(response, secret_response_header, sizeof(secret_response_header) - 1, secret_response_header_value, sizeof(secret_response_header_value) - 1);
	}
	else
	{
		// If the secret header was not sent, we send the default response.
		char buf[] = "<h1>Welcome to rawhttps server!</h1>";
		response->response_content = buf;
		response->response_content_size = sizeof(buf) - 1;
	}
	response->status_code = 200;
	rawhttps_response_flush(connection, response);
}

void foo_handle(const void* connection, const rawhttps_request* request, rawhttps_response* response)
{
	char buf[] = "<h1>FOO!</h1>";
	response->response_content = buf;
	response->response_content_size = sizeof(buf) - 1;
	response->status_code = 200;
	rawhttps_response_flush(connection, response);
}

void foo2_handle(const void* connection, const rawhttps_request* request, rawhttps_response* response)
{
	char buf[] = "<h1>FOO2!</h1>";
	response->response_content = buf;
	response->response_content_size = sizeof(buf) - 1;
	response->status_code = 200;
	rawhttps_response_flush(connection, response);
}

void close_server(int signum)
{
	// Stops the server and releases resources
	rawhttps_server_destroy(&server);
	rawhttps_logger_destroy();
}

int main(int argc, char** argv)
{
	if (argc != 3)
	{
		printf("Usage: %s <certificate_path> <private_key_path>\n", argv[0]);
		return -1;
	}

	signal(SIGINT, close_server);

	rawhttps_logger_init(RAWHTTPS_LOG_LEVEL_INFO);

	rawhttps_server_init(&server, 8080, argv[1], argv[2]);

	// Register a handle for pattern '/'. This will basically receive all requests
	// that doesn't have a "more specific" handler assigned.
	rawhttps_server_register_handle(&server, "/", sizeof("/") - 1, root_handle);
	// Register a handle for pattern '/foo/'. This will receive all requests
	// which URI has the format /foo/*. (example: /foo/ , /foo/bar , /foo/bar/daz)
	rawhttps_server_register_handle(&server, "/foo/", sizeof("/foo/") - 1, foo_handle);
	// Register a handle for the specific URI '/foo2'. This will receive only requests
	// with this specific URI. This happens because it doesn't end with a slash.
	rawhttps_server_register_handle(&server, "/foo2", sizeof("/foo2") - 1, foo2_handle);

	// In this example,
	// '/', '/a', '/foo', '/foo2/' and '/foo2/bar' are all redirected to handle 1
	// '/foo/', '/foo/a', '/foo/a/b/' are all redirected to handle 2
	// only '/foo2' is redirected to handle 3

	// Starts the server. This blocks!
	rawhttps_server_listen(&server);

	return 0;
}
```

To compile:

```
$ gcc example.c rawhttps.a -o example -lpthread
```

To run:

```
$ ./example ./certificate.pem ./key.pem
```

## To do
- [ ] Modify code to support HTTP keep-alive
- [ ] Implement session-id
- [ ] Implement compression methods
- [ ] Implement extensions
- [ ] Support for DH ciphers
- [ ] Support certificate chain
- [ ] Use scheduler instead of one thread per connection
- [ ] Stop running threads in rawhttps_server_destroy
