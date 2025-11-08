/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Copyright (C) 2025 Carter Williams
 *
 * This file is part of Cerve.
 *
 * Cerve is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Cerve is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

#ifndef CERVE_HTTP_H
#define CERVE_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum cerve_http_version {
	CERVE_HTTP_VERSION_11 = 0,
	CERVE_HTTP_VERSION_20,
	CERVE_HTTP_VERSION_30,
	CERVE_HTTP_VERSION_10,
	CERVE_HTTP_VERSION_AUTO,
};

enum cerve_http_method {
	CERVE_HTTP_METHOD_GET = 0,
	CERVE_HTTP_METHOD_POST,
	CERVE_HTTP_METHOD_PUT,
	CERVE_HTTP_METHOD_PATCH,
	CERVE_HTTP_METHOD_DELETE,
	CERVE_HTTP_METHOD_HEAD,
	CERVE_HTTP_METHOD_CONNECT,
	CERVE_HTTP_METHOD_OPTIONS,
	CERVE_HTTP_METHOD_TRACE,
	CERVE_HTTP_METHOD_INVALID,
};

// Bitmask of HTTP methods. This allows the user to set the
// same handler for multiple methods.
typedef uint32_t cerve_http_methods_t;
static cerve_http_methods_t cerve_http_methods_init(void)
{
	return 0;
}
static cerve_http_methods_t
cerve_http_methods_add(cerve_http_methods_t mask, enum cerve_http_method method)
{
	return mask | ((cerve_http_methods_t)1 << method);
}

// Opaque
struct cerve_http_headers;
struct cerve_http_headers_iter;
struct cerve_http_server;

// Forward declare
struct cerve_http_request;
struct cerve_http_response;

typedef int (*cerve_http_handler_t)(const struct cerve_http_request *req,
				    struct cerve_http_response *res);
typedef void (*cerve_http_response_cleanup_t)(struct cerve_http_response *res);

// HTTP request that is parsed and passed to the appropriate
// cerve_http_handler_t function.
// Cerve owns this struct and the user should not modify it. You should
// NOT reference anything related to this struct after the cerve_http_handler_t
// function returns.
struct cerve_http_request {
	enum cerve_http_method method;
	enum cerve_http_version version;

	// Access through cerve_http_headers_get().
	struct cerve_http_headers *headers;

	// These simply point into raw and are not guaranteed to be
	// null terminated. You must rely on the length.
	const char *path;
	size_t path_len;
	const char *query;
	size_t query_len;
	const char *body;
	size_t body_len;

	// Raw request buffer
	const char *raw;
	size_t raw_len;
};

// HTTP response that is allocated by cerve and passed to the appropriate
// cerve_http_handler_t function for the user to populate. body is initially
// NULL and the user is responsible for allocating it. After Cerve sends the
// response, it will call the cerve_http_response_cleanup_t function that
// was set by the user. You are responsible for setting this function and
// the associated userdata field.
// Similar to cerve_http_request, do NOT reference anything related to this
// struct after cerve_http_response_cleanup_t returns.
struct cerve_http_response {
	enum cerve_http_version version;
	int status;

	// Access through cerve_http_headers_add() and cerve_http_headers_get()
	struct cerve_http_headers *headers;

	// Initially NULL. You must allocate and set it.
	char *body;
	size_t body_len;

	// Initially NULL. You must set this function if you have things to
	// cleanup (like body) after the response is sent.
	cerve_http_response_cleanup_t cleanup;
	// Initially NULL. Userdata that may be useful in cleanup.
	void *userdata;
};

// name and value may not be NULL terminated. You must use the length.
struct cerve_http_header {
	char *name;
	char *value;
	unsigned int name_len;
	unsigned int value_len;
};

// Return the size and alignment requirements for struct cerve_http_server.
// The server_buf passed to cerve_http_init should fulfill these.
size_t cerve_http_server_struct_size(void);
size_t cerve_http_server_struct_alignment(void);

// Initialize a HTTP server. Ensure server_buf is aligned correctly and
// server_buf_size is adequate (see cerve_http_server_struct_size() and
// cerve_http_server_struct_alignment()).
//
// ip can contain the port number but it will be ignored.
// port should be in host order.
//
// On success, a non-NULL pointer is returned.
// On error, NULL is returned and errno is set.
struct cerve_http_server *cerve_http_init(void *server_buf,
					  size_t server_buf_size,
					  const char *ip, uint16_t port,
					  enum cerve_http_version version);

// Start the HTTP server. This function will not return unless an error has
// occurred.
//
// On success, 0 is returned.
// On error, errno is set and returned.
int cerve_http_start(struct cerve_http_server *s);

// These next few functions deal with registering files with the HTTP
// server. The motivation for these is to make the common case of serving
// static content very easy. Here are some insights into the implementation.
// - A file can be registered multiple times to different http_paths.
// - The most up to date version of the file will be sent. The contents are
//   not cached on registration (and if they are, the cached value will be
//   invalidated on file update).
// - If a file is registered and doesn't exist (or is later deleted),
//   the endpoint will return 404 and the file will remain registered.
//   It is up to the user to unregister the file.
// - Files will support the GET and HEAD methods.

// Register a file located at file_path to be served as http_path.
//
// On success, 0 is returned.
// On error, errno is set and returned.
//
// An error can occur in the following cases:
// - EINVAL: One of the arguments was NULL or cerve_http_server isn't valid.
// - EEXIST: A resource is already being served at http_path.
// - EISDIR: file_path is a directory.
int cerve_http_register_file(struct cerve_http_server *s, const char *file_path,
			     const char *http_path);

// Register a directory located at dir_path to be served as http_path.
// For example, if I serve ~/notes as /carter/notes, ~/notes/note.txt
// will be served as /carter/notes/note.txt.
//
// On success, 0 is returned.
// On error, errno is set and returned.
//
// An can can occur in the following cases:
// - EINVAL: One of the arguments was NULL or cerve_http_server isn't valid.
// - EEXIST: A resource is already being served at http_path.
// - ENOTDIR: dir_path is not a directory.
int cerve_http_register_directory(struct cerve_http_server *s,
				  const char *dir_path, const char *http_path);

// Register a custom handler to be called when http_path is requested
// with a method in the methods bitmask.
//
// On success, 0 is returned.
// On error, errno is set and returned.
//
// An error can occur in the following cases:
// - EINVAL: One of the arguments was NULL, cerve_http_server isn't valid, or
//   methods was emtpy.
// - EEXIST: A resouce is already being served at http_path.
int cerve_http_register_handler(struct cerve_http_server *s,
				cerve_http_methods_t methods,
				const char *http_path,
				cerve_http_handler_t handler);

// Unregister a file, directory, or custom handler at http_path.
//
// On success, 0 is returned.
// On error, errno is set and returned.
//
// An error can occur in the following cases:
// - EINVAL: One of the arguments was NULL or cerve_http_server isn't valid.
// - ENOENT: Nothing is registered at http_path.
int cerve_http_unregister(struct cerve_http_server *s, const char *http_path);

// Get a header from the cerve_http_headers pointer attached to a HTTP request
// or response. header should have the name and name_len set, and this function
// will set value and value_len. Some important notes:
// - You do not own value.
// - value IS NOT NULL terminated.
//
// If header->name is not found, value and value_len is set to NULL and
// errno is set to ENOENT and returned.
int cerve_http_headers_get(const struct cerve_http_headers *headers,
			   struct cerve_http_header *header);

// Add a header to the cerve_http_headers pointer attached to a
// HTTP response. The values will be copied into Cerve's buffers
// so you can free header->name, and/or header->value after the call
// returns.
//
// On success, 0 is returned.
// On error, errno is set and returned.
//
// An error can occur in the following cases:
// - EINVAL: One of the arguments was NULL or the header was invalid.
int cerve_http_headers_add(struct cerve_http_headers *headers,
			   const struct cerve_http_header *header);

// Return the number of headers.
size_t cerve_http_headers_count(const struct cerve_http_headers *headers);

// Initialize an iterator to iterate over all headers attached to a
// HTTP request or response.
void cerve_http_headers_iter_init(const struct cerve_http_headers *headers,
				  struct cerve_http_headers_iter *iter);

// Grab the next header from iter and place it into header_next. Some
// important notes:
// - You do not own name or value.
// - name and value ARE NOT NULL terminated.
//
// On success, true is returned and header_next is set to valid values.
// On error, false is returned and header_next is undefined.
bool cerve_http_headers_iter_next(struct cerve_http_headers_iter *iter,
				  struct cerve_http_header *header_next);

// Returns true if the header name is a valid HTTP header name.
// Returns false if:
// - A non-tchar character is present
//   (https://datatracker.ietf.org/doc/html/rfc9110#name-tokens)
// - An uppercase alphabetical char is present.
//
// Cerve will eventually support HTTP 2.0. HTTP 2.0 forces header
// names to be lower case so cerve also forces this.
bool cerve_http_header_valid_name(const char *name, size_t len);

enum cerve_http_server_opt {
	// uint64_t (ms): Maximum time to read an HTTP request.
	// 408 is returned after this timeout.
	CERVE_HTTP_SERVER_OPT_REQ_READ_TIMEOUT_MS = 0,
	// size_t (bytes): Maximum size an HTTP request's body can be.
	// 413 is returned if the request body is too long.
	CERVE_HTTP_SERVER_OPT_REQ_BODY_SIZE_MAX,
	// size_t (bytes): Maximum size an HTTP request's headers can be.
	// 431 is returned if the request headers are too long.
	CERVE_HTTP_SERVER_OPT_REQ_HEADER_SIZE_MAX,
	// uint64_t (ms): Maximum time to keep a TCP connection alive.
	CERVE_HTTP_SERVER_OPT_KEEPALIVE_TIMEOUT_MS,
	// unsigned int: Maximum number of concurrent connections. Idle
	// connections will be dropped if needed. If none can be dropped,
	// 503 will be returned.
	CERVE_HTTP_SERVER_OPT_CONNECTIONS_MAX,
	// unsigned int: Maximum number of connections in the socket's listen queue.
	CERVE_HTTP_SERVER_OPT_SOCKET_BACKLOG,
};

int cerve_http_server_setopt(struct cerve_http_server *s,
			     enum cerve_http_server_opt opt, const void *val,
			     size_t val_len);
int cerve_http_server_getopt(struct cerve_http_server *s,
			     enum cerve_http_server_opt opt, const void *val,
			     size_t val_len);

#endif /* CERVE_HTTP_H */
