#include "logger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "util.h"

static rawhttps_log_level log_level = RAWHTTPS_LOG_LEVEL_DISABLED;
static pthread_mutex_t log_mutex;

static const char color_reset[]   = "\x1B[0m";
static const char color_red[]     = "\x1B[31m";
static const char color_yellow[]  = "\x1B[33m";
static const char color_cyan[]    = "\x1B[36m";
static const char color_white[]   = "\x1B[37m";

void rawhttps_logger_init(rawhttps_log_level level)
{
	pthread_mutex_init(&log_mutex, NULL);
	log_level = level;
}

static void logger_log_out(FILE* target, const char* level, const char* format, va_list argptr)
{
	if (log_level == RAWHTTPS_LOG_LEVEL_DISABLED) return;

#ifdef __APPLE__
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);  // MacOS way of getting thread id
	pid_t pid = (pid_t)tid;
#else
	pid_t pid = syscall(__NR_gettid);
#endif
	size_t needed = snprintf(NULL, 0, "[%s]\t[%d]\t%s\n", level, pid, format) + 1;
	char* buf = malloc(needed);
	sprintf(buf, "[%s]\t[%d]\t%s\n", level, pid, format);
	pthread_mutex_lock(&log_mutex);
	vfprintf(target, buf, argptr);
	pthread_mutex_unlock(&log_mutex);
	free(buf);
}

void rawhttps_logger_log(rawhttps_log_level log_level, const char* msg)
{
	switch (log_level)
	{
		case RAWHTTPS_LOG_LEVEL_DEBUG: {
			rawhttps_logger_log_debug(msg);
		} break;
		case RAWHTTPS_LOG_LEVEL_INFO: {
			rawhttps_logger_log_info(msg);
		} break;
		case RAWHTTPS_LOG_LEVEL_WARNING: {
			rawhttps_logger_log_warning(msg);
		} break;
		case RAWHTTPS_LOG_LEVEL_ERROR: {
			rawhttps_logger_log_error(msg);
		} break;
		case RAWHTTPS_LOG_LEVEL_DISABLED: {
			return;
		} break;
	}
}

void rawhttps_logger_log_debug(const char* format, ...)
{
    if (log_level > RAWHTTPS_LOG_LEVEL_DEBUG) return;
    va_list argptr;
    va_start(argptr, format);
	char debug[256];
	sprintf(debug, "%sDEBUG%s", color_cyan, color_reset);
    logger_log_out(stdout, debug, format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_info(const char* format, ...)
{
    if (log_level > RAWHTTPS_LOG_LEVEL_INFO) return;
    va_list argptr;
    va_start(argptr, format);
	char info[256];
	sprintf(info, "%sINFO%s", color_white, color_reset);
    logger_log_out(stdout, info, format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_warning(const char* format, ...)
{
    if (log_level > RAWHTTPS_LOG_LEVEL_WARNING) return;
    va_list argptr;
    va_start(argptr, format);
	char warning[256];
	sprintf(warning, "%sWARNING%s", color_yellow, color_reset);
    logger_log_out(stderr, warning, format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_error(const char* format, ...)
{
    if (log_level > RAWHTTPS_LOG_LEVEL_ERROR) return;
    va_list argptr;
    va_start(argptr, format);
	char error[256];
	sprintf(error, "%sERROR%s", color_red, color_reset);
    logger_log_out(stderr, error, format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_hex(rawhttps_log_level level, const char* msg, const unsigned char* data, int size)
{
	char aux[16];
	rawhttps_util_dynamic_buffer log_db;
	rawhttps_util_dynamic_buffer_new(&log_db, 1024);

	for (long long i = 0; i < size; ++i)
	{
		int s = sprintf(aux, "0x%02hhX ", data[i]);
		rawhttps_util_dynamic_buffer_add(&log_db, aux, s);
	}

	switch (level) {
		case RAWHTTPS_LOG_LEVEL_DEBUG: {
			rawhttps_logger_log_debug("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case RAWHTTPS_LOG_LEVEL_INFO: {
			rawhttps_logger_log_info("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case RAWHTTPS_LOG_LEVEL_WARNING: {
			rawhttps_logger_log_warning("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case RAWHTTPS_LOG_LEVEL_ERROR: {
			rawhttps_logger_log_error("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case RAWHTTPS_LOG_LEVEL_DISABLED: {
		} break;
	}
	rawhttps_util_dynamic_buffer_free(&log_db);
}

void rawhttps_logger_destroy()
{
	pthread_mutex_destroy(&log_mutex);
}
