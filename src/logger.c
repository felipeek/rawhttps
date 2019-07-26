#include "logger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "util.h"

static enum Log_Level log_level = LOGGER_LOG_LEVEL_ERROR;
static pthread_mutex_t log_mutex;

void rawhttps_logger_init(enum Log_Level level)
{
	pthread_mutex_init(&log_mutex, NULL);
	log_level = level;
}

static void logger_log_out(FILE* target, const char* level, const char* format, va_list argptr)
{
    size_t needed = snprintf(NULL, 0, "[%s] %s\n", level, format) + 1;
    char* buf = malloc(needed);
    sprintf(buf, "[%s] %s\n", level, format);
    vfprintf(target, buf, argptr);
    free(buf);
}

void rawhttps_logger_log_debug(const char* format, ...)
{
    if (log_level > LOGGER_LOG_LEVEL_DEBUG) return;
    va_list argptr;
    va_start(argptr, format);
    logger_log_out(stdout, "DEBUG", format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_info(const char* format, ...)
{
    if (log_level > LOGGER_LOG_LEVEL_INFO) return;
    va_list argptr;
    va_start(argptr, format);
    logger_log_out(stdout, "INFO", format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_warning(const char* format, ...)
{
    if (log_level > LOGGER_LOG_LEVEL_WARNING) return;
    va_list argptr;
    va_start(argptr, format);
    logger_log_out(stderr, "WARNING", format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_error(const char* format, ...)
{
    if (log_level > LOGGER_LOG_LEVEL_ERROR) return;
    va_list argptr;
    va_start(argptr, format);
    logger_log_out(stderr, "ERROR", format, argptr);
    va_end(argptr);
}

void rawhttps_logger_log_hex(enum Log_Level level, const char* msg, const unsigned char* data, int size)
{
	char aux[16];
	dynamic_buffer log_db;
	util_dynamic_buffer_new(&log_db, 1024);

	for (long long i = 0; i < size; ++i)
	{
		int s = sprintf(aux, "0x%02hhX ", data[i]);
		util_dynamic_buffer_add(&log_db, aux, s);
	}

	switch (level) {
		case LOGGER_LOG_LEVEL_DEBUG: {
			rawhttps_logger_log_debug("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case LOGGER_LOG_LEVEL_INFO: {
			rawhttps_logger_log_info("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case LOGGER_LOG_LEVEL_WARNING: {
			rawhttps_logger_log_warning("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
		case LOGGER_LOG_LEVEL_ERROR: {
			rawhttps_logger_log_error("%s: %.*s", msg, (int)log_db.size, log_db.buffer);
		} break;
	}
	util_dynamic_buffer_free(&log_db);
}

void rawhttps_logger_destroy()
{
	pthread_mutex_destroy(&log_mutex);
}