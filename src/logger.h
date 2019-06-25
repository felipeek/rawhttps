#ifndef RAWHTTP_LOGGER_H
#define RAWHTTP_LOGGER_H

typedef enum {
	LOGGER_LOG_LEVEL_DEBUG = 0,
	LOGGER_LOG_LEVEL_INFO = 1,
	LOGGER_LOG_LEVEL_WARNING = 2,
	LOGGER_LOG_LEVEL_ERROR = 3
} rawhttp_log_level;

void logger_level_set(rawhttp_log_level level);
void logger_log_debug(const char* format, ...);
void logger_log_info(const char* format, ...);
void logger_log_warning(const char* format, ...);
void logger_log_error(const char* format, ...);

#endif