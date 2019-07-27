#ifndef RAWHTTPS_LOGGER_H
#define RAWHTTPS_LOGGER_H

typedef enum
{
    RAWHTTPS_LOG_LEVEL_DEBUG = 0,
    RAWHTTPS_LOG_LEVEL_INFO = 1,
    RAWHTTPS_LOG_LEVEL_WARNING = 2,
    RAWHTTPS_LOG_LEVEL_ERROR = 3
} rawhttps_log_level;

void rawhttps_logger_init(rawhttps_log_level level);
void rawhttps_logger_destroy();
void rawhttps_logger_log(rawhttps_log_level log_level, const char* msg);
void rawhttps_logger_log_debug(const char* format, ...);
void rawhttps_logger_log_info(const char* format, ...);
void rawhttps_logger_log_warning(const char* format, ...);
void rawhttps_logger_log_error(const char* format, ...);
void rawhttps_logger_log_hex(rawhttps_log_level level, const char* msg, const unsigned char* data, int size);
#endif