import logging.config
import colorlog

def julia_fiesta_logs():
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{log_color}{levelname} {asctime} {filename}:{lineno} {module} {message}',
                'style': '{',
                'log_colors': {
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'bold_red',
                },
            },
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'colorlog.StreamHandler',
                'formatter': 'verbose',
            },
            'file': {
                'level': 'DEBUG',
                'class': 'logging.FileHandler',
                'filename': 'debug.log',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            '': {  # root logger
                'handlers': ['console', 'file'],
                'level': 'DEBUG',
                'propagate': True,
            },
        },
    }
    logging.config.dictConfig(logging_config)
