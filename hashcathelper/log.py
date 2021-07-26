import logging

grey = "\x1b[38;21m"
yellow = "\x1b[33;21m"
green = "\x1b[32;21m"
red = "\x1b[31;21m"
bold_red = "\x1b[31;1m"
reset = "\x1b[0m"

# add success level
logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, 'SUCCESS')


def color_map(_format):
    FORMATS = {
        logging.DEBUG: grey + _format + reset,
        logging.INFO: _format,
        logging.WARNING: yellow + _format + reset,
        logging.ERROR: red + _format + reset,
        logging.CRITICAL: bold_red + _format + reset,
        logging.SUCCESS: green + _format + reset,
    }
    return FORMATS


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors"""

    fields = [
        #  '%(asctime)s',
        '%(levelname)s',
        '%(message)s'
    ]
    _format = ' - '.join(fields)

    FORMATS = color_map(_format)

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


class CustomFormatterDebug(CustomFormatter):
    fields = [
        '%(asctime)s',
        '%(filename)s:%(lineno)d',
        '%(levelname)s',
        '%(message)s'
    ]
    _format = ' - '.join(fields)
    FORMATS = color_map(_format)


def init_logging(loglevel=logging.WARNING, logfile=None):
    # create logger
    logger = logging.getLogger()
    logger.setLevel(loglevel)

    # add success level
    setattr(logger, 'success',
            lambda message, *args: logger._log(logging.SUCCESS, message, args))

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(loglevel)

    # create formatter and add it to the handlers
    if loglevel == logging.DEBUG:
        formatter = CustomFormatterDebug()
    else:
        formatter = CustomFormatter()
    ch.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(ch)

    if logfile:
        # create file handler which logs even debug messages
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
