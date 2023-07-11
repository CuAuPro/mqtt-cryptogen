import logging
from logging import Handler, LogRecord, Formatter, FileHandler
import datetime


# create formatter
FORMATTER = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')



class StdOutHandler(Handler):
    """Class for standard input and output handler (terminal print)
    """
    def emit(self, record: LogRecord) -> None:
        # Only print infos, warnings and errors to stdout.
        if record.levelno > logging.DEBUG:
            print(FORMATTER.format(record))

class FileHandlerCustom(FileHandler):
    """Class for file handler (file)
    """
    def __init__(self, name):
        super().__init__(name)

    def emit(self, record: LogRecord) -> None:
        # Only print infos, warnings and errors to stdout.
        if record.levelno > logging.DEBUG:
            record.msg = FORMATTER.format(record)
            FileHandler.emit(self, record)

def init_logger(logging_level: int = logging.DEBUG,
                print_to_stdout: bool = True, log_in_file: bool = False):
    """This function adds custom handlers to the root logger to send logging info to our graylog server at the specified ip
    and send slack messages to error_log channel if desired.

    Args:
        logging_level (int, optional): _description_. Defaults to logging.DEBUG.
    for the graylog server is used.. Defaults to False.
        print_to_stdout (bool, optional): Set to true if logging is also written to the standard output. Defaults to True.
        log_in_file (bool, optional): Set to true if logging is also written to the file. Defaults to False.
    Examples:
    --------
    >>> import logging
    >>> from logger import init_logger
    >>> init_logger(logging.DEBUG, print_to_stdout=False, log_in_file=True)
    >>> logging.info('Write log info')
    >>> logging.error('Write log error')
    >>> logging.warning('Write log warning')
    >>> logging.debug('Write log debug')
    """
    
    # If no name is provided we will add handlers to the root logger, which is Best practice imho
    root_logger = logging.getLogger()
    root_logger.setLevel(logging_level)
    # Clear handlers before adding new handlers
    root_logger.handlers.clear()

    # Set up handler for standard output
    if print_to_stdout:
        standard_handler = StdOutHandler()
        root_logger.addHandler(standard_handler)
    
    if log_in_file:
        file_handler = FileHandlerCustom("log/log"+datetime.datetime.today().strftime('%Y%m%d')+".log")
        root_logger.addHandler(file_handler)