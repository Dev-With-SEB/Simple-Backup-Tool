# -*- coding: utf-8 -*-
from __future__ import print_function #print('replace same line', end='\r')
import io
import os
import re
import sys
import shutil
import inspect
import inspect
import datetime
import threading
import traceback
from .colorPrinter import Color, ColorPrinter

pattern = r"<ipython-input[^>]*>|<module>"

__version__ = 9




# logger_registry.py
_loggers = {}

def get_logger(*args, **kwargs):
    name = kwargs.get('name', 'Main')
    # if _loggers and 'Main' == name:
    #     first_key = next(iter(_loggers))
    #     return _loggers[first_key]  
    #           
    # if args or kwargs or name not in _loggers:
    #     _loggers[name] = logger(*args, **kwargs)

    if name in _loggers:
        return _loggers[name]
    else: return None


def set_logger(name, loggerObj):
    _loggers[name] = loggerObj
    return _loggers[name]


def _could_be_path(path_str):
    if not isinstance(path_str, str):
        return False, None
    path_str = path_str.strip()
    if not path_str:
        return False
    # pattern = r'^[a-zA-Z0-9_\-\.\\/:\s]+$'
    # # Allow drive letters, slashes, backslashes, dots, underscores, hyphens, and alphanumerics
    # pattern = r'^[a-zA-Z]:[\\/]|^[\\/]|[\w\-.\\/]+$'
    # return bool(re.match(pattern, path_str))
    # Accept typical path characters

    pattern = r'^[a-zA-Z0-9_\-\.\\/:\s]+$'
    if not re.match(pattern, path_str):
        return False, None

    # Guess type: file or directory
    _, ext = os.path.splitext(path_str)
    if ext:
        # return True, "file"
        return True, True
    else:
        # return True, "directory"
        return True, False
    

class getDeffClassNames:
    def getFrame(self):
        # Get the current stack and pick the 4th frame from the end (caller of caller)
        stack = traceback.extract_stack()
        if len(stack) < 3:
            return (None, None)
        frame_info = stack[-3]
        func_name = frame_info[2]

        # Use inspect to get the actual frame object
        frame = inspect.currentframe()
        try:
            outer_frames = inspect.getouterframes(frame)
            if len(outer_frames) >= 4:
                frame_obj = outer_frames[2][0]
                local_vars = frame_obj.f_locals
                if 'self' in local_vars:
                    cls_name = local_vars['self'].__class__.__name__
                elif 'cls' in local_vars:
                    cls_name = local_vars['cls'].__name__
                else:
                    cls_name = os.path.splitext(os.path.basename(frame_info[0]))[0]
            else:
                cls_name = os.path.splitext(os.path.basename(frame_info[0]))[0]
        finally:
            del frame  # Avoid reference cycles

        return (cls_name,func_name)


def getLogSize(logFile):
    file_stats = os.stat(logFile)
    file_Size = round(file_stats.st_size / (1024 * 1024), 1) # File Size in MegaBytes
    return file_Size


class logger(object):
    def __init__(self, *args, **kwargs):
        print('args: {}'.format(args), 'kwargs: {}'.format(kwargs) )
        """
        logger(logFile=None, logLvl=0)

        Originally designed to provide simple and reliable logging for Python 2.7 scripts packaged with PyInstaller,
        which often failed to log to file consistently. Over time, this class has evolved into a flexible and
        intelligent logging utility that adapts to various runtime environments.


        Parameters:
        ----------
        logFile : str, optional
            Path to the log file. If not provided, the logger will generate one based on the caller's module.
        logLvl : int, optional
            Logging verbosity level. Defaults to 0.

        Attributes:
        ----------
        logFile : str
            Full path to the log file.
        logLvl : int
            Logging level.
        logFileName : str
            Base name of the log file without extension.
        logFileDir : str
            Directory where logs are stored, named as <logFileName>_logs.
        lock : threading.Lock
            Thread lock for safe concurrent logging.
        warn : method
            Alias for the warning method.
        """

        self.logLvl=None 
        self.name = kwargs.get('name', 'main')
        self.logFile = kwargs.get('logFile', None)
        exePath=None


        if args:
            for arg in args:
                posiblPath, posblFile =  _could_be_path(arg)
                if posiblPath:
                    if posblFile and not self.logFile:
                        self.logFile = arg
                    elif os.path.exists(arg):
                        exePath=arg

                elif isinstance(arg, int):
                   self.logLvl=arg

        if self.logLvl is None:
            self.logLvl = kwargs.get('logLvl', 3)

        if self.logFile is None:
            # Try to get the caller's module info
            try:
                frame = inspect.stack()[1]
                module = inspect.getmodule(frame[0])
                if module and hasattr(module, '__file__'):
                    if not exePath:
                        exePath = os.path.dirname(os.path.abspath(module.__file__))
                    runningFileName = module.__name__ if hasattr(module, '__name__') else os.path.splitext(os.path.basename(module.__file__))[0]
                else:
                    raise Exception("Module info not available")
            except Exception:
                # Fallback logic
                try:
                    if not exePath:
                        exePath = os.path.dirname(sys.executable)
                    runningFileName = os.path.splitext(os.path.basename(sys.executable))[0]
                except Exception:
                    if not exePath:
                        exePath = os.path.dirname(os.path.abspath(__file__))
                    fullRunningFileName = os.path.basename(__file__)
                    runningFileName = os.path.splitext(fullRunningFileName)[0]

            # Construct default log file path
            self.logFile = os.path.join(exePath, '{}.log'.format(runningFileName))

        # Aliases and thread safety
        self.warn = self.warning
        self.lock = threading.Lock()

        # Setup log directory
        logFilePath = os.path.dirname(os.path.abspath(self.logFile))
        fullLogFileName = os.path.basename(self.logFile)
        self.logFileName = os.path.splitext(fullLogFileName)[0]

        self.logFileDir = os.path.join(logFilePath, '{}_logs'.format(self.logFileName))
        if not os.path.isdir(self.logFileDir):
            os.mkdir(self.logFileDir)

        self.color = Color()
        self.colorPrt = ColorPrinter()

        self.logColors = {
            4: self.color.BRIGHT_BLACK,
            3: self.color.WHITE,
            2: self.color.CYAN,
            1: self.color.YELLOW,
            0: self.color.RED
        }        


    def verbose(self, txt, **kwargs):
        """
        Parameters:
        ----------
        txt : str
            The message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_VERBOSE', args=('VERBOSE', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('VERBOSE', txt, prt)


    def debug(self, txt, **kwargs):
        """
        Parameters:
        ----------
        txt : str
            The message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_DEBUG', args=('DEBUG', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('DEBUG', txt, prt)


    def info(self, txt, **kwargs):
        """
        Parameters:
        ----------
        txt : str
            The message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_INFO', args=('INFO', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('INFO', txt, prt)


    def warning(self, txt, **kwargs):
        """
        Parameters:
        ----------
        txt : str
            The message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_WARNING', args=('WARNING', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('WARNING', txt, prt)


    def error(self, txt, **kwargs):
        """
        Parameters:
        ----------
        txt : str
            The message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_ERROR', args=('ERROR', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('ERROR', txt, prt)


    def critical(self, txt, **kwargs):
        """
        critical(txt, **kwargs)

        Logs a message with level 'CRITICAL'. The message is dispatched in a separate thread
        to avoid blocking execution.

        Parameters:
        ----------
        txt : str
            The critical message to be logged.
        multiFiles : bool, optional
            If True, forces the message to be written their own file based on the classname.
        toFile : bool, optional
            If True, forces the message to be written to a file regardless of log level.
        prt : bool, optional
            If True, forces the message to be printed to stdout regardless of log level
        """
        thread = threading.Thread(target=self._log, name='_log_CRITICAL', args=('CRITICAL', txt, getDeffClassNames().getFrame(), kwargs))
        # thread.daemon = True  # Set the thread as a daemon thread
        thread.start()
        # self._log('CRITICAL', txt, prt)


    def _log(self, *args, **kwargs):
        level_name, logTxt, frameInfo  = args[:3]
        logLevl = self._get_log_level(level_name)
        if self.logLvl >= logLevl or kwargs.get('prt',False) or kwargs.get('toFile',False):
            with self.lock:
                logTime = datetime.datetime.now()
                className, DefName = frameInfo

                if re.match(pattern, className): className = 'root'
                logTxt = self._logmsgIndenter(logTxt)

                # Print to file
                if self.logLvl >= self._get_log_level(level_name) or kwargs.get('toFile',False):
                    if self.logLvl >= 4 or kwargs.get('multiFiles',False):
                        logFileName = '{}.{}'.format(className, DefName)
                        saveMsg = '[{:<26}] [{:<8}]: {}\n'.format(str(logTime), level_name, logTxt)
                    else:
                        logFileName = self.logFileName
                        saveMsg = '[{:<26}] [{:<8}] {}.{}: {}\n'.format(str(logTime), level_name, className, DefName, logTxt)

                    self._rotate_logs(logFileName)
                    logFile = os.path.join(self.logFileDir,'{}.log'.format(logFileName))
                    try:
                        with io.open(logFile, 'a', encoding='utf-8') as f:
                            f.write(saveMsg.decode('utf-8') ) 
                    except:
                        with open(logFile, 'a+') as fp:
                            fp.write(saveMsg ) 

                # Terminal log printing
                if self.logLvl >= self._get_log_level(level_name) or kwargs.get('prt',False):
                    # stdOutMsg = '[{:<8}] {}.{}: {}\n'.format(level_name, className, DefName, logTxt)
                    # print(stdOutMsg , end='')
                    
                    # color and print LogLvl
                    self.colorPrt.println('[{:<8}] '.format(level_name), self.logColors[logLevl], bold=True, end="")
                    stdOutMsg = '{}.{}: {}\n'.format(className, DefName, logTxt)
                    #print log msg
                    print(stdOutMsg , end='')


        return


    def _get_log_level(self, level_name):
        levels = {
            'VERBOSE': 4,
            'DEBUG': 3,
            'INFO': 2,
            'WARNING': 1,
            'ERROR': 0,
            'CRITICAL': 0
        }
        return levels.get(level_name.upper(), 0)


    def _rotate_logs(self, logFileName):
        logExtNum = 4
        logFile = os.path.join(self.logFileDir,'{}.log'.format(logFileName))
        if os.path.isfile(logFile) and getLogSize(logFile) >= 5.0:
            while 0 <= logExtNum:
                tempLogExtNum = logExtNum + 1
                newTemplogFile = '{}/{}_{}.log'.format(self.logFileDir, logFileName, tempLogExtNum )

                if 0 == logExtNum:
                    oldTemplogFile = '{}/{}.log'.format(self.logFileDir, logFileName)
                else:
                    oldTemplogFile = '{}/{}_{}.log'.format(self.logFileDir, logFileName, logExtNum )

                if os.path.isfile(oldTemplogFile):
                    shutil.move(oldTemplogFile, newTemplogFile)

                logExtNum -= 1
        return


    def _logmsgIndenter(self, logMsg):
        msgSplit = str(logMsg).split('\n')
        msgLen = len(msgSplit)
        if msgLen >= 3:
            logMsg = ''
            indent = 4
            indent = ' ' * (indent)
            for count, line in enumerate(msgSplit):
                # if (count == 0 or count == msgLen-1) and line != '':
                    # logMsg += '{}\n'.format(line)
                if (count == 0 ) and line != '':
                    logMsg += '\n{}{}\n'.format(indent, line)
                else:
                    logMsg += '{}{}\n'.format(indent, line)
        return logMsg




if __name__ == "__main__":
    # # Example usage
    # log = logger(r'C:\Users\foobar\logfile.log', logLvl=2)
    log = set_logger('Main',logger(name='Main', logFile='C:\Users\foobar\logfile.log', logLvl=3))



    class fooclass:
        def foobar(self):
            log.info('This is an info message')
            log.debug('This is an info message')
            # log.error('This is an error message')
            log2 = get_logger(name='foobarD')
            log2.debug('This is an debug message with logger 2')

    fooclass().foobar()

    def foobar1():
        log.info('This is an info message')
        # log.error('This is an error message')

    foobar1()