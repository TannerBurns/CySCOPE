import traceback
import sys

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

class WorkerSignals(QObject):
    '''
        SIGNALS:
            FINISHED = None
            ERROR = dict {'excType':str,'value':str,'traceback':str}
            RESULT = object
            PROGRESS = int
    '''

    FINISHED = pyqtSignal()
    ERROR = pyqtSignal(dict)
    RESULT = pyqtSignal(object)
    PROGRESS = pyqtSignal(int)

class Worker(QRunnable):
    
    def __init__(self, _run, *args, **kwargs):
        super(Worker, self).__init__()
        self._run = _run
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        kwargs['progress_callback'] = self.signals.PROGRESS
    
    @pyqtSlot()
    def run(self):
        '''
            Run worker, send signals
        '''

        try:
            result=self._run(*self.args,**self.kwargs)
        except:
            traceback.print_exc()
            excType, value = sys.exc_info()[:2]
            self.signals.ERROR.emit({'excType':excType,'value':value,'traceback':traceback.format_exc()})
        else:
            self.signals.RESULT.emit(result)
        finally:
            self.signals.FINISHED.emit()
            