import os
import yara

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PIL import Image
from PIL.ImageQt import ImageQt

from gui.worker import *
from gui.scope import *

class DescriptionTabs(QTabWidget):
    def __init__(self):
        super(DescriptionTabs, self).__init__()
        self.ctab1 = QWidget()
        self.ctab2 = QWidget()
    
    def draw_vinfo(self):
        self.addTab(self.ctab1, "Version Info")
        ctab1l = QVBoxLayout(self.ctab1)
        
        self.vinfo = QTextEdit()
        self.vinfo.setReadOnly(True)
        ctab1l.addWidget(self.vinfo)
    
    def draw_siginfo(self):
        self.addTab(self.ctab2, "Signature")
        ctab2l = QVBoxLayout(self.ctab2)

        self.siginfo = QTextEdit()
        self.siginfo.setReadOnly(True)
        ctab2l.addWidget(self.siginfo)

    def remove_vinfo(self):
        self.removeTab(0)
    
    def remove_siginfo(self):
        self.removeTab(1)
    

class StaticWindow(QTabWidget):
    def __init__(self, mainwindow, states):
        super(StaticWindow, self).__init__()
        self.mw = mainwindow
        self.setMinimumWidth(25)

        if not states["static"]:
            self.hide()
        staticLayout = QVBoxLayout(self)

        self.tab1 = QScrollArea()
        self.tab1.setStyleSheet("font-size:12px;")
        self.addTab(self.tab1, 'Static')
        self.tab1.setWidgetResizable(True)

        staticw = QWidget()
        hashl = QVBoxLayout(staticw)
        hashl.setAlignment(Qt.AlignTop)
        hashl.setSpacing(0)

        md5w = QWidget()
        md5lay = QHBoxLayout(md5w)
        md5l = QLabel("MD5\t")
        self.md5 = QLineEdit()
        self.md5.setReadOnly(True)
        self.md5.setStyleSheet("border: 0px;")
        self.md5.setMaximumWidth(500)
        self.md5.setMinimumWidth(500)
        md5lay.addWidget(md5l)
        md5lay.addWidget(self.md5)
        md5lay.addStretch()

        sha1w = QWidget()
        sha1lay = QHBoxLayout(sha1w)
        sha1l = QLabel("SHA1\t")
        self.sha1 = QLineEdit()
        self.sha1.setReadOnly(True)
        self.sha1.setStyleSheet("border: 0px;")
        self.sha1.setMaximumWidth(500)
        self.sha1.setMinimumWidth(500)
        sha1lay.addWidget(sha1l)
        sha1lay.addWidget(self.sha1)
        sha1lay.addStretch()

        sha256w = QWidget()
        sha256lay = QHBoxLayout(sha256w)
        sha256l = QLabel("SHA256\t")
        self.sha256 = QLineEdit()
        self.sha256.setReadOnly(True)
        self.sha256.setStyleSheet("border: 0px;")
        self.sha256.setMaximumWidth(700)
        self.sha256.setMinimumWidth(700)
        sha256lay.addWidget(sha256l)
        sha256lay.addWidget(self.sha256)
        sha256lay.addStretch()

        ssdw = QWidget()
        ssdlay = QHBoxLayout(ssdw)
        ssdl = QLabel("SSDeep\t")
        self.ssd = QLineEdit()
        self.ssd.setReadOnly(True)
        self.ssd.setStyleSheet("border: 0px;")
        self.ssd.setMaximumWidth(700)
        self.ssd.setMinimumWidth(700)
        ssdlay.addWidget(ssdl)
        ssdlay.addWidget(self.ssd)
        ssdlay.addStretch()

        magicw = QWidget()
        magiclay = QHBoxLayout(magicw)
        magicl = QLabel("Magic\t")
        self.magic = QLineEdit()
        self.magic.setReadOnly(True)
        self.magic.setStyleSheet("border: 0px;")
        self.magic.setMaximumWidth(700)
        self.magic.setMinimumWidth(700)
        magiclay.addWidget(magicl)
        magiclay.addWidget(self.magic)
        magiclay.addStretch()

        self.desc = DescriptionTabs()

        hashl.addWidget(md5w)
        hashl.addWidget(sha1w)
        hashl.addWidget(sha256w)
        hashl.addWidget(ssdw)
        hashl.addWidget(magicw)
        hashl.addStretch()
        hashl.addWidget(self.desc)
        
        self.tab1.setWidget(staticw)

        self.tab2 = QScrollArea()
        self.tab2.setStyleSheet("font-size:12px;")
        self.addTab(self.tab2, 'Yara')
        self.tab2.setWidgetResizable(True)

        yaraw = QWidget()
        yaral = QVBoxLayout(yaraw)
        yaral.setAlignment(Qt.AlignTop)
        yaral.setSpacing(0)

        peidw = QWidget()
        peidlay = QVBoxLayout(peidw)
        self.peid = QTextEdit()
        self.peid.setReadOnly(True)
        self.peid.setStyleSheet("border: 0px;")
        self.peid.setMaximumWidth(500)
        self.peid.setMinimumWidth(500)
        peidlay.addWidget(self.peid)

        yaral.addWidget(peidw)

        self.tab2.setWidget(yaraw)


    def update(self, output):
        if output["md5"]:
            self.md5.setText(output["md5"])
        if output["sha1"]:
            self.sha1.setText(output["sha1"])
        if output["sha256"]:
            self.sha256.setText(output["sha256"])
        if output["ssdeep"]:
            self.ssd.setText(output["ssdeep"])
        if output["magic"]:
            self.magic.setText(output["magic"])
    
    def update_vinfo(self,output):
        if output:
            self.desc.draw_vinfo()
            self.desc.vinfo.setText(output)
    
    def update_siginfo(self,output):
        if output:
            self.desc.draw_siginfo()
            self.desc.siginfo.setText(output[0].readable())
    
    def task(self, filename):
        self.filename=filename
        if self.filename:
            self.update({"md5":"", "sha1":"", "sha256":"", "ssdeep":"", "magic":""})
            worker = Worker(self.start)
            worker.signals.RESULT.connect(self._output)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
    
    def yara_task(self, filename):
        self.filename=filename
        if self.filename:
            worker = Worker(self.start_yara)
            worker.signals.RESULT.connect(self.yara_output)
            worker.signals.FINISHED.connect(self.yara_complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
        
    def _output(self, output):
        self.hashes = output
        output["magic"] = get_file_magic(self.filename)
        self.update(output)
    
    def yara_output(self, output):
        if output:
            self.peid.setText("\n".join(output))

    def _complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed Static')
    
    def yara_complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed Yara')
    
    def _error(self,s):
        print(str(s))
    
    def start(self, progress_callback):
        progress_callback.emit(1)
        output = get_hashes(self.filename)
        return output
    
    def start_yara(self, progress_callback):
        progress_callback.emit(1)
        output = yara_scan(self.filename)
        return output
    
    def vinfo_task(self, filename):
        self.filename=filename
        self.desc.remove_vinfo()
        if self.filename:
            worker = Worker(self.start_vinfo)
            worker.signals.RESULT.connect(self.update_vinfo)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
    
    def start_vinfo(self, progress_callback):
        progress_callback.emit(1)
        output = get_stringtable(self.filename)
        return output
    
    def siginfo_task(self, filename):
        self.filename=filename
        self.desc.remove_siginfo()
        if self.filename:
            worker = Worker(self.start_siginfo)
            worker.signals.RESULT.connect(self.update_siginfo)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
    
    def start_siginfo(self, progress_callback):
        progress_callback.emit(1)
        try:
            pe = pefile.PE(self.filename, fast_load=True)
        except:
            return None
        output = get_dsig(pe)
        return output

class StringsWindow(QTabWidget):
    def __init__(self, mainwindow, states):
        super(StringsWindow, self).__init__()
        self.mw = mainwindow
        self.strings = None
        self.urls = None

        if not states["strings"]:
            self.hide()

        self.tab1 = QScrollArea()
        self.tab1.setWidgetResizable(True)
        self.tab1.setStyleSheet("font-size:12px;")
        self.addTab(self.tab1, "Strings")

        tab1w = QWidget()
        tab1Layout = QVBoxLayout(tab1w)

        filterbar = QWidget()
        filterLayout = QHBoxLayout(filterbar)

        label = QLabel("Filter")
        self.filter = QLineEdit()
        self.filter.setStyleSheet("background: #333333;")
        self.filter.textChanged.connect(self.filter_strings)
        filterLayout.addWidget(label)
        filterLayout.addWidget(self.filter)

        self.edit = QPlainTextEdit()
        self.edit.setStyleSheet("background: #333333;")
        self.edit.setReadOnly(True)
        self.edit.setMinimumWidth(550)

        tab1Layout.addWidget(filterbar)
        tab1Layout.addWidget(self.edit)

        self.tab1.setWidget(tab1w)

        self.tab2 = QScrollArea()
        self.tab2.setWidgetResizable(True)
        self.tab2.setStyleSheet("font-size:12px;")
        self.addTab(self.tab2, "Urls")
        tab2w = QWidget()
        tab2Layout = QVBoxLayout(tab2w)

        filterbar2 = QWidget()
        filterLayout2 = QHBoxLayout(filterbar2)

        label2 = QLabel("Filter")
        self.filter2 = QLineEdit()
        self.filter2.setStyleSheet("background: #333333;")
        self.filter2.textChanged.connect(self.filter_urls)
        filterLayout2.addWidget(label2)
        filterLayout2.addWidget(self.filter2)

        self.edit2 = QPlainTextEdit()
        self.edit2.setStyleSheet("background: #333333;")
        self.edit2.setReadOnly(True)
        self.edit2.setMinimumWidth(450)

        tab2Layout.addWidget(filterbar2)
        tab2Layout.addWidget(self.edit2)

        self.tab2.setWidget(tab2w)

        self.tab3 = QScrollArea()
        self.tab3.setWidgetResizable(True)
        self.addTab(self.tab3, "Visual")
        
    
    def visual_task(self, filename):
        tab3w = QWidget()
        tab3w.setMinimumWidth(400)
        tab3layout = QHBoxLayout(tab3w)
        img = None

        with open(filename, 'rb') as fin:
            data = fin.read()

        try:
            img = Image.frombytes("L", (384,len(data)//384), data)
        except:
            return None

        imgq = ImageQt(img)
        qimg = QImage(imgq)

        pm =  QPixmap(qimg)
        lbl = QLabel()
        lbl.setPixmap(pm)

        tab3layout.addWidget(lbl)
        
        self.tab3.setWidget(tab3w)

    def update(self, output):
        if "strings" in output:
            if output["strings"]:
                self.edit.setPlainText('\n'.join(output["strings"]))
        if "urls" in output:
            if output["urls"]:
                self.edit2.setPlainText('\n'.join(output["urls"]))
    
    def get_strings(self):
        return self.strings

    def task(self, filename):
        self.filename=filename
        if self.filename:
            self.update("")
            worker = Worker(self.start)
            worker.signals.RESULT.connect(self._output)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
        
    def _output(self, output):
        self.strings = output["strings"]
        self.urls = output["urls"]
        self.update(output)

    def _complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed Strings')
    
    def _error(self,s):
        print(str(s))
    
    def start(self, progress_callback):
        progress_callback.emit(1)
        output = get_strings(self.filename)
        return output

    def filter_strings(self):
        search = self.filter.text()
        if search:
            res = [s for s in self.strings if search in s]
            self.update({"strings": res})
        else:
            self.update({"strings": self.strings})
    
    def filter_urls(self):
        search = self.filter2.text()
        if search:
            res = [s for s in self.urls if search in s]
            self.update({"urls": res})
        else:
            self.update({"urls": self.urls})

class HexWindow(QWidget):
    def __init__(self, mainwindow, states):
        super(HexWindow, self).__init__()
        self.mw = mainwindow
        self.hex = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        if not states["hex"]:
            self.hide()
        layout = QVBoxLayout(self)

        self.edit = QPlainTextEdit()
        self.edit.setStyleSheet("font-family:Courier;background: #333333; font-size: 12px;")
        self.edit.setReadOnly(True)
        self.edit.setMinimumWidth(600)

        scroll.setWidget(self.edit)
        layout.addWidget(scroll)

    def update(self, output):
        self.edit.setPlainText(output)
    
    def get_hex(self):
        return self.hex

    def task(self, filename):
        self.filename= filename
        if filename:
            self.update("")
            worker = Worker(self.start)
            worker.signals.RESULT.connect(self._output)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
        
    def _output(self, output):
        self.hex = output
        self.update('\n'.join(output))

    def _complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed Hex')
    
    def _error(self,s):
        print(str(s))
    
    def start(self, progress_callback):
        progress_callback.emit(1)
        output = get_hex(self.filename)
        return output

class FunctionsWindow(QTabWidget):
    def __init__(self, mainwindow, states):
        super(FunctionsWindow, self).__init__()
        self.mw = mainwindow
        self.imports = None

        if not states["functions"]:
            self.hide()

        self.tab1 = QWidget()
        self.addTab(self.tab1, 'Imports')

        filterbar = QWidget()
        filterLayout = QHBoxLayout(filterbar)

        label = QLabel("Filter")
        self.ifilter = QLineEdit()
        self.ifilter.setStyleSheet("background: #333333;")
        self.ifilter.textChanged.connect(self.filter_imports)
        filterLayout.addWidget(label)
        filterLayout.addWidget(self.ifilter)

        tab1Layout = QVBoxLayout(self.tab1)
        self.iedit = QTextBrowser()
        self.iedit.setStyleSheet("background: #333333;")
        self.iedit.setReadOnly(True)
        self.iedit.setOpenExternalLinks(True)

        tab1Layout.addWidget(filterbar)
        tab1Layout.addWidget(self.iedit)

        self.tab2 = QWidget()
        self.addTab(self.tab2, 'Exports')

        filterbar2 = QWidget()
        filterLayout2 = QHBoxLayout(filterbar2)

        label2 = QLabel("Filter")
        self.efilter = QLineEdit()
        self.efilter.setStyleSheet("background: #333333;")
        self.efilter.textChanged.connect(self.filter_exports)
        filterLayout2.addWidget(label2)
        filterLayout2.addWidget(self.efilter)

        tab2Layout = QVBoxLayout(self.tab2)
        self.eedit = QPlainTextEdit()
        self.eedit.setStyleSheet("background: #333333;")
        self.eedit.setReadOnly(True)

        tab2Layout.addWidget(filterbar2)
        tab2Layout.addWidget(self.eedit)
    
    def update_imports(self, output):
        if output:
            for imp in output:
                li = self.imp.link_imports(imp)
                self.iedit.append(li)
        self.iedit.moveCursor(QTextCursor.Start)
    
    def update_exports(self, output):
        self.eedit.setPlainText(output)
    
    def import_task(self, filename):
        self.filename= filename
        if filename:
            self.update_imports("")
            worker = Worker(self.istart)
            worker.signals.RESULT.connect(self.ioutput)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
        
    def ioutput(self, output):
        self.imports = output
        if output:
            self.update_imports(self.imports)

    def _complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed')
    
    def _error(self,s):
        print(str(s))
    
    def istart(self, progress_callback):
        progress_callback.emit(1)
        self.imp = Imports()
        output = self.imp.get_imports(self.filename)
        return output

    def export_task(self, filename):
        self.filename= filename
        if filename:
            self.update_exports("")
            worker = Worker(self.estart)
            worker.signals.RESULT.connect(self.eoutput)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)

    def eoutput(self, output):
        self.exports = output
        if output:
            self.update_exports('\n'.join(output))
    
    def estart(self, progress_callback):
        progress_callback.emit(1)
        output = get_exports(self.filename)
        return output
    
    def filter_imports(self):
        search = self.ifilter.text()
        self.iedit.clear()
        if search:
            res = [s for s in self.imports if search in s]
        else:
            res = self.imports
        self.update_imports(res)
    
    def filter_exports(self, search):
        if search:
            res = [s for s in self.exports if search in s]
        else:
            res = self.exports
        self.update_exports('\n'.join(res))
    
    def get_imports(self):
        return self.imports
    
    def get_exports(self):
        return self.exports

class SectionsWindow(QWidget):
    def __init__(self, mainwindow, states):
        super(SectionsWindow, self).__init__()
        self.mw = mainwindow
        self.hex = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        if not states["sections"]:
            self.hide()
        layout = QVBoxLayout(self)

        self.edit = QTextBrowser()
        self.edit.setStyleSheet("font-family:Courier;background: #333333; font-size: 12px;")
        self.edit.setReadOnly(True)
        self.edit.setMinimumWidth(840)

        scroll.setWidget(self.edit)
        layout.addWidget(scroll)

    def update(self, output):
        for i, line in enumerate(output):
            if i > 2:
                if "EXECUTE" in line:
                    self.edit.append('<pre style="color:red;font-family:Courier;">{}</pre>'.format(line))
                    self.edit.append(' ')
                else:
                    self.edit.append(line)
            else:
                self.edit.append(line)
    
    def task(self, filename):
        self.filename= filename
        try:
            self.pe = pefile.PE(self.filename, fast_load=True)
        except:
            return None
        if filename and self.pe:
            self.update("")
            worker = Worker(self.start)
            worker.signals.RESULT.connect(self._output)
            worker.signals.FINISHED.connect(self._complete)
            worker.signals.ERROR.connect(self._error)

            self.mw.threadpool.start(worker)
        
    def _output(self, output):
        self.sections = output
        self.update(output)

    def _complete(self):
        #self.tabs.progress+=1
        #self.tabs.tab1ui.progressBar.setValue(self.tabs.progress)
        print('Completed Sections')
    
    def _error(self,s):
        print(str(s))
    
    def start(self, progress_callback):
        progress_callback.emit(1)
        output = get_sections(self.pe)
        return output
