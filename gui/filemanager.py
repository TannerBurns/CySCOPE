from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from windows import *

class FileFactory:
    def __init__(self):
        self.files = []
        self.STATES = {"static": False, "strings": False, "functions": False,  "sections": False, "hex": False}

    def add(self, FileManager):
        self.files.append(FileManager)
    
    def remove(self, FileManager):
        self.files.remove(FileManager)
        FileManager.destroy()
    
    def show_static(self):
        self.STATES["static"] = True
        for f in self.files:
            f.static.show()
    
    def hide_static(self):
        self.STATES["static"] = False
        for f in self.files:
            f.static.hide()
    
    def show_strings(self):
        self.STATES["strings"] = True
        for f in self.files:
            f.strings.show()
    
    def hide_strings(self):
        self.STATES["strings"] = False
        for f in self.files:
            f.strings.hide()
    
    def show_hex(self):
        self.STATES["hex"] = True
        for f in self.files:
            f.hex.show()
    
    def hide_hex(self):
        self.STATES["hex"] = False
        for f in self.files:
            f.hex.hide()
    
    def show_functions(self):
        self.STATES["functions"] = True
        for f in self.files:
            f.functions.show()
    
    def hide_functions(self):
        self.STATES["functions"] = False
        for f in self.files:
            f.functions.hide()
    
    def show_sections(self):
        self.STATES["sections"] = True
        for f in self.files:
            f.sections.show()
    
    def hide_sections(self):
        self.STATES["sections"] = False
        for f in self.files:
            f.sections.hide()

    
    def hide_all(self):
        self.hide_strings()
        self.hide_static()
        self.hide_hex()
        self.hide_functions()
        self.hide_sections()
    
    def close_all(self):
        for f in self.files:
            f.destroy()
        del self.files[:]
        self.STATES = {"static": False, "strings": False, "functions": False, "sections": False, "hex": False}


class FileManager:
    def __init__(self,master, window, filebar, filename, states):
        self.master = master
        self.window = window
        self.filebar = filebar
        self.filename = filename
        self.fileTab()
        self.draw_windows(states)
        self.update_windows()
    
    def draw_windows(self, states):
        self.static = StaticWindow(self.master, states)
        self.window.addWidget(self.static)

        self.strings = StringsWindow(self.master, states)
        self.window.addWidget(self.strings)

        self.functions = FunctionsWindow(self.master, states)
        self.window.addWidget(self.functions)

        self.sections = SectionsWindow(self.master, states)
        self.window.addWidget(self.sections)

        self.hex = HexWindow(self.master, states)
        self.window.addWidget(self.hex)


    def update_windows(self): 
        self.static.task(self.filename)
        self.static.vinfo_task(self.filename)
        self.static.siginfo_task(self.filename)
        self.strings.task(self.filename)
        self.strings.visual_task(self.filename)
        self.hex.task(self.filename)
        self.functions.import_task(self.filename)
        self.functions.export_task(self.filename)
        self.sections.task(self.filename)
    
    def fileTab(self):
        def remove():
            self.master.exit_file(self)
        self.tab = QWidget()
        self.tab.setStyleSheet("background: #333333;")
        tabl = QHBoxLayout(self.tab)

        label = QLabel()
        label.setText(str(self.filename.split('/')[-1]))
        label.setMinimumWidth(25)
        button = QPushButton()
        button.setStyleSheet("border: 0px")
        button.setToolTip("Close")
        button.setIcon(QIcon("gui/img/close.png"))
        button.setIconSize(QSize(20,20))
        button.setMaximumWidth(18)
        button.setMinimumWidth(18)
        button.clicked.connect(remove)

        tabl.addWidget(label)
        tabl.addStretch()
        tabl.addWidget(button)

        self.filebar.addWidget(self.tab)
    
    def destroy(self):
        self.filebar.removeWidget(self.tab)
        self.tab.deleteLater()
        self.tab = None

        self.window.removeWidget(self.strings)
        self.strings.deleteLater()
        self.string = None
        self.window.removeWidget(self.static)
        self.static.deleteLater()
        self.static = None
        self.window.removeWidget(self.functions)
        self.functions.deleteLater()
        self.functions = None
        self.window.removeWidget(self.sections)
        self.sections.deleteLater()
        self.sections = None
        self.window.removeWidget(self.hex)
        self.hex.deleteLater()
        self.hex = None
        