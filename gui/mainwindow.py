import os

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from filemanager import *

class MainWindow(QMainWindow):
    '''
        Main window
            Input - File

    '''
    def __init__(self,*args,**kwargs):
        super(MainWindow, self).__init__()
        self.setWindowTitle('SCOPE')
        self.setWindowIcon(QIcon("gui/img/scope.png"))
        self.setGeometry(50,50,1000,875)
        self.setStyleSheet("background: #262626; color: white")
        self.setAcceptDrops(True)

        self.threadpool = QThreadPool()
        self.factory = FileFactory()

        ### DRAW FRAME ###
        masterWidget = QWidget()
        masterLayout = QVBoxLayout(masterWidget)

        thisLayout = QVBoxLayout()

        self.grid1w = QWidget()
        self.grid1w.setMinimumHeight(60)
        self.grid1w.setMaximumHeight(60)
        self.grid1l = QHBoxLayout(self.grid1w)

        grid2w = QWidget()
        self.grid2l = QHBoxLayout(grid2w)
        self.grid2l.setAlignment(Qt.AlignLeft)

        grid3w = QWidget()
        grid3w.setMinimumHeight(50)
        grid3w.setMaximumHeight(50)
        self.grid3l = QHBoxLayout(grid3w)

        thisLayout.addWidget(self.grid1w)
        thisLayout.addWidget(grid2w)
        thisLayout.addWidget(grid3w)

        masterLayout.addLayout(thisLayout)

        self.setCentralWidget(masterWidget)
        ### FILL FRAME ###
        self.draw_topbar()
        self.draw_sidebar()
        self.draw_filebar()

        self.show()

        if len(args) > 0:
            if os.path.isfile(args[0][0]):
                self.draw_update(args[0][0])
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self.draw_update(path)
        
    def openFileName(self):
        fileName, _ = QFileDialog.getOpenFileName(self,"Choose File..", "","All Files (*)")
        if fileName:
            self.draw_update(fileName)

    def draw_topbar(self):
        #### TOP BAR ####
        spacer = QWidget()
        spacer.setMinimumWidth(50)
        spacer.setMaximumWidth(50)

        grid1_1w = QWidget()
        grid1_1w.setStyleSheet("background: #333333;")   
        grid1_1l = QHBoxLayout(grid1_1w)

        b0 = QPushButton()
        b0.setToolTip("New File")
        b0.setIcon(QIcon("gui/img/newfile.png"))
        b0.setIconSize(QSize(75,75))
        b0.clicked.connect(self.openFileName)
        b0.setMinimumWidth(25)
        b0.setMaximumWidth(25)
        b0.setMinimumHeight(25)
        b0.setMaximumHeight(25)

        b1 = QPushButton()
        b1.setToolTip("Close All")
        b1.setIcon(QIcon("gui/img/exitall.png"))
        b1.setIconSize(QSize(50,50))
        b1.clicked.connect(self.close)
        b1.setMinimumWidth(25)
        b1.setMaximumWidth(25)
        b1.setMinimumHeight(25)
        b1.setMaximumHeight(25)

        b2 = QPushButton()
        b2.setToolTip("Hide All")
        b2.setIcon(QIcon("gui/img/hideall.png"))
        b2.setIconSize(QSize(50,50))
        b2.clicked.connect(self.hide)
        b2.setMinimumWidth(25)
        b2.setMaximumWidth(25)
        b2.setMinimumHeight(25)
        b2.setMaximumHeight(25)

        self.grid1l.addWidget(spacer)
        self.grid1l.addWidget(grid1_1w)

        grid1_1l.addStretch()
        grid1_1l.addWidget(b0)
        grid1_1l.addWidget(b2)
        grid1_1l.addWidget(b1)
    
    def draw_sidebar(self):
        #### SIDE BAR ####
        grid2_1w = QWidget()
        grid2_1w.setStyleSheet("background: #333333;")
        grid2_1w.setMinimumWidth(50)
        grid2_1w.setMaximumWidth(50)
        grid2_1l = QVBoxLayout(grid2_1w)
        grid2_1l.setAlignment(Qt.AlignTop)

        def static_action():
            if self.b1.isChecked():
                self.factory.show_static()
            else:
                self.factory.hide_static()

        def string_action():
            if self.b2.isChecked():
                self.factory.show_strings()
            else:
                self.factory.hide_strings()
        
        def hex_action():
            if self.b5.isChecked():
                self.factory.show_hex()
            else:
                self.factory.hide_hex()
        
        def functions_action():
            if self.b3.isChecked():
                self.factory.show_functions()
            else:
                self.factory.hide_functions()

        def sections_action():
            if self.b4.isChecked():
                self.factory.show_sections()
            else:
                self.factory.hide_sections()

        self.b1 = QPushButton()
        self.b1.setToolTip("Static")
        self.b1.setIcon(QIcon("gui/img/static.png"))
        self.b1.setIconSize(QSize(25,25))
        self.b1.setStyleSheet("QPushButton:checked { background-color: #0000e6 }")
        self.b1.setCheckable(True)
        self.b1.clicked.connect(static_action)
        self.b1.setMaximumHeight(50)
        self.b1.setMinimumHeight(50)

        self.b2 = QPushButton()
        self.b2.setToolTip("Strings")
        self.b2.setIcon(QIcon("gui/img/strings3.png"))
        self.b2.setIconSize(QSize(25,25))
        self.b2.setStyleSheet("QPushButton:checked { background-color: #0000e6 }")
        self.b2.setCheckable(True)
        self.b2.clicked.connect(string_action)
        self.b2.setMaximumHeight(50)
        self.b2.setMinimumHeight(50)

        self.b3 = QPushButton()
        self.b3.setToolTip("Imports / Exports")
        self.b3.setIcon(QIcon("gui/img/functions.png"))
        self.b3.setIconSize(QSize(25,25))
        self.b3.setStyleSheet("QPushButton:checked { background-color: #0000e6 }")
        self.b3.setCheckable(True)
        self.b3.clicked.connect(functions_action)
        self.b3.setMaximumHeight(50)
        self.b3.setMinimumHeight(50)

        self.b4 = QPushButton()
        self.b4.setToolTip("Sections")
        self.b4.setIcon(QIcon("gui/img/sections.png"))
        self.b4.setIconSize(QSize(25,25))
        self.b4.setStyleSheet("QPushButton:checked { background-color: #0000e6 }")
        self.b4.setCheckable(True)
        self.b4.clicked.connect(sections_action)
        self.b4.setMaximumHeight(50)
        self.b4.setMinimumHeight(50)

        self.b5 = QPushButton()
        self.b5.setToolTip("Hex")
        self.b5.setIcon(QIcon("gui/img/hex.png"))
        self.b5.setIconSize(QSize(25,25))
        self.b5.setStyleSheet("QPushButton:checked { background-color: #0000e6 }")
        self.b5.setCheckable(True)
        self.b5.clicked.connect(hex_action)
        self.b5.setMaximumHeight(50)
        self.b5.setMinimumHeight(50)

        
        grid2_1l.addWidget(self.b1)
        grid2_1l.addWidget(self.b2)
        grid2_1l.addWidget(self.b3)
        grid2_1l.addWidget(self.b4)
        grid2_1l.addWidget(self.b5)

        self.grid2l.addWidget(grid2_1w)
    
    def draw_filebar(self):
        #### FILE BAR ####
        grid3_1w = QWidget()
        grid3_1w.setMinimumWidth(50)
        grid3_1w.setMaximumWidth(50)
        self.grid3_1l = QHBoxLayout(grid3_1w)

        self.grid3l.addWidget(grid3_1w)
    
    def draw_update(self,filename):
        #### UPDATE FIELDS ####
        self.factory.add(FileManager(self, self.grid2l, self.grid3l, filename, self.factory.STATES))
    
    def exit_file(self, FileManager):
        self.factory.remove(FileManager)
    
    def hide(self):
        self.b1.setChecked(False)
        self.b2.setChecked(False)
        self.b3.setChecked(False)
        self.b4.setChecked(False)
        self.b5.setChecked(False)

        self.factory.hide_all()
    
    def close(self):
        self.b1.setChecked(False)
        self.b2.setChecked(False)
        self.b3.setChecked(False)
        self.b4.setChecked(False)
        self.b5.setChecked(False)
        
        self.factory.close_all()
    
    




