from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import argparse
import gui.mainwindow as mainwindow

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='CylaSCOPE')
    parser.add_argument("FILE", nargs="?")
    args=parser.parse_args()

    app = QApplication([])
    app.setStyle(QStyleFactory.create("Fusion"))

    if args.FILE:
        window = mainwindow.MainWindow([args.FILE])
    else:
        window = mainwindow.MainWindow()

    app.exec_()