import sys, os, signal
import osquery
import time
import json
import signal
import psutil

from datetime import datetime
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog, QLabel, QTreeWidget, QTreeWidgetItem, QTextEdit,QMessageBox
from PyQt5.QtGui import QIcon,QPixmap, QImage
from apscheduler.schedulers.background import BackgroundScheduler

# import pypiwin32
global osquery_instance, white_list, col_list_id, col_list_name 

def handler(signum, frame):
    print('Signal handler called with signal', signum)
    return signal.SIGKILL

def validate_process():    
    print(" inside validate_process")
    osquery_RESULTS = osquery_instance.client.query("select data from windows_events")
    if osquery_RESULTS.status.code != 0:
        print("Error running the query: %s" % osquery_RESULTS.status.message)
        sys.exit(1)
    for row in osquery_RESULTS.response:
        EventData = row.get('data',None)
        json_EventData = json.loads(EventData)
        i=0
        while i<2:
            try :
                process_name = json_EventData['EventData'][col_list_name[i]]
                pid = json_EventData['EventData'][col_list_id[i]]
                pid_int = int(pid,16)
                # if process_name == "C:\ProgramData\osquery\osqueryd\osqueryd.exe":
                if process_name not in white_list:
                    print(" %s-%s Process not in whitelist.\nProcess to be terminated" %(process_name,pid_int))
                    # try :
                    #     p = psutil.Process(pid_int)
                    #     if psutil.pid_exists(pid_int) :
                    #         if p.is_running() == True:                    
                    #             # os.kill(pid_int,signal.SIGTERM )
                    #             p.kill()
                    #             print("%s killed / Terminated "%(pid_int))
                    # except (psutil.AccessDenied):
                    #     pass
                    # except (psutil.NoSuchProcess):
                    #     pass
                else :
                    print(" %s - %s Process  in whitelist.\n" %(process_name,pid_int))
                i=2
            except KeyError:
                i=i+1                
                pass

def insert_processec_details():
    osquery_RESULTS = osquery_instance.client.query("select pid,name,uid,parent,start_time,path,cmdline from processes")
    if osquery_RESULTS.status.code != 0:
        print("Error running the query: %s" % osquery_RESULTS.status.message)
        sys.exit(1)
    items = []
    for row in osquery_RESULTS.response:    
        val_items = []
        val_items.append(row.get('pid',None))
        val_items.append(row.get('name',None))
        val_items.append(row.get('uid',None))            
        val_items.append(row.get('parent',None))            
        val_items.append(row.get('path',None))
        val_items.append(row.get('cmdline',None))            
        timestamp = int(row.get('start_time',None))            
        if timestamp>0 :
            val_items.append(datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"))
        else:
            val_items.append("")
        items.append(QTreeWidgetItem(None,val_items ))
    return items

class list_window(QWidget):    
    def __init__(self):
        super().__init__()        
        self.initUI()        
        
    def initUI(self): 
        self.ui = uic.loadUi("window.ui")
        self.setGeometry(300, 300, 300, 220)
        self.ui.btnAdd.clicked.connect(self.btnAddClicked)
        self.ui.btnEdit.clicked.connect(self.btnEditClicked)
        self.ui.btnDelete.clicked.connect(self.btnDeleteClicked)
        self.ui.btnBrowse.clicked.connect(self.btnBrowseClicked)
        ret_items = insert_processec_details()
        self.ui.treeWidget.addTopLevelItems(ret_items)
        self.ui.show()
        
    def btnBrowseClicked(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(None,"Select File", "","Excuitable Files (*.exe)", options=options)
        if fileName:
            self.ui.le_Path.setText(fileName)
    
    def btnAddClicked(self):        
        exe_path = self.ui.le_Path.toPlainText()
        exe_name = self.ui.le_Name.toPlainText()
        print("Add Clicked %s - %s" % (exe_name,exe_path))
        if len(exe_name) == 0 :#or exe_path.empty():            
            QMessageBox.information(self,"Message","Name cannot be empty", buttons = QMessageBox.Ok, defaultButton = QMessageBox.NoButton)
            return
        if len(exe_path) == 0:# or exe_path.empty():            
            QMessageBox.information(self,"Message","Path cannot be empty", buttons = QMessageBox.Ok, defaultButton = QMessageBox.NoButton)
            return
        

    def btnEditClicked(self):
        print("Edit Clicked")

    def btnDeleteClicked(self):
        print("Delete Clicked")

if __name__ == "__main__":
    white_list = ['C:\\WINDOWS\\system32\\NOTEPAD.EXE','C:\Windows\System32\audiodg.exe','C:\\Windows\\System32\\svchost.exe']
    col_list_id = ['ProcessId','NewProcessId','CallerProcessId']
    col_list_name = ['ProcessName','NewProcessName','CallerProcessName']
    osquery_instance = osquery.SpawnInstance()
    osquery_instance.open()  # This may raise an exception    

    scheduler = BackgroundScheduler()
    scheduler.add_job(validate_process, 'interval', seconds=15)
    scheduler.start()

    app = QtWidgets.QApplication([])
    application = list_window()
    # application.show()
    # del osquery_instance
    sys.exit(app.exec())

