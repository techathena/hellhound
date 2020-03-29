import sys, os, signal
import osquery
import time
import json
import signal
import psutil
import PyQt5.sip
from pathlib import Path

from datetime import datetime
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog, QLabel, QTreeWidget, QTreeWidgetItem, QTextEdit,QMessageBox
from PyQt5.QtGui import QIcon,QPixmap, QImage
from apscheduler.schedulers.background import BackgroundScheduler

# import pypiwin32
global osquery_instance, col_list_id, col_list_name, application
white_list_file_available = False 
white_list = []
latest_time_stamp = 0
selected_item = []

def validate_process():    
    global latest_time_stamp
    print("\n%s -"%(latest_time_stamp))
    print(" \n\n\nEntered validate_process %s"%(datetime.now()))
    query_str = "select time,data from windows_events where time > %s order by time desc"%(latest_time_stamp)
    print(query_str)
    osquery_RESULTS = osquery_instance.client.query(query_str)
    if osquery_RESULTS.status.code != 0:
        print("Error running the query: %s" % osquery_RESULTS.status.message)
        sys.exit(1)
    for row in osquery_RESULTS.response:
        time_stamp = int(row.get('time',0))
        print("\n%s - %s"%(time_stamp,latest_time_stamp))
        if time_stamp > latest_time_stamp:
            latest_time_stamp = time_stamp
        print("\n%s - %s"%(time_stamp,latest_time_stamp))
        EventData = row.get('data',None)
        json_EventData = json.loads(EventData)
        i=0
        process_present=False
        process_name = ""
        pid_int = -1
        while i<2:
            try :
                process_name = json_EventData['EventData'][col_list_name[i]]
                pid = json_EventData['EventData'][col_list_id[i]]
                pid_int = int(pid,16)                                
                # process_name=process_name.replace('\\','\\\\')
                j=1
                for tmp_rule in white_list:
                    # if process_name not in white_list:
                    # print("\n%s) %s == %s"%(j,process_name.casefold(),tmp_rule.casefold()))
                    if process_name.casefold() == tmp_rule.casefold():
                        process_present=True
                        break
                    j+=1
                i=2
            except KeyError:
                i=i+1                
                pass
        # print("\n%s) %s == %s"%(j,process_name,tmp_rule))
        if process_present==False:
            tmp_msg = " %s-%s Process not in whitelist.\nProcess to be terminated\n" %(process_name,pid_int)
            print(tmp_msg)
            application.show_message(tmp_msg)
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
        # else :
        #     print(" %s - %s Process  in whitelist.\n" %(process_name,pid_int))
            # break
    print(" \n\n\nReturned validate_process %s"%(datetime.now()))

def insert_processec_details():
    global white_list_file_available
    white_list_tmp = []
    osquery_RESULTS = osquery_instance.client.query("select pid,name,uid,parent,start_time,path,cmdline from processes")
    if osquery_RESULTS.status.code != 0:
        print("Error running the query: %s" % osquery_RESULTS.status.message)
        sys.exit(1)
    items = []
    for row in osquery_RESULTS.response:    
        val_items = []
        process_name = row.get('name',None)
        process_path = row.get('path',None)
        process_uid = row.get('uid',None)
        val_items.append(row.get('pid',None))
        val_items.append(process_name)
        val_items.append(process_uid)            
        val_items.append(row.get('parent',None))            
        val_items.append(process_path)
        val_items.append(row.get('cmdline',None))            
        timestamp = int(row.get('start_time',None))            
        if timestamp>0 :
            val_items.append(datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"))        
        else:
            val_items.append("")        
        items.append(QTreeWidgetItem(None,val_items ))
        if white_list_file_available == False:
            tmp_lst = []
            tmp_lst.append(process_name)
            tmp_lst.append(",")
            tmp_lst.append(process_path)  
            tmp_lst.append(",")
            if tmp_lst not in white_list_tmp:
                white_list_tmp.append(tmp_lst)                        
                if process_path == '':
                    white_list.append(process_name)
                else :                
                    white_list.append(process_path)
    # print("insert_processec_details \n\t %s" %white_list_tmp)
    if white_list_file_available == False:
        white_list_file = open("whitelist","w")
        for whiteline in white_list_tmp:
            white_list_file.writelines(whiteline)
            # white_list_file.write(whiteline)
            white_list_file.write("\n")
        white_list_file.close()
        white_list_file_available = True
    return items

def insert_white_list_details():
    items = []
    white_list_file = open("whitelist","r")
    for line in white_list_file:
        items.append(QTreeWidgetItem(None, line.split(',')))
    white_list_file.close()
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
        self.ui.treeWidget_2.selectionModel().selectionChanged.connect(self.clearall)
        ret_items = insert_processec_details()
        self.ui.treeWidget.addTopLevelItems(ret_items)
        ret_white_list_items = insert_white_list_details()
        self.ui.treeWidget_2.addTopLevelItems(ret_white_list_items)
        self.ui.show()

    def  clearall(self):        
        self.ui.le_Path.clear()
        self.ui.le_Name.clear()
        self.ui.le_Desc.clear()
        self.ui.btnAdd.setText("Add")
    
    def btnBrowseClicked(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(None,"Select File", "","Excuitable Files (*.exe)", options=options)
        if fileName:
            self.ui.le_Path.setText(fileName)
    
    def btnAddClicked(self):
        global selected_item
        exe_path = self.ui.le_Path.toPlainText()
        exe_name = self.ui.le_Name.toPlainText()
        exe_descriptor = self.ui.le_Desc.toPlainText()
        # print("Add Clicked %s - %s" % (exe_name,exe_path))
        if len(exe_name) == 0:# or exe_path.empty():            
            QMessageBox.information(self,"Message","Name cannot be empty", buttons = QMessageBox.Ok, defaultButton = QMessageBox.NoButton)
            return
        if len(exe_path) == 0:# or exe_path.empty():            
            QMessageBox.information(self,"Message","Path cannot be empty", buttons = QMessageBox.Ok, defaultButton = QMessageBox.NoButton)
            return
        white_list.append(str(Path(exe_path)))
        tmp = "\n%s,%s,%s"%(exe_name,str(Path(exe_path)),exe_descriptor)        
        tmp_str = self.ui.btnAdd.text()
        tmp_list = []
        tmp_list.append(exe_name)
        tmp_list.append(str(Path(exe_path)))
        tmp_list.append(exe_descriptor)
        if tmp_str == "Update" and selected_item is not []:
            print("update")
            del_line = "%s,%s,%s"%(selected_item.text(0),selected_item.text(1),selected_item.text(2))
            white_list_file = open("whitelist","r")
            white_list_file_tmp = open("whitelisttemp","w")
            for line in white_list_file:
                if del_line not in line:
                    white_list_file_tmp.writelines(line)
            white_list_file_tmp.write(tmp)
            white_list_file.close()
            white_list_file_tmp.close()
            os.remove("whitelist")
            os.rename("whitelisttemp","whitelist")
            PyQt5.sip.delete(selected_item)
            selected_item = []
            # self.ui.treeWidget_2.removeItem(selected_item)
        else:
            white_list_file = open("whitelist","a")
            white_list_file.write(tmp)
            white_list_file.close()
        item = QTreeWidgetItem(None, tmp_list)
        self.ui.treeWidget_2.insertTopLevelItem(self.ui.treeWidget_2.topLevelItemCount()-1,item)

    def btnEditClicked(self):
        global selected_item
        selected_item = self.ui.treeWidget_2.selectedItems()[0]
        exe_name = selected_item.text(0)
        exe_path = selected_item.text(1)
        exe_descriptor = selected_item.text(2)
        self.ui.le_Name.setText(exe_name)
        self.ui.le_Desc.setText(exe_descriptor)
        self.ui.le_Path.setText(exe_path)
        self.ui.btnAdd.setText("Update")
        print("Edit Clicked")

    def btnDeleteClicked(self):
        global selected_item
        selected_item = self.ui.treeWidget_2.selectedItems()[0]
        print("Delete Clicked")
        if selected_item is not []:
            del_line = "%s,%s,%s"%(selected_item.text(0),selected_item.text(1),selected_item.text(2))
            white_list_file = open("whitelist","r")
            white_list_file_tmp = open("whitelisttemp","w")
            for line in white_list_file:
                if del_line not in line:
                    white_list_file_tmp.writelines(line)
            white_list_file.close()
            white_list_file_tmp.close()
            os.remove("whitelist")
            os.rename("whitelisttemp","whitelist")
            PyQt5.sip.delete(selected_item)
            selected_item = []

    def show_message(slef,display_message):
        # msg = QMessageBox()
        # msg.setIcon(QMessageBox.Critical)
        # msg.setText("Error")
        # msg.setInformativeText(tmp_msg)
        # msg.setWindowTitle("Error")
        # msg.setStandardButtons(QMessageBox.Ok)
        # msg.exec()            
        # msg.exec_()            
        QMessageBox.critical(slef,"Message",display_message, buttons = QMessageBox.Ok, defaultButton = QMessageBox.NoButton)

def write_into_white_list_file(file_options):
    if file_options == 0:
        white_list_file = open("whitelist","w")
    elif file_options == 1:
        white_list_file = open("whitelist","r")
        white_list_file_tmp = open("whitelist_tmp","w")

if __name__ == "__main__":
    global col_list_id,col_list_name,osquery_instance,application
    try:
        white_list_file = open("whitelist","r")
        items = []        
        for line in white_list_file:
            items = line.split(',')
            if items.__len__() == 3:
                if items[1] == '':
                    white_list.append(items[0])
                else :                
                    white_list.append(items[1])
        # print(white_list)
        white_list_file.close()
        white_list_file_available = True
    except FileNotFoundError:
        white_list_file_available = False
        pass
    # white_list = ['C:\\WINDOWS\\system32\\NOTEPAD.EXE','C:\\Windows\\System32\\audiodg.exe','C:\\Windows\\System32\\svchost.exe']
    col_list_id = ['ProcessId','NewProcessId','CallerProcessId']
    col_list_name = ['ProcessName','NewProcessName','CallerProcessName']
    osquery_instance = osquery.SpawnInstance()
    osquery_instance.open()  # This may raise an exception    
    
    app = QtWidgets.QApplication([])
    application = list_window()
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(validate_process, 'interval', seconds=15)
    scheduler.start()

    app.exec()

    # application.show()
    del osquery_instance
    scheduler.shutdown()
    sys.exit()

