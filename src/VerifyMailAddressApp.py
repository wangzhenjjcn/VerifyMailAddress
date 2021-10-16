#!/usr/bin/python
# -*- coding: UTF-8 -*-
# by WangZhen<wangzhenjjcn@gmail.com>
# from 2021-10-17 All Rights Reserved By Myazure.org Code on https://github.com/wangzhenjjcn/VerifyMailAddress

import os
import sys
import time
import threading
import copy
import tkinter.filedialog as tkFileDialog
from validate_email import validate_email
import smtplib
import dns.resolver
import socket
import re


class MailVerifier():
    def __init__(self):
        self.windows=sys.platform=="win32"
        self.linux=sys.platform!="win32"
        if self.windows:
            self.path=os.path.dirname(os.path.realpath(sys.argv[0]))
        if self.linux:
            self.path="./"
        self.path=""
        self.dataResourceFile=self.path+"/data.csv"
        self.dataTargetFile=self.path+"/resault.csv"
        self.data={}
        self.data2save={}
        self.mailAddress=[]
        self.domains=[]
        self.checkedDomain=[]
        self.checkedFaildDomain=[]
        self.checkedMailAddress=[]
        self.dnsThreadNum=4  #default 4
        self.checkMailMaxThreadNum=10
        self.checkDomainMaxThreadNum=10  #default 10 MaxThread
        self.mxcache={}
    
    def loadVerifier(self):
        print("system ready!")
        self.readDataFile()
        time.sleep(5)
        self.decodeDataFile()
        time.sleep(5)
        self.checkMailAddresses()
        time.sleep(5)
        self.checkMailDomains()
        time.sleep(5)
        self.checkMailAddressValidate()
        time.sleep(5)
        self.genDataResault()
        time.sleep(5)
        self.saveDataFile()
        time.sleep(5)

    def readDataFile(self):
        print("ready to read data file:[%s]"%(self.dataResourceFile))
        if not os.path.exists(self.dataResourceFile):
            print("data file not exists:[%s]"%(self.dataResourceFile))
        print("waitting user choice a csv file to verity mail address")
        try:
            file_path = tkFileDialog.askopenfilename(title=u'请选择解析文件', filetypes=(
            ("Csv Files", "*.csv"), ("all files", "*.*")))
            if file_path == None:
                print("file not exists![%s]" % file_path)
                sys.exit(0)
            elif not os.path.exists(file_path):
                print("file not exists![%s]" % file_path)
                sys.exit(4)
            else:
                print("user choiced file:[%s]"%(file_path))
                self.dataResourceFile=file_path  
        except Exception as e:
            print("failed read file[%s]"%(self.dataResourceFile))
            print(e)
            time.sleep(10)
            sys.exit(3)
        print("ready to read file[%s]"%(self.dataResourceFile))
        dataline=[]
        try:
            with open(self.dataResourceFile, 'r+', encoding='utf-8') as file_to_read:
                while True:
                    lines = file_to_read.readline()
                    if not lines:
                        break
                    if "@" in lines:
                        dataline.append(copy.deepcopy(str(lines).strip().replace('\n', '').replace('\r', '').replace(",","")))
        except Exception as e:
            print("read file err at utf-8 decoder:")
            time.sleep(5)
            if "GBK" in str(e) or "gbk" in str(e):
                print("err encode errinfo:[%s]"%(str(e)))
                time.sleep(1)
                print("try to read at gbk encode")
                try:
                    with open(self.dataResourceFile, 'r+', encoding='GBK') as file_to_read:
                        while True:
                            lines = file_to_read.readline()
                            if not lines:
                                break
                            if "@" in lines:
                                dataline.append(copy.deepcopy(str(lines).strip().replace('\n', '').replace('\r', '').replace(",","")))
                except Exception as e2:
                    print(e2)
                    print("failed read file[%s]"%(self.dataResourceFile))
                    time.sleep(10)
                    sys.exit(3)
            else:
                print(e)
                time.sleep(10)
                sys.exit(3)
        self.mailAddress=list(copy.deepcopy(dataline))
 
        time.sleep
        print("success read file:[%s],d atanum:[%s]"%(self.dataResourceFile,len(self.mailAddress)))
        return

    def decodeDataFile(self):
        for aaddress in self.mailAddress:
            print("add:[%s]"%(aaddress))
            hostname = aaddress[aaddress.find('@') + 1:]
            username = aaddress[:aaddress.find('@') - 1]
            self.domains.append(hostname)
            self.data[aaddress]={}
            self.data[aaddress]["domain"]=hostname
            self.data[aaddress]["username"]=username
            self.data[aaddress]["address"]=aaddress
            self.data[aaddress]["AddressCheck"]=None
            self.data[aaddress]["MXCheck"]=None
            self.data[aaddress]["Validate"]=None
            
        return

    def checkMailAddresses(self):
        print("checkMailAddress successed")
        for address in self.mailAddress:
            self.checkMailAddressThreadMax = threading.BoundedSemaphore(self.checkMailMaxThreadNum)
            try:
                self.checkMailAddressThreadMax.acquire()
                scanThread = threading.Thread(target=self.checkMailAddress,args=(copy.deepcopy(address),),)
                scanThread.start()
            except Exception as e2:
                print("err at scanalldata creat threads maxthread:[%s]"%(self.checkMailMaxThreadNum))
                print(e2)
                pass
        return
    
    def checkMailAddress(self,address):
        try:
            addressToVerify = str(address).lower()
            match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', addressToVerify) 
            if match == None: 
                print("checkMailAddress falid:Bad Syntax in[%s]"%(address))
                self.data[address]["AddressCheck"]="checkMailAddress falid:Bad Syntax in[%s]"%(address)
            else:
                print("checkMailAddress successed:[%s]"%(address))
                self.checkedMailAddress.append(copy.deepcopy(address))
                self.data[address]["AddressCheck"]=True
        except Exception as e:
            print(e)
            self.data[address]["AddressCheck"]=str(e).replace(",","，")
        finally:
            self.checkMailAddressThreadMax.release()

    def checkMailDomains(self):
        print("checkMailDomain start>>>")
        for address in self.mailAddress:
            self.checkDomainThreadMax = threading.BoundedSemaphore(self.checkDomainMaxThreadNum)
            try:
                self.checkDomainThreadMax.acquire()
                checkDomainThread = threading.Thread(target=self.checkMailDomain,args=(copy.deepcopy(address),),)
                checkDomainThread.start()
            except Exception as e2:
                print("err at scanalldata creat threads maxthread:[%s]"%(self.checkDomainThreadMax))
                print(e2)
                pass
        print("checkMailDomain end<<<")
        return

    def checkMailDomain(self,address):
        try:
            if self.data[address]["domain"] in self.checkedDomain:
                self.data[address]["MXCheck"]=True
                return self.mxcache[self.data[address]["domain"]]
            if self.data[address]["domain"] in self.checkedFaildDomain:
                self.data[address]["MXCheck"]=False
                return False
            if not self.data[address]["AddressCheck"]:
                self.data[address]["MXCheck"]=False
                return False
            mxRecord=""
            domain_name = address.split('@')[1] 
            if domain_name in self.mxcache.keys():
                return self.mxcache[domain_name]
            records = dns.resolver.query(domain_name, 'MX') 
            mxRecord = records[0].exchange 
            mxRecord = str(mxRecord) 
            self.mxcache[domain_name]=mxRecord
            self.checkedDomain.append(domain_name)
            self.data[address]["MXCheck"]=True
            return mxRecord
        except Exception as e:
            if "The DNS response does not contain an answer to the question" in str(e) or "None of DNS query names exist" in str(e):
                mxRecord=None
                self.mxcache[domain_name]=mxRecord
                self.checkedFaildDomain.append(domain_name)
                self.data[address]["MXCheck"]=False
            print("checkMailMxRecorderr:%s,%s"%(address,str(e)))
            if "timed out" in str(e):
                self.data[address]["MXCheck"]=None
                return False
            print(str(e))
        finally:
            self.checkDomainThreadMax.release()

    def checkMailAddressValidate(self,address):
        return True

    def sendTestMail(self,mail):
        return True

    def genDataResault(self):
        return

    def saveDataFile(self):
        return
    
if __name__ == "__main__":
    mailchecker=MailVerifier()
    mailchecker.loadVerifier()