#!/usr/bin/python
# -*- coding: UTF-8 -*-
# by WangZhen<wangzhenjjcn@gmail.com>
# from 2021-10-17 All Rights Reserved By Myazure.org Code on https://github.com/wangzhenjjcn/VerifyMailAddress

import os
import sys
import time
import datetime
import pytz
import threading
import copy
import re
import tkinter.filedialog as tkFileDialog
from validate_email import validate_email
import DNS

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
        self.checkValidateMaxThreadNum=2
        self.checkMailAddressThreadMax= threading.BoundedSemaphore(self.checkMailMaxThreadNum)
        self.checkDomainThreadMax= threading.BoundedSemaphore(self.checkDomainMaxThreadNum)
        self.checkValidateThreadMax = threading.BoundedSemaphore(self.checkValidateMaxThreadNum)
        self.mxcache={}
    
    def loadVerifier(self):
        print("system ready!")
        start=time.time()
        self.readDataFile()
        self.decodeDataFile()     

        self.checkMailAddresses()
        

        self.checkMailDomains()
        

        self.checkMailAddressValidates()        
        



        self.genDataResault()        
        self.saveDataFile()
        

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
        print("success read file:[%s],datanum:[%s]"%(self.dataResourceFile,len(self.mailAddress)))
        return

    def decodeDataFile(self):
        for address in self.mailAddress:
            print("add:[%s]"%(address))
            hostname = address[address.find('@') + 1:]
            username = address[:address.find('@') - 1]
            self.domains.append(hostname)
            self.data[address]={}
            self.data[address]["domain"]=hostname
            self.data[address]["username"]=username
            self.data[address]["address"]=address
            self.data[address]["AddressCheck"]=None
            self.data[address]["MXCheck"]=None
            self.data[address]["Validate"]=None
            
        return

    def checkMailAddresses(self):
        print("checkMailAddresses start>>>%.2f"%time.time())
        start=time.time()
        for address in self.mailAddress:
            self.checkMailAddressThreadMax.acquire()
            try:
                scanThread = threading.Thread(target=self.checkMailAddress,args=(copy.deepcopy(address),),)
                scanThread.start()
            except Exception as e2:
                print("err at scanalldata creat threads maxthread:[%s]"%(self.checkMailMaxThreadNum))
                print(e2)
                pass
        for i in (0,self.checkMailMaxThreadNum):
            self.checkMailAddressThreadMax.acquire()
        print("[%s]checkMailAddresses check finished at [%.2f]"%(str(datetime.datetime.fromtimestamp(int(time.time()), pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')),time.time()-start))
        for i in (0,self.checkMailMaxThreadNum):
            self.checkMailAddressThreadMax.release()
        print("checkMailAddresses end<<<%.2f"%time.time())

    
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
            try:
                self.checkMailAddressThreadMax.release()
            except Exception as e2:
                return

    def checkMailDomains(self):
        print("checkMailDomain start>>>")
        start=time.time()
        for address in self.mailAddress:
            try:
                self.checkDomainThreadMax.acquire()
                checkDomainThread = threading.Thread(target=self.checkMailDomain,args=(copy.deepcopy(address),),)
                checkDomainThread.start()
            except Exception as e2:
                print("err at scanalldata creat threads maxthread:[%s]"%(self.checkDomainThreadMax))
                print(e2)
                pass
        for i in (0,self.checkDomainMaxThreadNum):
            self.checkDomainThreadMax.acquire()
        print("[%s]checkMailDomains check finished at [%.2f]"%(str(datetime.datetime.fromtimestamp(int(time.time()), pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')),time.time()-start))
        for i in (0,self.checkDomainMaxThreadNum):
            self.checkDomainThreadMax.release()
        print("checkMailDomain end<<<")
         

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
            self.data[address]["MXCheck"]=self.data[address]["Validate"]=validate_email(address,check_mx=True,verify=False,debug=True,smtp_timeout=30)
            # mxRecord=""
            domain_name = address.split('@')[1] 
            # if domain_name in self.mxcache.keys():
            #     return self.mxcache[domain_name]
            # records = dns.resolver.resolve(domain_name, 'MX') 
            # mxRecord = records[0].exchange 
            # mxRecord = str(mxRecord) 
            # self.mxcache[domain_name]=mxRecord
            if self.data[address]["MXCheck"]==True:
                self.checkedDomain.append(domain_name)
                if address in self.checkedFaildDomain:
                    self.checkedFaildDomain.remove(address)
            elif self.data[address]["MXCheck"]==False:
                self.checkedFaildDomain.append(domain_name)
                if address in self.checkedDomain:
                    self.checkedDomain.remove(address)
            # self.data[address]["MXCheck"]=True
            # self.data[address]["mxRecord"]=mxRecord
        except Exception as e:
            # if "The DNS response does not contain an answer to the question" in str(e) or "None of DNS query names exist" in str(e):
            #     mxRecord=None
            #     self.mxcache[domain_name]=mxRecord
            #     self.checkedFaildDomain.append(domain_name)
            #     self.data[address]["mxRecord"]=None
            #     self.data[address]["MXCheck"]=False
            # print("checkMailMxRecorderr:%s,%s"%(address,str(e)))
            # if "timed out" in str(e):
            #     self.data[address]["MXCheck"]=None
            #     self.data[address]["mxRecord"]=None
            #     return False
            print(str(e))
        finally:
            try:
                self.checkDomainThreadMax.release()
            except Exception as e2:
                return False
            

    def checkMailAddressValidates(self):
        print("checkMailAddressValidates start>>>")
        start=time.time()
        for address in self.mailAddress:
            self.checkValidateThreadMax.acquire()
            try:
                checkDomainThread = threading.Thread(target=self.checkMailAddressValidate,args=(copy.deepcopy(address),),)
                checkDomainThread.start()
            except Exception as e2:
                print("err at scanalldata creat threads maxthread:[%s]"%(self.checkValidateThreadMax))
                print(e2)
                pass
        for i in (0,self.checkValidateMaxThreadNum):
            self.checkValidateThreadMax.acquire()
        print("[%s]checkMailAddressValidates check finished at [%.2f]"%(str(datetime.datetime.fromtimestamp(int(time.time()), pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')),time.time()-start))
        for i in (0,self.checkValidateMaxThreadNum):
            self.checkValidateThreadMax.release()
        print("checkMailAddressValidates end<<<")
        return True

    def checkMailAddressValidate(self,address):
        try:
            self.data[address]["Validate"]=validate_email(address,check_mx=False,verify=True,debug=True,smtp_timeout=30)
            time.sleep(1)
        except Exception as e:
            print(e)
        finally:
            try:
                self.checkValidateThreadMax.release()
            except Exception as e2:
                return False


    def sendTestMail(self,mail):
        return True

    def genDataResault(self):
        return

    def saveDataFile(self):
        for address in self.data:
            print("address[%s]adcheck[%s]mxcheck[%s]validatecheck[%s]"%(address,self.data[address]["AddressCheck"],self.data[address]["MXCheck"],self.data[address]["Validate"]))

        return
    
if __name__ == "__main__":
    mailchecker=MailVerifier()
    mailchecker.loadVerifier()