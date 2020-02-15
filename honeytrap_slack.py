# -*- coding: utf-8 -*-

import json
import pprint
import binascii
from collections import Counter
import re
import csv
import urllib.parse
import slack
import subprocess
import sys
import urllib.parse
import datetime
import time
from config import *
from pattern import *

csv.field_size_limit(1000000000)
# 引数でフォルダパスを指定

args = sys.argv
try:
    honeytrap_payload=args[1] # honeytrap payload
except IndexError as e:
    print("Error: ", e)
    print("Please set payload file.")
    print("ex: python3 <honeytrap_slack.py> payload_file")
    sys.exit()

def main():
    #ログからデータを読み込み
    local_port,remote_ip,malware,uri_path=func_csv_read(honeytrap_payload)
    print('<Honeytrap>')
    #引数からペイロードを指定
    print('Analyze:', args[1])
    local_port=func_sort_count(local_port,'LocalPort',10)
    print('Local Port Top 10')
    print(local_port)
    remote_ip=func_sort_count(remote_ip,'RemoteIP',10)
    print('Remote IP Top 10')
    print(remote_ip)
    malware=func_sort_count(malware,'Malware','all')
    print('Malware')
    print(malware)
    # send slack
    uri_path, uri_new=func_sort_count(uri_path,'URI PATH','all')
    print('URI_path')
    print(uri_path)
    print('NEW Path')
    print(uri_new)
    slack_message='<Honeytrap>' + '\r\n'+ '\r\n' +  'Local Port Top 10' + '\r\n' + '\r\n' + local_port + 'Remote IP Top 10' +  '\r\n'+ '\r\n' + remote_ip + 'Malware' + '\r\n' + '\r\n' + malware
    if(slack_flag=='ON'):
        func_slack_send(slack_message,slack_channel_honeytrap)


def func_slack_send(slack_message,send_channel):
    token = SLACK_API_TOKEN
    #print(token)
    client = slack.WebClient(token)
    response = client.chat_postMessage(
        channel=send_channel,
        text=slack_message)

def func_sort_count(data,item, sort_count):
    # 新規パス収集用
    uri_new = ''
    count = Counter(data)
    sorted_list = sorted(count.items(), key=lambda x: x[1], reverse=True)
    result = re.match("URI",item,re.IGNORECASE)
    count_data= item  + ',Count' + '\r\n'
    #uri_path_list,target_list,cve_list,reference_list=func_uri_path_read(uri_path_list_csv)
    #全て表示させる場合に実行
    if (sort_count == 'all'):
        # URIをソートする場合に実行
        if result != None:
            uri_path_list,target_list,cve_list,reference_list=func_uri_path_read(uri_path_list_csv)
            for i in sorted_list:
                uri, uri_new =func_uri_check(i[0],uri_path_list,target_list,cve_list,reference_list, uri_new)
                uri =func_sanitize(uri)
                count_data=count_data+uri+','+str(i[1]) + ' 件' +'\r\n'

            return count_data, uri_new
        else:
            # 指定された数値分を集計
            for i in sorted_list:
                var_count =func_sanitize(str(i[0]))
                count_data=count_data+var_count +','+str(i[1]) + ' 件' +'\r\n'

        return count_data

    #TOPX件の表示はこちらで処理
    else:
        j=1
        if result != None:
            uri_path_list,target_list,cve_list,reference_list=func_uri_path_read(uri_path_list_csv)
            for i in sorted_list:
                uri, uri_new =func_uri_check(i[0],uri_path_list,target_list,cve_list,reference_list, uri_new)
                uri =func_sanitize(uri)
                #uri_new =func_sanitize(uri_new)
                count_data=count_data+uri+','+str(i[1]) + ' 件' +'\r\n'
                j=j+1
                if (j>sort_count):
                    break

            return count_data, uri_new
        else:
            for i in sorted_list:
                var_count =func_sanitize(str(i[0]))
                count_data=count_data+var_count +','+str(i[1]) + ' 件' +'\r\n'
                j = j + 1
                if (j>sort_count):
                    break
        return count_data

def func_sanitize(sanitize_data):
    # サニタイズ処理
    sanitize_data=re.sub("\.",'[.]',sanitize_data)
    sanitize_data=re.sub("http","hxxp",sanitize_data)
    sanitize_data=re.sub("^/\s$","/",sanitize_data) # /の置換

    return sanitize_data

def func_uri_check(uri,uri_path_list,target_list,cve_list,reference_list,new_data):
    #uri表示用
    flag=0
    for i in range(len(uri_path_list)):
        result = re.match(uri_path_list[i],uri,re.IGNORECASE)
        if result != None:
            re_uri=uri + ',Target:' + target_list[i]
            flag=1
            break
    if (uri == '/'):
        re_uri=uri + ',Target:' + '-'
        flag=1

    if (flag==0):
        re_uri=uri + ',Target: new'
        uri = func_sanitize(uri)
        new_data=new_data+uri + '\r\n'


    return re_uri, new_data



def func_csv_read(file_name):
    # CSV読み込み
    local_port_data=[]
    remote_ip_data=[]
    malware_data=[]
    uri_path_data=[]
    with open(honeytrap_payload) as f:
        reader = csv.reader(f)
        for row in reader:
             local_port_data.append(row[2])
             remote_ip_data.append(row[3])
             malware_hxxp=re.sub("http","hxxp",row[1])
             malware_data.append(row[1])
             uri_path_data.append(row[4])

    return local_port_data,remote_ip_data,malware_data,uri_path_data

def func_uri_path_read(file_name):
    # HTTP PATH抽出
    uri_path_list=[]
    target_list=[]
    cve_list=[]
    reference_list=[]
    with open(file_name) as f:
        reader = csv.reader(f)
        for row in reader:
            uri_path_decode=row[0]
            uri_path_list.append(uri_path_decode)
            target_list.append(row[1])
            cve_list.append(row[2])
            reference_list.append(row[3])

    return uri_path_list,target_list,cve_list,reference_list

if __name__ == "__main__":
    main()

