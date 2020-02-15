# -*- coding: utf-8 -*-
#モジュールインポート
import json
import pprint
import binascii
#import numpy as np
#from collections import Counter
import re
import csv
import urllib.parse
#import os
#import slack
#import subprocess
import sys
import urllib.parse
import datetime
import time
import base64
from config import *
from pattern import *
from datetime import datetime, date, timedelta
from pattern import *
#パーサが許容する現在の最大フィールドサイズを定義
csv.field_size_limit(1000000000)


#パターン定義
pattern_wow = "\[([^\]]+?)\]\s([^\s]+?)\s([^\s]+?)\s\"([^\s]+?)\s(.+?)(\sHTTP\/1\.d|HTTP\/1\.\d).*?\"\s([^\s]+)\s([^\s]+)\s(.+?)[\s$]"
pattern_path = "(.+?)($|\?)"
pattern_query = "[^\?]+?\?(.+?)$"
# compile後match
repatter = re.compile(pattern_wow)
repatter_path = re.compile(pattern_path)
repatter_query = re.compile(pattern_query)

# 引数でフォルダパスを指定
args = sys.argv
try:
    load_file=args[1] # logfile
    write_file=args[2] # payload
except IndexError as e:
    print("Error:", e)
    print("Please set payload file.")
    print("ex: python3 <wowhoneypot_csv_write.py> <log_file> <payload file>")
    sys.exit()


def main():
    print('WOWHoneypot Analaysis Start')

    data = func_log_read(load_file)
    print('Number of detection:',len(data))
    func_csv_write(data, write_file)
    
    print('WOWHoneypot Analaysis End')

def func_csv_write(data, write_file):
    #ファイル書き込み
    with open(write_file, "w", newline="") as f:
        w = csv.writer(f, delimiter=",")
        header=[]
        header = ['Date','Remote IP','Local IP','Method','URI','URI Path','URI Query','Status Code','Payload']
        w.writerow(header)
        for data_list in data:
            w.writerow(data_list)


def func_log_read(load_file):
    #ログ読み込み
    data=[]
    with open(load_file, 'r') as line:
        for reader in line:
            #print(reader)
            result = repatter.match(reader)
            #日付
            date = result.group(1)
            #リモートIP
            remote_ip = result.group(2)
            #ローカルIP
            local_ip = result.group(3)
            #httpメソッド
            http_method = result.group(4)
            #uri
            http_uri = result.group(5)
            http_uri=re.sub("\s$",'', http_uri)
            #http path
            path_result = repatter_path.match(http_uri)
            http_path = path_result.group(1)
            #http query
            query_result = repatter_query.match(http_uri)
            if query_result != None:
                http_query = query_result.group(1)
            else:
                http_query = 'No Query'
            status_code = result.group(7)
            #payload
            payload= str(base64.b64decode(result.group(9)))
            payload=re.sub("^b'",'', payload)
            payload=re.sub("^b\"",'', payload)
            payload=re.sub("'$",'', payload)
            payload=re.sub("\"$",'', payload)
            http_uri = urllib.parse.unquote(http_uri)
            http_path = urllib.parse.unquote(http_path)
            http_query = urllib.parse.unquote(http_query)
            #csvに書き込み用データ
            data.append([date, remote_ip, local_ip, http_method, http_uri, http_path, http_query, status_code, payload])

    return data

if __name__ == "__main__":
    main()
