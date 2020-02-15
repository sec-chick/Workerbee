import json
import pprint
import binascii
import re
import csv
import urllib.parse
import subprocess
import sys
import urllib.parse
import datetime
import time
from config import *
from pattern import *
from datetime import datetime, date, timedelta
from pattern import *


#variable
attack_connection_payload_data_hex=[]
local_port=[]
remote_ip=[]
hex_decode=[]
hex_raw=[]
timestamp=[]
malware_url=[]
http_path=[]
data=""
j=0

# 引数でフォルダパスを指定
args = sys.argv
try:
    honeytrap_logfile=args[1] # honeytrap logfile
    honeytrap_payload=args[2] # honeytrap payload
except IndexError as e:
    print("Error:", e)
    print("Please set payload file.")
    print("ex: python3 <honeytrap_csv_write.py> <log_file> <payload file>")
    sys.exit()

def main():
    print('Honeytrap Analysis Start')
    log_count=0
    #header write
    header=['Date','Malware URL','Local Port','Remote IP','URI Path','Decode Payload'] # header
    with open(honeytrap_payload , 'a') as f:
            writer=csv.writer(f)
            writer.writerow(header)

    with open(honeytrap_logfile) as lines:
        for line in lines:
            log_count=log_count+1
            try:
                data = json.loads(line)
                if (data['attack_connection']['local_port'] == 0 or data['attack_connection']['payload']['data_hex'] == ""):
                    pass
                else:
                    malware_url, data_hex,http_path=func_read_payload(data, pattern)
                    func_csv_write(data, malware_url, data_hex, http_path)

            except Exception as e:
                now_time=str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
                error = 'time:' + now_time +', type:' + str(type(e)) + ', type:' + str(type(e)) + ', args:' + str(e.args) +  ', error:' + str(e)
                with open(error_file , 'a') as f:
                    writer=csv.writer(f)
                    writer.writerow(error)
    
    print('Number of detection:',log_count)
    print('Honeytrap Analysis end')

def func_read_payload(temp, pattern):
    malware_url=""
    malware_url_check=[]
    result_malware=0
    data_hex=str(bytes.fromhex(temp['attack_connection']['payload']['data_hex']))
    data_hex=re.sub("\\\\",'', data_hex)
    data_hex=re.sub("^b'",'', data_hex)
    data_hex=re.sub("^b\"",'', data_hex)
    data_hex=re.sub("'$",'', data_hex)
    data_hex=re.sub("\"$",'', data_hex)
    data_hex=urllib.parse.unquote(data_hex)
    result = re.match(r"^(GET|HEAD|POST|OPTIONS|PUT|DELETE|TRACE|PATCH|LINK|UNLINK)\s([^\s\?]+)",data_hex,re.IGNORECASE)
    
    if result!=None:
        http_path=result.group(2)
    else:
        http_path='No uri path'

    for i in pattern:
        result = re.match(i, data_hex,re.IGNORECASE)
        if result != None:
            result_malware=1
            if (len(malware_url_check) != 0):
                for j in malware_url:
                    if (result.group(1) == j):
                        break
                malware_url = malware_url + result.group(1)
            
            malware_url=result.group(1)
            print('Malware URL: ',malware_url)

    if (result_malware == 0):
        malware_url='No Malware'

    return malware_url, data_hex, http_path


def func_csv_write(temp, malware_url, data_hex, http_path):
    csv_data=[temp['start_time'], malware_url,temp['attack_connection']['local_port'], temp['attack_connection']['remote_ip'],http_path,data_hex]
    with open(honeytrap_payload , 'a') as f:
            writer=csv.writer(f)
            writer.writerow(csv_data)

if __name__ == "__main__":
    main()
