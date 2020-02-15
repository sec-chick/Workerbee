# import modules
import requests
from requests.exceptions import ConnectionError
import hashlib
import time
import csv
import datetime
from config import *

#csv header
csv_header=['Date','Malware URL','Virus Total','Remote IP','Local Port','Status Code',
        'Malware File Name','Regular Expression','Hash(MD5)','Hash(SHA1)','Hash(SHA256)','Payload']

def main():
    csv_data=[]
    csv_data.append(csv_header) # 先頭をヘッダファイルにする
    with open(malware_result_file) as f: # malware用ファイルオープン
        reader = csv.reader(f)
        headaer = next(reader)
        for row in reader:
            virustotal=row[2]
            if(virustotal=='NO' or virustotal== 'No Data'):
                # VirusTotal Scan
                func_virustotal_url_scan(row[1]) # URLで調査
                response_virustotal=func_virustotal_hash_scan(row[9]) #sha256で調査
                if (response_virustotal['response_code'] == 1): #結果が存在する場合

                    row[2]=func_virustotal_result(response_virustotal)           
                    
                else:
                    row[2] = 'NG'

            csv_data.append(row)
    
    func_csv_write(csv_data)


def func_virustotal_hash_scan(malware_hash):
    time.sleep(20)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'  # file report VT
    params = {'apikey': vt_apikey, 'resource': malware_hash} # sha256で調査
    response = requests.get(url, params=params)
    response_virustotal = response.json()
    return response_virustotal



def func_virustotal_url_scan(malware_url):
    time.sleep(20)
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': vt_apikey, 'resource': malware_url} # urlで調査
    response = requests.get(url, params=params)


def func_virustotal_result(response_virustotal):
    # malware結果を記載
    scan_count = 0
    flag = 'off'
    vt_scan = response_virustotal['scans']
    for row in vt_scan.items():
        virus_scan = str(row[1]['detected'])
        if virus_scan == "True":
            flag = 'ON'
            if scan_count == 0:
                scan_count = 1
                vt_result2 = str(row[1]['result'])
                vt_virus_name = row[0] + ':' + vt_result2
            else:
                vt_result2 = str(row[1]['result'])
                vt_virus_name = vt_virus_name + ',' + "\r\n" + row[0] + ':' + vt_result2
    if (flag != 'ON'):
        vt_virus_name = 'No Data'

    return vt_virus_name

def func_csv_write(csv_data):
    with open(malware_result_file, 'w') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerows(csv_data)

if __name__ == "__main__":
    main()
