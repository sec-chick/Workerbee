# -*- coding: utf-8 -*-
import datetime

date_today = datetime.date.today()
date_today = str("{0:%Y%m%d}".format(date_today))

#uri path list
uri_path_list_csv=''

#malware
malware_result_file=''
malware_result_vt_file=''
malware_path=''

#API KEY
SLACK_API_TOKEN=''
error_file=''
vt_apikey = '' # apikey(VT)

#slack channel
slack_channel_new_malware='#test_malware'
slack_channel_honeytrap ='#test_honeytrap_daily'
slack_channel_wowhoneypot='#test_wowhoneypot_daily'
slack_channel_wowhoneypotssl='#test_wowhoneypotssl_daily'

#mode setting
slack_flag='ON' # slack送信フラグ
