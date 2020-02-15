# Workerbee
## ToDoリスト
1. VTおよびSlackのAPIキーを取得  
2. Slackのチャンネルを設定  
3. cofing.pyのファイルパスを埋める  
※error_fileは含まれていないの、自分で作成  

## 概要
本ツールはハニーポットの簡易分析を目的としたツールとなっています。  
pythonプロラグムで動作をしており、以下のスペックで動作していることを確認しております。
<VPSスペック>  
CPU:仮想1Core  
メモリ:512MB  
標準容量(SSD):25GB  
python:Python 3.6.9
## ツール機能および利用方法
### wowhoneypot_csv_write.py
#### 機能
WOWHoneypotのログをcsvにエクスポートするツールとなります。    　
本ツールでは以下の項目を取得することが可能です。  
Date,Remote IP,Local IP,Method,URI,URI Path,URI Query,Status Code,Payload  
#### 利用方法
以下のコマンドを実行
```
python3 wowhoneypot_csv_write.py <wowhoneypotのaccess_log> <出力するcsvファイルのパスおよびファイル名>
```

例：

```
python3 wowhoneypot_csv_write.py /home/ubuntu/wowhoneypot/log/access_log /home/ubuntu/wowhoneypot/log/wowhoneypot_report.csv
```
### wowhoneypot_slack.py
#### 機能
wowhoneypot_csv_write.py で出力したcsvファイルを用いて簡易分析を実施するツールです。
ipアドレス、アクセス先について分析し、必要に応じてSlackへ連携することが可能です。  
※slackへ連携する場合、config.pyのslack_flagを ON にする必要があります。  
uri_path.csv に記載されている正規表現を元に検知したURIパスがどのような製品を狙ったものであるかも判定することが可能です。 
また、WOWHoneypotをHTTPとHTTPSの両方で運用していることを想定しており、引数にてどちらのログか選択することでSlackの連携先を変更することが可能です。
#### 利用方法
以下のコマンドを実行
```
python3 wowhoneypot_slack.py  <wowhoneypot_csv_write.pyで出力したファイル> <wowhoneypot or wowhoneypotssl>
```

例：  WOWHoneypot(HTTP)に関する出力を行う場合
```
python3 wowhoneypot_csv_write.py /home/ubuntu/wowhoneypot/log/wowhoneypot_report.csv wowhoenypot
```
WOWHoneypot(HTTPS)に関する出力を行う場合
```
python3 wowhoneypot_csv_write.py /home/ubuntu/wowhoneypotssl/log/wowhoneypotssl_report.csv wowhoenypotssl
```
### honeytrap_csv_write.py
#### 機能
Honeytrapのログをcsvにエクスポートするツールとなります。  
本ツールでは以下の項目を取得することが可能です。  
Date,Malware URL,Local Port,Remote IP,URI Path,Decode Payload
#### 利用方法
以下のコマンドを実行
```
python3 honeytrap_csv_write.py <honeytrapのattackers.json> <出力するcsvファイルのパスおよびファイル名>
```

例：
```
python3 honeytrap_csv_write.py /home/ubuntu/honeytrap/log/attackers.json /home/ubuntu/honeytrap/log/honeytrap_report.csv
```
### honeytrap_slack.py
honeytrap_csv_write.py で出力したcsvファイルを用いて簡易分析を実施するツールです。
ipアドレス、マルウェアURL、アクセス先について分析し、必要に応じてSlackへ連携することが可能です。  
※slackへ連携する場合、config.pyのslack_flagを ON にする必要があります。  
uri_path.csv に記載されている正規表現を元に検知したURIパスがどのような製品を狙ったものであるかも判定することが可能です。 
#### 利用方法
以下のコマンドを実行
```
python3 honeytrap_slack.py <honeytrap_csv_write.pyで出力したファイル> 
```

例：
```
python3 honeytrap_slack.py /home/ubuntu/honeytrap/log/honeytrap_report.csv
```
### honeytrap_malware_check.py
#### 機能
Honeytrapのログで検知したマルウェアURLからマルウェアをダウンロードするツールとなります。  
HoneytrapのログからマルウェアURLを抽出し、過去に検知のないマルウェアは取得するプログラムとなります。
検知したマルウェア情報はcsvファイル(config.pyで設定)として出力されます。  
csvファイルに出力される項目は以下となります。  
Date,Malware URL,Virus Total,Remote IP,Local Port,Status Code,Malware File Name,Regular Expression,Hash(MD5),Hash(SHA1),Hash(SHA256),Payload  
マルウェアダウンロード時は以下の命名規則でファイル保存されます。  
Malware_SHA256
※マルウェアの取り扱いについては自己責任のもとで十分に注意してください。
 マルウェアの取得が不必要な場合、本ツールは必要ありません。
 
#### 利用方法
以下のコマンドを実行
```
python3 honeytrap_malware_check.py <honeytrapのattackers.json>
```

例：
```
python3 honeytrap_malware_check.py /user/ubuntu/honeytrap/log/attackers.json
```

### honeytrap_virustotal.py
#### 機能
honeytrap_malware_check.py で抽出したマルウェアをVirusTotalへ連携するツールとなります。 
virutotalで分析した結果をマルウェア情報が記載されているcsvファイルに追記します。  
連携する情報はハッシュ値およびURL情報となります。
本ツールを利用するためにはconfig.pyにVirustotalのAPIキーの入力が必要となります。  
※マルウェアの取り扱いについては自己責任のもとで十分に注意してください。
 マルウェアの取得が不必要な場合、本ツールは必要ありません。
 
#### 利用方法
以下のコマンドを実行
```
python3 honeytrap_virustotal.py
```
## 初期設定
### 1.本ツールのダウンロード

例：ツールをダウンロードするフォルダへ移動後に以下を実行
```
git clone https://github.com/sec-chick/Workerbee.git
```
### 2.pip3 のインストール
### 3.pip3でPythonのパッケージ（ライブラリ）をインストール
requirements.txtから必要なものをインストール
```
pip3 install -r requirements.txt
```
### 4.サービスの登録
マルウェア解析を行う場合、virustotalのAPIキーを取得し、slack連携を行う場合、slackのワ⁠ー⁠ク⁠ス⁠ペ⁠ー⁠スの作成およびAPIキーの取得を行なってください。  
Google先生に聞いてもらえれば、登録できると思います。
### 4.1 virustotal
ユーザ登録を行い、APIキーを取得してください。
### 4.2 slack
slackにユーザ登録を行い、ワ⁠ー⁠ク⁠ス⁠ペ⁠ー⁠スの作成およびAPIキー(OAuth Access Token)の取得を行なってください。
### 5.cofig.pyの設定
解析に必要となる情報をcofig.pyに記載します。必要な項目は以下の通りとなります。  
#### uri_path_list_csv
WOWHoneypotのどの宛先を狙ったものか分析に利用する uri_path.csv が格納されるファイルの場所を記載してください。 
※本githubのフォルダに雛形および作者が一定数分析したcsvファイルが含まれています。　　
これらのファイルをいずれかのフォルダに格納してください。　　
ヘッダのみ記載されている場合、全て新規のものとして扱われます。
本ファイルに必要な正規表現を埋め込むことによって、どの宛先を狙ったものか紐づけられるようになっています。  

例：
```
uri_path_list_csv='/home/ubuntu/Workerbee/uri_path.csv'
```
#### malware_result_file
Honeytrapのマルウェア調査結果を記載するcsvファイルの場所を記載してください。
本githubのフォルダに雛形が含まれていますので、必要に応じて適切なフォルダへ移動してください。  
なお、マルウェア分析を行わない場合、記載は不要です。

例：
```
uri_path_list_csv='/user/ubuntu/Workerbee/uri_path.csv'
```
#### malware_result_file
マルウェアを保存するフォルダを記載して下さい。

例：
```
malware_path='/home/ubuntu/malware/'
```
#### SLACK_API_TOKEN
SLACKのAPIキー(OAuth Access Token)を記載して下さい。

例：
```
SLACK_API_TOKEN='xxxx-111111111111-111111111111-a1aAaaaAAaA11aAaa1aA1aAA'
```
#### vt_apikey 
VirusTotalのAPIキーを記載してください。

例：
```
vt_apikey = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' # apikey(VT)
```
#### error_file
pythonツールのエラーを記載するcsvファイルを作成してください。
作成後にファイルのパスを記載してください。

例：
```
error_file='/home/ubuntu/error_file.csv'
```

#### slack channel
slackのチャンネル情報を入力してください。  
今回のツールでは以下の4つのチャンネル作成が必要となります。  
slack_channel_new_malware: 新規マルウェア通知用チャンネル  
slack_channel_honeytrap: Honeytrapの分析情報通知用チャンネル  
slack_channel_wowhoneypot: WOWHoneypot(HTTP)の分析情報通知用チャンネル  
slack_channel_wowhoneypotssl：WOWHoneypot(HTTPS)の分析情報通知用チャンネル  

例：
```
slack_channel_new_malware='#new_malware'
slack_channel_honeytrap='#honeytrap'
slack_channel_wowhoneypot='#wowhoneypot'
slack_channel_wowhoneypotssl='#wowhoneypotssl'
```
#### slack_flag
slackでの情報連携を行うか決めるフラグとなります。必要な場合はONに設定し、不必要な場合はNOに設定してください。

例：
```
slack_flag='ON' 
```
## uri_path.csvのチューニング
uri_path.csv に記載された１列目に正規表現を記載します。正規表現はpythonのre.matchの正規表現で評価されるため、URLの特徴をうまく正規表現に記載する必要があります。  
なお、uri_path.csv に記載された正規表現を上から評価していき、一致したものがあった場合は、break処理を行うものとなっています。
評価されるプログラム箇所の例：
```
result = re.match(uri_path.csvの1行目,評価対象のURL,re.IGNORECASE)
```
## 注意事項
### マルウェア分析機能を利用する場合は、自己責任で十分に注意した上で行なってください。
### Honeytrapにつきましてはattakers.jsonファイルのサイズが3GB程度までは動作したことは確認しておりますが、非常に大きなファイルサイズの場合、適切に処理できない可能性があるので、注意してください。
### csvファイルに出力する関係上、ファイルサイズが大きくなる傾向にあるため、容量に注意して運用してください。
