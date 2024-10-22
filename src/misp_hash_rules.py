from pymisp import PyMISP
from collections import defaultdict
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert
import json

misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

### md5 ###
mispAttributes = misp.search(controller="attributes", return_format="json", type_attribute="md5")
hashValues = []
for attribute in mispAttributes['Attribute']:
    hashValues.append(attribute['value'] + '\n')
# remove duplicates
hashValues = list(set(hashValues))
with open('./hash/misp_md5.txt', 'w') as f:
    for hashvalue in hashValues:
        f.write(hashvalue)

### sha1 ###
mispAttributes = misp.search(controller="attributes", return_format="json", type_attribute="sha1")
hashValues = []
for attribute in mispAttributes['Attribute']:
    hashValues.append(attribute['value'] + '\n')
# remove duplicates
hashValues = list(set(hashValues))
with open('./hash/misp_sha1.txt', 'w') as f:
    for hashvalue in hashValues:
        f.write(hashvalue)

### sha256 ###
mispAttributes = misp.search(controller="attributes", return_format="json", type_attribute="sha256")
hashValues = []
for attribute in mispAttributes['Attribute']:
    hashValues.append(attribute['value'] + '\n')
# remove duplicates
hashValues = list(set(hashValues))
with open('./hash/misp_sha256.txt', 'w') as f:
    for hashvalue in hashValues:
        f.write(hashvalue)

#suricata rules
# default files location : /etc/suricata/rules/
hashRules = [
    'alert http any any -> any any (msg:"md5 hash detection from MISP"; flow: established; filemd5:/etc/suricata/rules/misp_md5.txt; sid:1; rev:1;)\n',
    'alert http any any -> any any (msg:"sha1 hash detection from MISP"; flow: established; filesha1:/etc/suricata/rules/misp_sha1.txt; sid:2; rev:1;)\n',
    'alert http any any -> any any (msg:"sha256 hash detection from MISP"; flow: established; filesha256:/etc/suricata/rules/misp_sha256.txt; sid:3; rev:1;)\n'
]
with open('./rule/hash.rules', 'w') as f:
    for rule in hashRules:
        f.write(rule)
