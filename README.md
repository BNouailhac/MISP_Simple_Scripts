# MISP Simple Scripts
This code provides several scripts for exploiting data from a local MISP installation.

## Packages python utilisés :
- json
- csv
- datetime
- pandas

## Usage
The local MISP api connection variables are in the ‘src/conf/misp_conf.py’ file.

### misp_create_event.py
Script to create a new event in misp

```
$ python3 ./src/create_event.py
```

### misp_attribute_csv.py
Takes all the events from the MISP instance to extract the IOCs and create a .csv file for each type of IOC (in the attribute/ folder)

```
$ python3 ./src/misp_attribute_csv.py
```

### misp_suricata.py
Takes all the events from the MISP instance and creates suricata rules to detect them (in the rule/misp.rules file)

```
$ python3 ./src/misp_suricata.py
```

### misp_hash_rules.py
Takes all suricata-compatible file hash IOCs (md5, sha1 and sha256) from the MISP instance to create files collecting them (in the hash/ folder) and a suricata rules file detecting file hashes from these files (in the rule/hash.rules file)

```
$ python3 ./src/misp_hash_rules.py
```

### misp_warninglist_csv.py
Takes all the warninglists in the MISP instance, extracts the IOCs and creates a .csv file for each type (in the warninglist/ folder)

```
$ python3 ./src/misp_warninglist_csv.py
```

### misp_pull_feeds.py
From online IOC feeds url (list of feeds available for MISP found on our local instance at : /feeds/index) and drop the files found in the feeds/ folder.

```
$ python3 ./src/misp_pull_feeds.py
```
### misp_push_event.py
Take all the files in the feeds folder and import them into the local misp instance

```
$ python3 ./src/misp_push_event.py
```
