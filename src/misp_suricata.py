from pymisp import PyMISP
import pandas as pd
import re
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert
""" import time
start = time.time() """

def concatenate_columns(series):
    unique_values = series.astype(str).unique()
    return ' | '.join(unique_values)

# On enlève temporairement les sid et les mesages des règles pour disserné les duplications de règles inutiles
def modify_rule(row):
    sid = re.search(r'sid:(.*?);', row['rules'])
    msg = re.search(r'msg: "(.*?)";', row['rules'])
    if sid and msg:
        row['rules'] = "alert " + row['rules'].replace(sid.group(1), '')
        row['rules'] = row['rules'].replace(msg.group(1), '')
        row['sid'] = sid.group(1)
        ruleurl = re.search(r'reference:url,(.*?);', row['rules'])
        if (ruleurl):
            row['rules'] = row['rules'].replace("reference:url," + ruleurl.group(1) + ';', '')
            row['msg'] = ruleurl.group(1).split('/')[-1]
    return row

def merge_row(row):
    row['rules'] = row['rules'].replace('msg: "";', 'msg:"MISP event(s): ' + row['msg'] + '";')

    try: # Empeche les règles de MISP d'être en colision avec les règles de EmergingThreat
        if (int(row['sid']) > 2000000 and int(row['sid']) < 3000000):
            row['rules'] = row['rules'].replace("sid:;", 'sid:' + str(int(row['sid']) - 1000000) + ';') # 1000000 - 1999999 Reserved sids for Local Use
        else:
            row['rules'] = row['rules'].replace("sid:;", 'sid:' + str(row['sid']) + ';')
    except:
        row['rules'] = row['rules'].replace("sid:;", 'sid:' + str(row['sid']) + ';')

    row['rules'] = row['rules'] + '\n'
    return row

misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

# Prend tous les évènements selon les params met le résultat dans un fichier .rules exploitable
suricata_rules = misp.search(controller="attributes", return_format="suricata")

if not suricata_rules:
    print('No results for those params')
    exit(0)
else:
    # Si un résultat à été récupéré, on reformate les règles pour éviters des bugs.
    new_lines = []
    rules = suricata_rules.split('alert ') # Pour forcer chaque règles à être sur des lignes différentes (car c'est pas le cas de base)
    df = pd.DataFrame(rules, columns=['rules'])

    df = df.drop(index=0).reset_index(drop=True)

    print(len(df))

    df = df.apply(modify_rule, axis=1)

    # Pour chaque règles identique, garde le SID le plus élevé et met ensemble leurs event id source
    df_merged = df.groupby('rules', as_index=False).agg({
        'msg': concatenate_columns,
        'sid': "max"
    })

    df_merged = df_merged.apply(merge_row, axis=1)

    print(len(df_merged))

    # Saving rules to a file
    with open('rule/misp.rules', 'w') as f:
        for row in df_merged["rules"]:
            f.write(row)

""" end = time.time()
print(end - start) # time in seconds """