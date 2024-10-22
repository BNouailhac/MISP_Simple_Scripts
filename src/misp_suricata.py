from pymisp import PyMISP
import pandas as pd
import re
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert

def concatenate_columns(series):
    unique_values = series.astype(str).unique()
    return ' | '.join(unique_values)

# We're temporarily removing sid and mesage from the rules to eliminate unnecessary duplication of rules.
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

    row['rules'] = row['rules'].replace("sid:;", 'sid:' + str(row['sid']) + ';')

    row['rules'] = row['rules'] + '\n'
    return row

misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

# Takes all the events according to the parameters and puts the result in a usable .rules file
suricata_rules = misp.search(controller="attributes", return_format="suricata")

if not suricata_rules:
    print('No results for those params')
    exit(0)
else:
    # If a result has been recovered, the rules are reformatted to avoid bugs.
    new_lines = []
    rules = suricata_rules.split('alert ') # To force each rule to be on different lines (because this isn't the basic case)
    df = pd.DataFrame(rules, columns=['rules'])

    df = df.drop(index=0).reset_index(drop=True)

    print(len(df))

    df = df.apply(modify_rule, axis=1)

    # For each identical rule, keep the highest SID and put their source event id together
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
