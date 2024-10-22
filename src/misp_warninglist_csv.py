from pymisp import PyMISP
from collections import defaultdict
import pandas as pd
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert

# Initialize PyMISP
misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

# Retrieve all warning lists
warninglists = misp.warninglists()

# Dictionary to hold warning lists and their linked attributes
WarningListAttributes = defaultdict(list)

# Loop through each warning list to get linked attributes
for warninglist in warninglists:
    attributes = misp.get_warninglist(warninglist['Warninglist']['id'])
    attribute_type = attributes['Warninglist']['type']
    warninglist = {
        'type': attribute_type,
        'category': attributes['Warninglist']['category'],
        'name': attributes['Warninglist']['name'],
        'description': attributes['Warninglist']['description'],
        'warninglist_id': attributes['Warninglist']['id']
    }

    for attribute in attributes['Warninglist']['WarninglistEntry']:

        attribute = {
            'value': attribute['value']
        }
        allattributes_ofwarninglist = {**attribute, **warninglist}
        WarningListAttributes[attribute_type].append(allattributes_ofwarninglist)

# Save attributes to separate csv files by type
for attribute_type, attrs in WarningListAttributes.items():
    attributecsv = pd.DataFrame(attrs)
    attributecsv.to_csv('warninglist/' + attribute_type + '.csv', index=False)