from pymisp import PyMISP
from collections import defaultdict
import pandas as pd
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert
import json

misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

# Function to extract tags as a list of tag names
def extract_tag_names(tags):
    if tags != False:
        return [tag['name'] for tag in tags]
    else:
        return []

def extract_threat_level(levelId):
    match levelId:
        case "1":
            return 'High'
        case "2":
            return 'Medium'
        case "3":
            return 'Low'
        case "4":
            return 'Undefined'
        case _:
            return 'Unknow'

def extract_analysis_level(analysisId):
    match analysisId:
        case "0":
            return 'Initial'
        case "1":
            return 'Ongoing'
        case "2":
            return 'Complete'
        case _:
            return 'Unknow'

# Returns attributes sorted by type in csv format
events = misp.search(controller='events', includeDecayScore='1', return_format='json')

# Define here the types of misp IOC that you are not interested in recovering
unwanted_types = [
                    "AS",
                    "comment",
                    "datetime",
                    "email-body",
                    "http-method",
                    "mime-type",
                    "other",
                    "port",
                    "sigma",
                    "size-in-bytes",
                    "snort",
                    "target-external",
                    "target-location",
                    "target-machine",
                    "target-org",
                    "target-user",
                    "vulnerability",
                    "whois-creation-date",
                    "yara"
                ]

# Categorize attributes by type and include event info
attributes_by_type = defaultdict(list)
for event in events:
    event_info = {
        'event_id': event['Event']['id'],
        'event_info': event['Event']['info'],
        'event_threat_level': extract_threat_level(event['Event']['threat_level_id']),
        'event_analysis_level': extract_analysis_level(event['Event']['analysis']),
        'event_org': event["Event"]["Orgc"]["name"],
        'event_date': event["Event"]["date"],
        'event_tags': extract_tag_names(event['Event'].get('Tag', False))
    }
    for attribute in event['Event']['Attribute']:
        attribute_type = attribute.get("type", "")
        if attribute_type not in unwanted_types:
            attribute = {
                'value': attribute.get("value", ""),
                'type': attribute.get("type", ""),
                'category': attribute.get("category", ""),
                'event_tags': extract_tag_names(attribute.get('Tag', False)),
                'comment': attribute.get("comment", ""),
                'first_seen': attribute.get("first_seen", ""),
                'last_seen': attribute.get("last_seen", ""),
                'score': attribute.get("decay_score", "")
            }
            attribute_with_event_info = {**attribute, **event_info}
            attributes_by_type[attribute_type].append(attribute_with_event_info)

# Save attributes to separate csv files by type
for attribute_type, attrs in attributes_by_type.items():
    attributecsv = pd.DataFrame(attrs)
    attributecsv.to_csv('attribute/' + attribute_type + '.csv', index=False)
