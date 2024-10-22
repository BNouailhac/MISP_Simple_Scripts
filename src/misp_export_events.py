from pymisp import PyMISP
import json

from conf.misp_conf import misp_url, misp_user_key, misp_verifycert

def get_all_events(misp_url, misp_key, misp_verifycert):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    # Fetch all events
    #events = misp.search(controller='events', includeDecayScore='1', limit="3", return_format='json')

    # Fetch last event
    events = misp.search_index(limit=1, page=1, sort='date')

    event = misp.get_event(events[0]['id'])

    # Convert the events to JSON format
    events_json = json.dumps(event, indent=4)

    return events_json

if __name__ == "__main__":
    events_json = get_all_events(misp_url, misp_user_key, misp_verifycert)

    # Optionally, save to a file
    with open('misp_events.json', 'w') as f:
        f.write(events_json)