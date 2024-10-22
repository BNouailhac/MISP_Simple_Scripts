from pymisp import PyMISP, MISPEvent, MISPAttribute
from datetime import datetime
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert

misp = PyMISP(misp_url, misp_user_key, misp_verifycert)

# Create an event that can be exported in suricata rules
def create_event(_distribution, _threat_level, _analysis, _info, _attribute, _tags):
    event = MISPEvent()

    # Your distribution choice:
    # 0 - This Organization only
    # 1 - This community only
    # 2 - Connected communities
    # 3 - All communities
    event.distribution = _distribution

    # threat:
    # 1 - High
    # 2 - Medium
    # 3 - Low
    # 4 - Undefined
    event.threat_level_id = _threat_level

    # Represents the analysis maturity level:
    # 0 - Initial
    # 1 - Ongoing
    # 2 - Complete
    event.analysis = _analysis
    event.info = _info
    event.date = datetime.now().date().isoformat() # Today's date

    # Adding an attribute (IOC) that Suricata can use, such as a domain
    attr = MISPAttribute()
    attr.category = _attribute["category"]
    attr.type = _attribute["type"]
    attr.value = _attribute["value"]
    attr.to_ids = True  # Mark as to_ids to be used for IDS export
    attr.comment = _attribute["comment"]

    event.add_attribute(**attr)

    # Adding Tags (Works only if specified tag already exist)
    for tag in _tags:
        event.add_tag(tag)

    # Upload the event to MISP
    response = misp.add_event(event)
    # Publish event to allow his export later
    misp.publish(event)

# Exemple Usage :
event_id = create_event(3, 1, 1, "Example event with network IOC for Suricata", {"category": 'Network activity', "type": 'domain', "value": 'Vilain.com', "comment": 'Test domain for Suricata rule generation'}, ["tlp:white", "Phising"])
