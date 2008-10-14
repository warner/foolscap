
# this is a plugin for "flogtool classify-incident" or the Incident Gatherer

import re

TUBCON_RE = re.compile(r'^Tub.connectorFinished: WEIRD, <foolscap.negotiate.TubConnector instance at \w+> is not in \[')
def classify_incident(trigger):
    m = trigger.get('message', '')
    if TUBCON_RE.search(m):
        return 'foolscap-tubconnector'
    return None
