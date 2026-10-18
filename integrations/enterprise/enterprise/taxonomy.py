"""Taxonomy enrichment requires a trusted detector's explicit attribution.

The gateway cannot infer an attack technique solely from an access denial.
Agent-supplied IDs never flow into this interface automatically.
"""
import json
from pathlib import Path
CATALOG = json.loads(Path(__file__).with_name('atlas_catalog.json').read_text())


def enrich(event, technique_id, *, basis, evidence_id):
    if technique_id not in CATALOG['techniques']:
        raise ValueError('unsupported ATLAS technique')
    if basis not in {'analyst_review', 'trusted_detector', 'synthetic_test'}:
        raise ValueError('trusted attribution basis required')
    if type(evidence_id) is not str or not 1 <= len(evidence_id) <= 160:
        raise ValueError('evidence reference required')
    # Fresh output avoids mutating an already committed journal event.
    import copy
    result = copy.deepcopy(event)
    result['threat'] = {'framework': 'MITRE ATLAS',
        'technique': [{'id': technique_id, 'name': CATALOG['techniques'][technique_id],
            'reference': 'https://atlas.mitre.org/techniques/' + technique_id}]}
    result.setdefault('aa_ztce', {})['attribution'] = {
        'basis': basis, 'evidence_id': evidence_id, 'collection_version': CATALOG['collection_version'],
        'source_sha256': CATALOG['source_sha256'], 'simulated': basis == 'synthetic_test'}
    return result
