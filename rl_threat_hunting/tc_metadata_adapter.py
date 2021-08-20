
from copy import deepcopy
from collections import OrderedDict

from rl_threat_hunting.utils import encode_unicode
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.utils import is_python2_executing
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.child_evaluation import tiscale_select_interesting_children
from rl_threat_hunting.adapter.sample_info import compose_sample_info
from rl_threat_hunting.adapter.readable_summary import compose_sample_description
from rl_threat_hunting.adapter.readable_summary import compose_final_classification
from rl_threat_hunting.adapter.readable_summary import compose_cloud_hunting_summary
from rl_threat_hunting.adapter.readable_summary import compose_local_hunting_summary
from rl_threat_hunting.adapter.readable_summary import compose_attack_matrix
from rl_threat_hunting.adapter.threat_hunting import ThreatHuntingReports
from rl_threat_hunting.adapter.email import extract_attachments
from rl_threat_hunting.adapter.documents import extract_scripts


def parse_tc_metadata(service_response, threat_hunting_state=None):
    tc_reports = service_response.get('tc_report', [service_response])

    tc_meta = OrderedDict()

    sample_info = generate_sample_info(tc_reports)
    if sample_info:
        if is_python2_executing():
            sample_info = encode_unicode(sample_info)

        if threat_hunting_state:
            sample_info['cloud_reputation'] = threat_hunting_state['sample_info']['cloud_reputation']

        tc_meta['sample_info'] = sample_info
        build_hunting_tasks_and_summarize(tc_meta)

    return tc_meta


def generate_sample_info(tc_reports):
    container_report = tc_reports[0]

    sample_info = compose_sample_info(container_report)

    child_reports = tc_reports[1:]
    if child_reports:
        add_relationships(sample_info, 'children')
        interesting_children = tiscale_select_interesting_children(child_reports)
        for child in interesting_children:
            child_sample_info = compose_sample_info(child.tc_report)
            sample_info['relationships']['children'].append(child_sample_info)

        if is_email(sample_info):
            append_attachments_to_email(sample_info, interesting_children)

        if is_document(sample_info):
            append_scripts_to_document(sample_info)

    return sample_info


def build_hunting_tasks_and_summarize(tc_meta):
    sample_info = tc_meta['sample_info']

    threat_hunting = generate_threat_hunting(sample_info)
    if threat_hunting:
        tc_meta['cloud_hunting'] = threat_hunting

        local_hunting = build_local_hunting_tasks(threat_hunting)
        if local_hunting:
            tc_meta['local_hunting'] = local_hunting

    readable_summary = generate_readable_summary(tc_meta)
    if readable_summary:
        tc_meta['readable_summary'] = readable_summary


def generate_threat_hunting(sample_info):
    threat_hunting = ThreatHuntingReports()
    threat_hunting.add_hunting_data(sample_info)

    children_sample_info = safely_traverse_dict(sample_info, 'relationships.children', [])
    for child_sample_info in children_sample_info:
        child_sha1 = child_sample_info.get('sha1')
        threat_hunting.add_hunting_data(child_sample_info, propagated=child_sha1)

    return threat_hunting


def build_local_hunting_tasks(threat_hunting):
    local_hunting_tasks = ThreatHuntingReports()
    for task in threat_hunting:
        if task['query']['type'] == HuntingCategory.ADVANCED_SEARCH:
            local_task = deepcopy(task)
            local_hunting_tasks.append(local_task)

    return local_hunting_tasks


def generate_readable_summary(tc_meta):
    sample_info    = tc_meta['sample_info']
    cloud_hunting  = _get_threat_hunting(tc_meta, 'cloud_hunting')
    local_hunting  = _get_threat_hunting(tc_meta, 'local_hunting')
    classification = compose_final_classification(sample_info, cloud_hunting, local_hunting)

    summary = OrderedDict()
    summary['classification'] = classification
    summary['sample']         = compose_sample_description(sample_info)
    summary['cloud_hunting']  = _summarize_threat_hunting(classification, cloud_hunting, compose_cloud_hunting_summary) if cloud_hunting else []
    summary['local_hunting']  = _summarize_threat_hunting(classification, local_hunting, compose_local_hunting_summary) if local_hunting else []
    summary['att&ck']         = compose_attack_matrix(sample_info)

    return summary


def _get_threat_hunting(tc_meta, hunting_key):
    threat_hunting = tc_meta.get(hunting_key)
    if threat_hunting:
        threat_hunting = ThreatHuntingReports(threat_hunting)
    return threat_hunting


def _summarize_threat_hunting(classification, threat_hunting, summary_function):
    if classification.is_final():
        threat_hunting.update_all_pending_to_skipped()
    return summary_function(threat_hunting)


def add_relationships(sample_info, relationship_type):
    if 'relationships' not in sample_info:
        sample_info['relationships'] = {relationship_type: []}
    elif 'children' not in sample_info['relationships']:
        sample_info['relationships'][relationship_type] = []


def append_attachments_to_email(sample_info, interesting_children):
    children_sample_info = safely_traverse_dict(sample_info, 'relationships.children', [])
    children_tc_reports  = [child.tc_report for child in interesting_children]

    # Same indices in children_sample_info and children_tc_reports have to share information about the same sample.
    attachments = extract_attachments(children_tc_reports, children_sample_info)
    if attachments:
        sample_info['email']['attachment'] = attachments


def is_email(sample_info):
    return 'email' in sample_info


def append_scripts_to_document(sample_info):
    children_sample_info = safely_traverse_dict(sample_info, 'relationships.children', [])
    scripts = extract_scripts(children_sample_info)
    if scripts:
        sample_info['document']['scripts'] = scripts


def is_document(sample_info):
    return 'document' in sample_info
