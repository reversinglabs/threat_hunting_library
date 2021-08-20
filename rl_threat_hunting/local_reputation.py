
from datetime import datetime
from collections import OrderedDict

from rl_threat_hunting import utils
from rl_threat_hunting import tc_metadata_adapter
from rl_threat_hunting.filter import intersting_children
from rl_threat_hunting.adapter import sample_info
from rl_threat_hunting.utils import is_python2_executing
from rl_threat_hunting.utils import iteritems


HASHES = ['sha1', 'sha256', 'md5']
INTEGER_FIELDS = {'factor', 'scanner_count', 'scanner_match'}

CLOUD_CLASSIFICATION = 'cloud'
USER_CLASSIFICATION  = 'user'
ALLOWED_CLASSIFICATION_REASON = {CLOUD_CLASSIFICATION, USER_CLASSIFICATION}


def process_local_reputation(api_request_function, samples_meta, hunting_state=None):
    """
    :param api_request_function: Request function on /api/samples/list/details/ endpoint on the A1000.
                                 Function will fetch classification meta for multiple samples.
                                 Function takes list of hashes as an argument.
    :param samples_meta: One or more instances of the TC metadata or the Child class.
                         If Child objects are passed, TC metadata is extracted from them.
    :param hunting_state: Threat hunting state from previous hunting steps.
                          The cloud_reputation section will be updated if there is an user override.
    :return: Enriched TC metadata with cloud reputation or local A1000 user override.
    """

    if not samples_meta:
        return []

    meta_map  = {}
    child_map = {}
    for sample in samples_meta:
        if isinstance(sample, intersting_children.Child):
            tc_meta = sample.get_tc_report()
            child_map[sample.sha1] = sample
        else:
            tc_meta = sample

        sha1 = tc_meta['sha1']
        meta_map[sha1] = tc_meta

    tc_meta_reputation_pairs = _local_file_reputation(meta_map.values(), api_request_function)
    updated_tc_meta          = parse_reputation_metadata(tc_meta_reputation_pairs, hunting_state)

    for updates in updated_tc_meta:
        sha1 = updates['sha1']
        tc_meta = meta_map[sha1]
        tc_meta.update(updates)

        child = child_map.get(sha1)
        if child:
            child.update_tc_report(tc_meta)

    if hunting_state:
        tc_metadata_adapter.build_hunting_tasks_and_summarize(hunting_state)

    return samples_meta


def _local_file_reputation(ticore_responses, api_request_function):
    samples = {}
    for tc_report in ticore_responses:
        container_hashes = sample_info.extract_interesting_hashes(tc_report)
        hash_value, hash_type = get_valid_hash(container_hashes)
        if hash_value:
            samples[hash_value] = {
                'hash_type': hash_type,
                'tc_report': tc_report,
            }

    if is_python2_executing():
        api_data = api_request_function(samples.keys())
    else:
        api_data = api_request_function(list(samples.keys()))
    if api_data:
        for result in api_data['results']:
            hash_value, _ = get_valid_hash(result)
            samples[hash_value]['reputation'] = result

    tc_meta_reputation_pairs = []
    for _, sample in iteritems(samples):
        tc_report = sample['tc_report']
        result    = sample.get('reputation')
        tc_meta_reputation_pairs.append((tc_report, result))

    return tc_meta_reputation_pairs


def parse_reputation_metadata(tc_meta_reputation_pairs, hunting_state=None):
    tc_reports = []
    for tc_meta, api_data in tc_meta_reputation_pairs:
        if api_data:
            classification_reason = api_data.get('classification_reason', '').lower()
            cloud_reputation      = compose_local_reputation(api_data)

            if is_container(hunting_state, api_data) and classification_reason == USER_CLASSIFICATION:
                cloud_reputation['is_user_override'] = True
                update_hunting_state(hunting_state, cloud_reputation)

            if cloud_reputation and classification_reason in ALLOWED_CLASSIFICATION_REASON:
                tc_meta['cloud_reputation'] = cloud_reputation

        tc_reports.append(tc_meta)

    return tc_reports


def is_container(hunting_state, api_data):
    if not hunting_state or not api_data:
        return
    hash_value, hash_type = get_valid_hash(api_data)
    container_hash = hunting_state['sample_info'].get(hash_type, '')
    return hash_value == container_hash


def get_valid_hash(api_data):
    for hash_name in HASHES:
        hash_value = api_data.get(hash_name)
        if hash_value:
            return hash_value, hash_name
    raise ValueError('No hash found. API response: {}'.format(api_data))


def compose_local_reputation(api_data):
    cloud_reputation = OrderedDict()

    classification  = api_data.get('threat_status', '').lower()
    scanner_summary = api_data.get('av_scanners_summary', {})
    for name, value in [('classification', classification),
                        ('threat_name'   , api_data.get('threat_name', '')),
                        ('factor'        , utils.get_factor(api_data, classification)),
                        ('first_seen'    , api_data.get('local_first_seen')),
                        ('last_seen'     , api_data.get('local_last_seen')),
                        ('scanner_count' , scanner_summary.get('scanner_count')),
                        ('scanner_match' , scanner_summary.get('scanner_match'))]:
        if value or (name in INTEGER_FIELDS and value == 0):
            cloud_reputation[name] = value

    return cloud_reputation


def update_hunting_state(hunting_state, new_cloud_reputation):
    previous_reputation = hunting_state['sample_info']['cloud_reputation']

    new_first_seen = new_cloud_reputation.get('first_seen')
    new_last_seen  = new_cloud_reputation.get('last_seen')

    prev_first_seen  = previous_reputation.get('first_seen')
    prev_last_seen   = previous_reputation.get('last_seen')

    updates = {}
    if is_first_seen_older(new_first_seen, prev_first_seen) or (new_first_seen and not prev_first_seen):
        updates['first_seen'] = new_first_seen

    if is_last_seen_newer(new_last_seen, prev_last_seen) or (new_last_seen and not prev_last_seen):
        updates['last_seen'] = new_last_seen

    new_cloud_reputation.update(updates)
    hunting_state['sample_info']['cloud_reputation'] = new_cloud_reputation


def is_first_seen_older(new, previous):
    return (new and previous) and (date(new) < date(previous))


def is_last_seen_newer(new, previous):
    return (new and previous) and (date(new) > date(previous))


def date(iso_date):
    # A1000 iso_date format         : 2019-09-09T11:09:24.071789Z
    # Reputation API iso_date format: 2020-03-06T06:27:48
    try:
        parsed_date = datetime.strptime(iso_date, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        parsed_date = datetime.strptime(iso_date, '%Y-%m-%dT%H:%M:%S')

    return parsed_date
