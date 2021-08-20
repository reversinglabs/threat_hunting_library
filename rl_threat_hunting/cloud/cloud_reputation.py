
from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import Classification
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.mwp_metadata_adapter import compose_cloud_reputation
from rl_threat_hunting.adapter.threat_hunting import build_threat_field
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta


def pair_up_cloud_task_and_response(api_response_data, tasks):
    mwp_single_query = safely_traverse_dict(api_response_data, 'rl.malware_presence')
    mwp_bulk_query   = safely_traverse_dict(api_response_data, 'rl.entries', [])

    if mwp_single_query:
        return [(tasks[0], mwp_single_query)]

    tasks_responses_pairs = []
    for task in tasks:
        query_term   = task['query']['term']
        api_response = _find_cloud_response_for_task(mwp_bulk_query, query_term)
        tasks_responses_pairs.append((task, api_response))

    return tasks_responses_pairs


def update_sample_info_with_cloud_reputation(tc_meta, tasks_response_pairs):
    container_sample_info = tc_meta['sample_info']

    for _, api_response in tasks_response_pairs:
        if not api_response:
            continue

        query_sha1 = _get_query_hash(api_response)

        if query_sha1 != container_sample_info.get('sha1'):
            children = safely_traverse_dict(container_sample_info, 'relationships.children', [])
            sample_info = _get_child_info_for_hash(children, query_sha1)
        else:
            sample_info = container_sample_info

        cloud_reputation = compose_cloud_reputation(api_response)
        if sample_info and cloud_reputation:
            sample_info['cloud_reputation'] = cloud_reputation


def _find_cloud_response_for_task(entries, query_term):
    for entry in entries:
        query_hash = _get_query_hash(entry)

        if query_hash == query_term:
            return entry


def process_mwp_entry(mwp):
    sample_sha1 = _get_query_hash(mwp)

    build_parameters = {
        'query_type' : HuntingCategory.CLOUD_REPUTATION,
        'query_term' : sample_sha1,
        'status'     : HuntingStatus.COMPLETED,
    }

    classification_summary = result_evaluation.malware_presence(mwp)
    build_parameters.update(classification_summary)

    if Classification.is_malware(classification_summary['classification']):
        build_parameters['malicious'] = 1

        threat_info = build_threat_field(
            mwp.get('status'),
            mwp.get('threat_name'),
            mwp.get('threat_level')
        )
        if threat_info:
            build_parameters['threats'] = [threat_info]
    else:
        build_parameters['malicious'] = 0

    return build_hunting_task_meta(**build_parameters)


def _get_query_hash(mwp):
    sha1_hash = mwp.get('sha1')
    if sha1_hash:
        return sha1_hash

    query_hash = mwp['query_hash']

    try:
        hash_type  = query_hash.keys()[0]
    except TypeError:
        hash_type_keys = list(query_hash.keys())
        hash_type = hash_type_keys[0]

    return query_hash[hash_type]


def _get_child_info_for_hash(children, sha1):
    for child_info in children:
        if sha1 == child_info['sha1']:
            return child_info
