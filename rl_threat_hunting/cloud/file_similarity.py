
from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta


def pair_up_rha_task_and_response(api_response_data, tasks):
    single_query = safely_traverse_dict(api_response_data, 'rl.rha1_counters')
    bulk_query   = safely_traverse_dict(api_response_data, 'rl.entries', [])

    if single_query:
        return [(tasks[0], single_query)]

    tasks_responses_pairs = []
    for task in tasks:
        query_term   = task['query']['term']
        api_response = _find_rha_response_for_task(bulk_query, query_term)
        tasks_responses_pairs.append((task, api_response))

    return tasks_responses_pairs


def _find_rha_response_for_task(entries, query_term):
    for entry in entries:
        query_rha = _get_rha_identifier(entry)

        if query_rha == query_term:
            return entry


def process_rha_entry(rha):
    query_term = _get_rha_identifier(rha)

    build_parameters = {
        'query_type': HuntingCategory.FILE_SIMILARITY_ANALYTICS,
        'query_term': query_term,
        'status': HuntingStatus.COMPLETED,
    }
    classification_summary = result_evaluation.rha1_analytics(rha)
    build_parameters.update(classification_summary)

    malicious_counters = safely_traverse_dict(rha, 'sample_counters.malicious', 0)
    suspicious_counters = safely_traverse_dict(rha, 'sample_counters.suspicious', 0)
    build_parameters['malicious'] = malicious_counters + suspicious_counters

    return build_hunting_task_meta(**build_parameters)


def _get_rha_identifier(rha_entry):
    sample_sha1 = rha_entry['sha1']
    rha_type    = rha_entry['rha1_type']
    return '{}/{}'.format(rha_type, sample_sha1)
