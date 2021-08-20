
from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta


def pair_up_uri_task_and_response(api_response_data, tasks):
    uri_state = safely_traverse_dict(api_response_data, 'rl.uri_state')
    return [(tasks[0], uri_state)]


def process_uri_entry(uri):
    query_term = _get_uri_term(uri)

    build_parameters = {
        'query_type': HuntingCategory.URI_ANALYTICS,
        'query_term': query_term,
        'status': HuntingStatus.COMPLETED,
    }

    classification_summary = result_evaluation.uri_analytics(uri)
    build_parameters.update(classification_summary)

    malicious_counters  = safely_traverse_dict(uri, 'counters.malicious', 0)
    suspicious_counters = safely_traverse_dict(uri, 'counters.suspicious', 0)
    build_parameters['malicious'] = malicious_counters + suspicious_counters

    return build_hunting_task_meta(**build_parameters)


def _get_uri_term(uri):
    uri_type = uri['uri_type']
    return uri[uri_type]
