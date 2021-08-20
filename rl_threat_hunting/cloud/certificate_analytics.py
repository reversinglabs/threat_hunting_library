
from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta


def pair_up_cert_task_and_response(api_response_data, tasks):
    certificate_analytics = safely_traverse_dict(api_response_data, 'rl.certificate_analytics')

    if isinstance(certificate_analytics, dict):
        certificate_analytics = [certificate_analytics]

    tasks_responses_pairs = []
    for task in tasks:
        query_term = task['query']['term']
        api_response = _find_certificate_response_for_task(certificate_analytics, query_term)
        tasks_responses_pairs.append((task, api_response))

    return tasks_responses_pairs


def _find_certificate_response_for_task(entries, query_term):
    for entry in entries:
        query_thumbprint = _get_certificate_sha256_thumbprint(entry)

        if query_thumbprint == query_term:
            return entry


def process_cert_entry(cert):
    cert_thumbprint = _get_certificate_sha256_thumbprint(cert)

    build_parameters = {
        'query_type': HuntingCategory.CERTIFICATE_ANALYTICS,
        'query_term': cert_thumbprint,
        'status': HuntingStatus.COMPLETED,
    }

    classification_summary = result_evaluation.certificate_analytics(cert)
    build_parameters.update(classification_summary)

    malicious_counters  = safely_traverse_dict(cert, 'statistics.malicious', 0)
    suspicious_counters = safely_traverse_dict(cert, 'statistics.suspicious', 0)
    build_parameters['malicious'] = malicious_counters + suspicious_counters

    return build_hunting_task_meta(**build_parameters)


def _get_certificate_sha256_thumbprint(cert):
    thumbprints = safely_traverse_dict(cert, 'certificate.certificate_thumbprints', [])
    for thumbprint in thumbprints:
        if thumbprint['name'] == 'SHA256':
            return thumbprint['value'].lower()
