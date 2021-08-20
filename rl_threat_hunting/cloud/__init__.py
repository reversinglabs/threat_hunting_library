
from rl_threat_hunting import result_evaluation
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.tc_metadata_adapter import generate_readable_summary


from rl_threat_hunting.cloud import certificate_analytics
from rl_threat_hunting.cloud import cloud_reputation
from rl_threat_hunting.cloud import file_similarity
from rl_threat_hunting.cloud import uri_analytics
from rl_threat_hunting.cloud.advanced_search import AdvancedSearchInterface


PROCESSING_FUNCTIONS = {
    HuntingCategory.CLOUD_REPUTATION          : cloud_reputation.process_mwp_entry,
    HuntingCategory.CERTIFICATE_ANALYTICS     : certificate_analytics.process_cert_entry,
    HuntingCategory.FILE_SIMILARITY_ANALYTICS : file_similarity.process_rha_entry,
    HuntingCategory.URI_ANALYTICS             : uri_analytics.process_uri_entry,
    HuntingCategory.ADVANCED_SEARCH           : AdvancedSearchInterface.process_search_entry,
}

PAIRING_FUNCTIONS = {
    HuntingCategory.CLOUD_REPUTATION          : cloud_reputation.pair_up_cloud_task_and_response,
    HuntingCategory.CERTIFICATE_ANALYTICS     : certificate_analytics. pair_up_cert_task_and_response,
    HuntingCategory.FILE_SIMILARITY_ANALYTICS : file_similarity.pair_up_rha_task_and_response,
    HuntingCategory.URI_ANALYTICS             : uri_analytics.pair_up_uri_task_and_response,
    HuntingCategory.ADVANCED_SEARCH           : AdvancedSearchInterface.pair_up_search_task_and_response,
}


def get_query_tasks(tc_meta, task_type):
    HuntingCategory.validate_task_category(task_type)

    tasks = []
    for task in tc_meta.get('cloud_hunting', []):
        if task['query']['type'] == task_type:
            tasks.append(task)
    return tasks


def update_hunting_meta(tc_meta, api_response_data, *tasks):
    if not tasks:
        raise ValueError('Task(s) argument not provided.')

    task_type           = _get_type_for_tasks(tasks)
    pair_function       = PAIRING_FUNCTIONS[task_type]
    processing_function = PROCESSING_FUNCTIONS[task_type]

    if api_response_data:
        tasks_responses_pairs  = pair_function(api_response_data, tasks)

        if task_type == HuntingCategory.CLOUD_REPUTATION:
            cloud_reputation.update_sample_info_with_cloud_reputation(tc_meta, tasks_responses_pairs)

        tasks_without_response = _update_completed_tasks(tc_meta, tasks_responses_pairs, processing_function)
    else:
        tasks_without_response = tasks

    update_tasks_without_response(tasks_without_response)

    threat_hunting = tc_meta['cloud_hunting']
    summarize_hunting_results(tc_meta)

    if task_type == HuntingCategory.ADVANCED_SEARCH and \
       AdvancedSearchInterface.check_search_early_exit_condition(api_response_data, tasks[0]):
        mark_pending_tasks_as_skipped(threat_hunting, HuntingCategory.ADVANCED_SEARCH)
        raise StopIteration('Malicious Advanced Search response. No need for further processing, break iteration.')


def _get_type_for_tasks(tasks):
    first_task_type = None
    for task in tasks:
        task_type = task['query']['type']

        if first_task_type is None:
            first_task_type = task_type

        elif task_type != first_task_type:
            raise ValueError('Update supported for one task type at the time. '
                             'Task types detected: {} and {}'.format(first_task_type, task_type))

    return task_type


def _update_completed_tasks(tc_meta, tasks_responses_pairs, processing_function):
    tasks_without_response = []
    for task, api_response in tasks_responses_pairs:
        if api_response:
            updated_task = processing_function(api_response)
            _update_hunting_task(tc_meta, updated_task)
        else:
            tasks_without_response.append(task)
    return tasks_without_response


def _update_hunting_task(tc_meta, task):
    threat_hunting = tc_meta['cloud_hunting']

    query_type = task['query']['type']
    query_term = task['query']['term']

    for hunting_task in threat_hunting:
        if hunting_task['query']['type'] == query_type and hunting_task['query']['term'] == query_term:
            hunting_task.update(task)


def update_tasks_without_response(tasks):
    for task in tasks:
        task['query']['status'] = HuntingStatus.COMPLETED
        classification_summary = result_evaluation.classify_empty_response()
        task.update(classification_summary)


def summarize_hunting_results(tc_meta):
    readable_summary = generate_readable_summary(tc_meta)
    if readable_summary:
        tc_meta['readable_summary'] = readable_summary


def mark_tasks_as_failed(tc_meta, *tasks):
    threat_hunting = tc_meta['cloud_hunting']

    task_lookup = map_tasks(tasks)

    for hunting_task in threat_hunting:
        task_key = get_task_key(hunting_task)

        if task_lookup.get(task_key):
            hunting_task['query']['status'] = HuntingStatus.FAILED

    summarize_hunting_results(tc_meta)


def map_tasks(tasks):
    mapping = {}
    for task in tasks:
        task_key = get_task_key(task)
        mapping[task_key] = task
    return mapping


def get_task_key(task):
    task_query = task['query']
    return task_query['type'] + task_query['term']


def mark_pending_tasks_as_skipped(threat_hunting, task_type):
    for hunting_task in threat_hunting:
        if hunting_task['query']['status'] == HuntingStatus.PENDING and hunting_task['query']['type'] == task_type:
            hunting_task['query']['status'] = HuntingStatus.SKIPPED
