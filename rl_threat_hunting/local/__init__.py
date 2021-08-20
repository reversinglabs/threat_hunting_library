
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory

from rl_threat_hunting.cloud import update_tasks_without_response
from rl_threat_hunting.cloud import summarize_hunting_results
from rl_threat_hunting.cloud import mark_pending_tasks_as_skipped
from rl_threat_hunting.cloud import map_tasks, get_task_key

from rl_threat_hunting.local.advanced_search import AdvancedSearchInterface


def get_query_tasks(tc_meta):
    return tc_meta.get('local_hunting', [])


def update_hunting_meta(tc_meta, api_response_data, *tasks):
    if not tasks:
        raise ValueError('Task(s) argument not provided.')

    if api_response_data:
        tasks_responses_pairs  = AdvancedSearchInterface.pair_up_search_task_and_response(api_response_data, tasks)
        tasks_without_response = _update_completed_tasks(tc_meta, tasks_responses_pairs)
    else:
        tasks_without_response = tasks

    update_tasks_without_response(tasks_without_response)

    threat_hunting = tc_meta['local_hunting']
    summarize_hunting_results(tc_meta)

    if AdvancedSearchInterface.check_search_early_exit_condition(api_response_data, tasks[0]):
        mark_pending_tasks_as_skipped(threat_hunting, HuntingCategory.ADVANCED_SEARCH)
        raise StopIteration('Malicious Advanced Search response. No need for further processing, break iteration.')


def _update_completed_tasks(tc_meta, tasks_responses_pairs):
    tasks_without_response = []
    for task, api_response in tasks_responses_pairs:
        if api_response:
            updated_task = AdvancedSearchInterface.process_search_entry(api_response)
            _update_hunting_task(tc_meta, updated_task)
        else:
            tasks_without_response.append(task)
    return tasks_without_response


def _update_hunting_task(tc_meta, task):
    threat_hunting = tc_meta['local_hunting']

    query_type = task['query']['type']
    query_term = task['query']['term']

    for hunting_task in threat_hunting:
        if hunting_task['query']['type'] == query_type and hunting_task['query']['term'] == query_term:
            hunting_task.update(task)


def mark_tasks_as_failed(tc_meta, *tasks):
    threat_hunting = tc_meta['local_hunting']

    task_lookup = map_tasks(tasks)

    for hunting_task in threat_hunting:
        task_key = get_task_key(hunting_task)

        if task_lookup.get(task_key):
            hunting_task['query']['status'] = HuntingStatus.FAILED

    summarize_hunting_results(tc_meta)
