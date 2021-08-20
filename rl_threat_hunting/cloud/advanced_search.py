
import heapq

from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import Classification
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.adapter.threat_hunting import build_threat_field
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta


class AdvancedSearchInterface(object):
    CLASSIFICATION = 'classification'
    THREAT_NAME    = 'threatname'
    THREAT_LEVEL   = 'threatlevel'

    @classmethod
    def pair_up_search_task_and_response(cls, api_response_data, tasks):
        task = tasks[0]

        api_malicious, api_known = cls._unpack_api_responses(api_response_data)

        api_data = cls._extract_search_api_data(api_malicious, task)
        if api_known:
            known_cnt = safely_traverse_dict(api_known, 'rl.web_search_api.total_count', 0)
            api_data.update({'known': known_cnt})

        return [(task, api_data)]

    @staticmethod
    def _unpack_api_responses(api_response_data):
        if isinstance(api_response_data, tuple) and len(api_response_data) == 2:
            return api_response_data

        if isinstance(api_response_data, dict):
            return api_response_data, None

        raise ValueError('Provide single API response or tuple of API responses - (malicious, known).')

    @staticmethod
    def _extract_search_api_data(api_malicious, task):
        return {
            'search_term' : task['query']['term'],
            'malicious'   : safely_traverse_dict(api_malicious, 'rl.web_search_api.total_count', 0),
            'threats'     : safely_traverse_dict(api_malicious, 'rl.web_search_api.entries', []),
        }

    @classmethod
    def process_search_entry(cls, search_data):
        query_term = search_data['search_term']

        build_parameters = {
            'query_type' : HuntingCategory.ADVANCED_SEARCH,
            'query_term' : query_term,
            'status'     : HuntingStatus.COMPLETED,
        }

        classification_summary = result_evaluation.advanced_search_query(search_data)
        build_parameters.update(classification_summary)

        if Classification.is_malware(classification_summary['classification']):
            build_parameters['malicious'] = search_data.get('malicious', 0)

            threats = search_data['threats']
            build_parameters['threats'] = cls._select_top_threats(threats)
        else:
            build_parameters['malicious'] = 0

        return build_hunting_task_meta(**build_parameters)

    @classmethod
    def _select_top_threats(cls, threats):
        threats_rank = ThreatsRankList(cls.CLASSIFICATION, cls.THREAT_NAME, cls.THREAT_LEVEL)

        for threat in threats:
            if threat.get(cls.THREAT_NAME):
                threats_rank.add(threat)

        return threats_rank.get_top_threats()

    @classmethod
    def check_search_early_exit_condition(cls, api_response_data, task):
        api_malicious, _ = cls._unpack_api_responses(api_response_data)
        api_data         = cls._extract_search_api_data(api_malicious, task)

        classification_summary = result_evaluation.advanced_search_query(api_data)
        return classification_summary.is_malware()


class ThreatDict(dict):
    def __init__(self, threat_level, threat):
        self.threat_level = threat_level
        super(ThreatDict, self).__init__(threat)

    def __lt__(self, other):
        return self[self.threat_level] < other[self.threat_level]


class ThreatsRankList(object):
    def __init__(self, classification, threat_name, threat_level):
        self.classification = classification
        self.threat_name    = threat_name
        self.threat_level   = threat_level

        self.queue = []
        heapq.heapify(self.queue)
        self.names_in_queue = set()

    def add(self, threat):
        threat_name = threat[self.threat_name]
        if threat_name in self.names_in_queue:
            return

        factor = threat[self.threat_level]
        threat = ThreatDict(self.threat_level, threat)
        heapq.heappush(self.queue, (factor, threat))
        self.names_in_queue.add(threat_name)

    def _format(self, threat):
        return build_threat_field(
            threat.get(self.classification).lower(),
            threat.get(self.threat_name),
            threat.get(self.threat_level)
        )

    def get_top_threats(self, limit=5):
        top_threats = heapq.nlargest(limit, self.queue)
        top_threats = [dict(queue_entry[1]) for queue_entry in top_threats]
        return [self._format(threat) for threat in top_threats]
