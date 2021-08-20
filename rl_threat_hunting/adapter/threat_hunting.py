
from collections import defaultdict
from collections import OrderedDict

from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import is_valid_tc_factor
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.adapter.search_suggestions import generate_search_queries
from rl_threat_hunting.adapter.search_suggestions import generate_complex_search_queries
from rl_threat_hunting.adapter.search_suggestions import generate_complex_info_search_queries
from rl_threat_hunting.adapter.query_descriptions import build_query_type_description
from rl_threat_hunting.constants import Classification
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.constants import HuntingCategory


TASK_LIMITS = {
    HuntingCategory.URI_ANALYTICS               : 25,
    HuntingCategory.ADVANCED_SEARCH             : 10,
    HuntingCategory.ADVANCED_SEARCH_INFORMATIVE : 10,
}
MAX_TASKS = 100

BL_TAGS = {'packed', 'sfx', 'installer'}


class ThreatHuntingReports(list):

    def __init__(self, *args, **kwargs):
        super(ThreatHuntingReports, self).__init__(*args, **kwargs)
        self.uniq_reports = set()
        self.task_counter = defaultdict(int)

    def add_hunting_data(self, sample_info, propagated=None):
        for report in _generate_threat_hunting(sample_info, propagated):
            task_type = report['query']['type']
            uniq_id   = task_type + report['query']['term']
            if uniq_id in self.uniq_reports or self._has_too_many_tasks(task_type):
                continue
            self.uniq_reports.add(uniq_id)
            self.append(report)
            self.task_counter[task_type] += 1

    def _has_too_many_tasks(self, query_type):
        return self.task_counter[query_type] >= TASK_LIMITS.get(query_type, MAX_TASKS)

    def get_completed_hunting_tasks(self):
        for task in self:
            if task['query']['status'] == HuntingStatus.COMPLETED:
                yield task

    def update_all_pending_to_skipped(self):
        for task in self:
            if task['query']['status'] == HuntingStatus.PENDING:
                task['query']['status'] = HuntingStatus.SKIPPED

    def aggregate_hunting_statuses(self, *categories):
        hunting_summary = self._generate_empty_hunting_summary(categories)
        for task in self:
            category = task['query']['type']
            status   = task['query']['status']
            if category == HuntingCategory.ADVANCED_SEARCH_INFORMATIVE:
                continue
            hunting_summary[category][status] += 1
        return hunting_summary

    @staticmethod
    def _generate_empty_hunting_summary(categories):
        hunting_summary = OrderedDict()
        for hunting_category in categories:
            hunting_summary[hunting_category] = OrderedDict()
            for possible_status in HuntingStatus.ALL_STATUSES:
                hunting_summary[hunting_category][possible_status] = 0
        return hunting_summary


def _generate_threat_hunting(sample_info, propagated):
    report_generators = [
        generate_cloud_reputation_report,
        generate_uri_analytics_report,
        generate_certificate_analytics_report,
    ]

    tags = set(sample_info.get('tags', []))
    if not tags.intersection(BL_TAGS):
        if _is_virus(sample_info):
            report_generators.append(generate_advanced_search_analytics_report)
        else:
            report_generators.extend([generate_file_similarity_analytics_report, generate_advanced_search_analytics_report])

    hunting_reports   = []
    for generate_hunting_metadata in report_generators:
        hunting_metadata = generate_hunting_metadata(sample_info, propagated)
        if hunting_metadata:
            hunting_reports.extend(hunting_metadata)
    return hunting_reports


def _is_dotnet_installer(sample_info):
    sample_type = sample_info.get('sample_type', '')
    if '.Net' in sample_type:
        tags = set(sample_info.get('tags', []))
        return 'sfx' in tags or 'installer' in tags


def _is_virus(sample_info):
    cloud_result = safely_traverse_dict(sample_info, 'cloud_reputation.threat_name', '')
    tc_result    = safely_traverse_dict(sample_info, 'static_analysis_classification.result', '')
    return 'Virus' in cloud_result or 'Virus' in tc_result


def build_hunting_task_meta(query_type, query_term, status=HuntingStatus.PENDING, propagated=None,
                            malicious=None, classification=None, description=None, threats=None):
    if not query_term:
        return

    meta = OrderedDict()
    meta['query'] = OrderedDict([
        ('status'      , status),
        ('type'        , query_type),
        ('term'        , query_term),
        ('description' , build_query_type_description(query_type, query_term)),
    ])
    if propagated:
        meta['query']['propagated'] = propagated

    for name, value in [('malicious'         , malicious),
                        ('classification'    , classification),
                        ('description'       , description),
                        ('threats'           , threats)]:
        if value is not None:
            meta[name] = value

    return meta


def generate_cloud_reputation_report(sample_info, propagated):
    query_type  = HuntingCategory.CLOUD_REPUTATION

    for hash_type in ['sha1', 'md5', 'sha256']:
        hash_value = sample_info.get(hash_type)
        if hash_value is None:
            continue

        cloud_reputation = sample_info.get('cloud_reputation')
        if not cloud_reputation:
            hunting_task = build_hunting_task_meta(query_type=query_type, query_term=hash_value, propagated=propagated)
            return [hunting_task] if hunting_task else []

        cloud_reputation_hunting = parse_cloud_reputation_hunting_data(cloud_reputation, query_type, hash_value, propagated)
        if cloud_reputation_hunting:
            return [cloud_reputation_hunting]


def parse_cloud_reputation_hunting_data(cloud_reputation, query_type, hash_value, propagated):
    classification_summary = result_evaluation.malware_presence(cloud_reputation)

    classification = classification_summary['classification']
    description    = classification_summary['description']
    build_parameters = {
        'query_type'     : query_type,
        'query_term'     : hash_value,
        'status'         : HuntingStatus.COMPLETED,
        'classification' : classification,
        'description'    : description,
        'propagated'     : propagated,
    }
    if Classification.is_malware(classification):
        build_parameters['malicious'] = 1

        threat_info = build_threat_field(
            cloud_reputation.get('classification'),
            cloud_reputation.get('threat_name'),
            cloud_reputation.get('factor')
        )
        if threat_info:
            build_parameters['threats'] = [threat_info]
    else:
        build_parameters['malicious'] = 0

    return build_hunting_task_meta(**build_parameters)


def build_threat_field(classification, threat_name, factor):
    meta = OrderedDict()
    for name, value in [('name'        , threat_name),
                        ('factor'      , factor)]:
        if value or (name == 'factor' and is_valid_tc_factor(value, classification)):
            meta[name] = value
    return meta


def generate_uri_analytics_report(sample_info, propagated):
    uris = sample_info.get('uri', [])

    uri_reports = []
    for uri in uris:
        uri_value = uri['value']
        report = build_hunting_task_meta(
            query_type=HuntingCategory.URI_ANALYTICS,
            query_term=uri_value,
            propagated=propagated,
        )
        uri_reports.append(report)

    return uri_reports


def generate_certificate_analytics_report(sample_info, propagated):
    signer_certificates = sample_info.get('signer_certificate_list', [])

    signer_thumbprints = []
    for certificate in signer_certificates:
        thumbprint = certificate.get('thumbprint')
        if thumbprint:
            report = build_hunting_task_meta(
                query_type=HuntingCategory.CERTIFICATE_ANALYTICS,
                query_term=thumbprint,
                propagated=propagated,
            )
            signer_thumbprints.append(report)

    return signer_thumbprints


def generate_file_similarity_analytics_report(sample_info, propagated):
    sample_type = sample_info.get('sample_type', '')
    sample_sha1 = sample_info.get('sha1')

    query_prefix = _get_rha1_prefix(sample_type)
    if query_prefix:
        return [build_hunting_task_meta(
            query_term=query_prefix.format(sample_sha1),
            query_type=HuntingCategory.FILE_SIMILARITY_ANALYTICS,
            propagated=propagated,
        )]


def _get_rha1_prefix(sample_type):
    if sample_type.startswith('MachO'):
        return 'macho01/{}'
    if sample_type.startswith('ELF'):
        return 'elf01/{}'
    if sample_type.startswith('PE'):
        return 'pe01/{}'


def generate_advanced_search_analytics_report(sample_info, propagated):
    advanced_search = []

    for generator_function, query_type in [
        (generate_complex_search_queries     , HuntingCategory.ADVANCED_SEARCH),
        (generate_search_queries             , HuntingCategory.ADVANCED_SEARCH),
        (generate_complex_info_search_queries, HuntingCategory.ADVANCED_SEARCH_INFORMATIVE)
    ]:
        search_parameters = generator_function(sample_info)
        for search_parameter in search_parameters:
            report = build_hunting_task_meta(
                query_term=search_parameter,
                query_type=query_type,
                propagated=propagated,
            )
            advanced_search.append(report)

    return advanced_search
