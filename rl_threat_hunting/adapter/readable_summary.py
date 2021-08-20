
from collections import OrderedDict

from rl_threat_hunting import result_evaluation
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import Classification
from rl_threat_hunting.constants import Description
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.constants import HuntingStatus
from rl_threat_hunting.adapter.threat_hunting import build_threat_field
from rl_threat_hunting.adapter.threat_hunting import build_hunting_task_meta
from rl_threat_hunting.filter.sample_importance import calculate_malware_interest_score
from rl_threat_hunting.filter.sample_importance import calculate_non_malware_interest_score


class Reason(object):
    CLOUD_REPUTATION          = 'Hash based lookup ({}) on TiCloud file reputation API.'
    USER_OVERRIDE_REPUTATION  = 'Classification user override ({}) on the local A1000'
    CLOUD_REPUTATION_CHILD    = 'Hash based lookup (based on unpacked file sha1: {}) on TiCloud file reputation API.'
    CERTIFICATE_WHITELIST     = 'File is signed with whitelisted certificate (thumbprint: {}).'
    CERTIFICATE_ANALYTICS     = 'Certificate (thumbprint: {}) is known to have been used to sign malware.'
    FILE_SIMILARITY_ANALYTICS = 'File similarity hash lookup ({}) shows that file is similar to known malware.'
    URI_ANALYTICS             = 'File contains URI ({}) related to known malicious content.'
    ADVANCED_SEARCH           = 'File contains indicator that is usually found in malicious samples. Search query: "{}".'

    STATIC_ANALYSIS  = 'Static analysis classification made with {}.'
    DYNAMIC_ANALYSIS = 'Dynamic analysis classification made with {}.'
    UNPACKED_FILE    = ' Found in unpacked file sha1: {}.'

    _QUERY_TYPE = {
        HuntingCategory.CLOUD_REPUTATION          : CLOUD_REPUTATION,
        HuntingCategory.CERTIFICATE_ANALYTICS     : CERTIFICATE_ANALYTICS,
        HuntingCategory.FILE_SIMILARITY_ANALYTICS : FILE_SIMILARITY_ANALYTICS,
        HuntingCategory.URI_ANALYTICS             : URI_ANALYTICS,
        HuntingCategory.ADVANCED_SEARCH           : ADVANCED_SEARCH,
    }

    @classmethod
    def parse_static_analysis(cls, sample_info, scanner_name):
        propagated = safely_traverse_dict(sample_info, 'static_analysis_classification.propagated')
        reason = cls.STATIC_ANALYSIS.format(scanner_name)
        if propagated:
            reason += cls.UNPACKED_FILE.format(propagated)
        return reason

    @classmethod
    def parse_from_task(cls, task):
        reason = task.get('reason')
        if reason:
            return reason

        query_data = task.get('query', {})
        query_type = query_data.get('type')
        query_term = query_data.get('term')
        propagated = query_data.get('propagated')

        reason = cls._QUERY_TYPE.get(query_type)
        if not reason:
            return

        if propagated and query_type == HuntingCategory.CLOUD_REPUTATION:
            return cls.CLOUD_REPUTATION_CHILD.format(propagated)
        if propagated:
            reason += cls.UNPACKED_FILE.format(propagated)

        return reason.format(query_term)

    @classmethod
    def format_user_override(cls, hash_value):
        return cls.USER_OVERRIDE_REPUTATION.format(hash_value)


def compose_sample_description(sample_info):
    description = OrderedDict()
    description['description'] = sample_info.get('description')
    description['type']        = sample_info.get('sample_type')
    description['size']        = sample_info.get('sample_size')
    description['extracted']   = sample_info.get('extracted')
    description['md5']         = sample_info.get('md5')
    description['sha1']        = sample_info.get('sha1')
    description['sha256']      = sample_info.get('sha256')
    description['tags']        = sample_info.get('tags')
    return description


def compose_attack_matrix(sample_info):
    result = []
    attack = sample_info.get('attack', [])
    for item in attack:
        tactics = item.get('tactics', [])
        matrix  = item.get('matrix')
        if tactics and matrix == 'Enterprise':
            result = _parse_tactics_and_techniques(tactics)
            break

    return result


def _parse_tactics_and_techniques(tactics):
    result = []
    for tactic in tactics:
        info = OrderedDict()
        info['name'] = tactic['name']
        info['description'] = tactic['description']
        info['techniques'] = []
        for technique in tactic.get('techniques', []):
            formatted_technique = OrderedDict([
                ('id', technique['id']),
                ('name', technique['name']),
                ('static_analysis_indicators', technique['indicators']),
            ])
            info['techniques'].append(formatted_technique)
        result.append(info)
    return result


def compose_cloud_hunting_summary(threat_hunting):
    return threat_hunting.aggregate_hunting_statuses(
        HuntingCategory.CLOUD_REPUTATION,
        HuntingCategory.CERTIFICATE_ANALYTICS,
        HuntingCategory.FILE_SIMILARITY_ANALYTICS,
        HuntingCategory.URI_ANALYTICS,
        HuntingCategory.ADVANCED_SEARCH,
    )


def compose_local_hunting_summary(threat_hunting):
    return threat_hunting.aggregate_hunting_statuses(HuntingCategory.ADVANCED_SEARCH)


def compose_final_classification(sample_info, cloud_hunting=None, local_hunting=None):
    whitelisted_container = _find_whitelisted_result(sample_info)
    if whitelisted_container:
        return FinalClassification(whitelisted_container, whitelisted_container=True)

    final_results = [FinalClassification()]

    dynamic_analysis_results = _find_dynamic_analysis_results(sample_info)
    if dynamic_analysis_results:
        for result in dynamic_analysis_results:
            summary = FinalClassification(result)
            final_results.append(summary)

    static_analysis_result = _find_static_analysis_result(sample_info)
    if static_analysis_result:
        summary = FinalClassification(static_analysis_result)
        final_results.append(summary)

    for threat_hunting in [cloud_hunting, local_hunting]:
        if threat_hunting:
            for completed_task in threat_hunting.get_completed_hunting_tasks():
                summary = FinalClassification(completed_task)
                final_results.append(summary)

    worst_classification = sorted(final_results)[-1]

    for hash_type in ['sha1', 'sha256', 'md5']:
        hash_value = sample_info.get(hash_type)
        if is_cloud_reputation(hash_value, worst_classification) and is_user_override(sample_info):
            worst_classification['reason'] = Reason.format_user_override(hash_value)
            break

    return worst_classification


def is_cloud_reputation(hash_value, worst_classification):
    return worst_classification['reason'] == Reason.CLOUD_REPUTATION.format(hash_value)


def is_user_override(sample_info):
    cloud_reputation = sample_info.get('cloud_reputation', {})
    return cloud_reputation.get('is_user_override')


def _find_whitelisted_result(sample_info):
    static_analysis = result_evaluation.tc_metadata(sample_info)
    if static_analysis.is_whitelisted():
        thumbprint = _get_first_signer_cert_thumbprint(sample_info)
        return _build_temporary_hunting_task_meta(
            reason=Reason.CERTIFICATE_WHITELIST.format(thumbprint),
            query_type=HuntingCategory.STATIC_ANALYSIS,
            query_term=thumbprint,
            status=HuntingStatus.COMPLETED, **static_analysis
        )

    cloud_reputation = sample_info.get('cloud_reputation', {})
    mwp_result       = result_evaluation.malware_presence(cloud_reputation)
    if mwp_result.is_whitelisted():
        sha1 = sample_info.get('sha1')
        return _build_temporary_hunting_task_meta(
            reason=Reason.CLOUD_REPUTATION.format(sha1),
            query_type=HuntingCategory.CLOUD_REPUTATION,
            query_term=sha1,
            status=HuntingStatus.COMPLETED, **mwp_result
        )

    dynamic_analysis = sample_info.get('dynamic_analysis_classification', [])
    for analysis in dynamic_analysis:
        result = result_evaluation.dynamic_analysis(analysis)
        if result.is_whitelisted():
            name = analysis.get('name')
            return _build_temporary_hunting_task_meta(
                reason=Reason.DYNAMIC_ANALYSIS.format(name),
                query_type=HuntingCategory.DYNAMIC_ANALYSIS,
                query_term=name,
                status=HuntingStatus.COMPLETED, **result
            )


def _get_first_signer_cert_thumbprint(sample_info):
    certs = sample_info.get('signer_certificate_list')
    if certs:
        return certs[0].get('thumbprint')


def _build_temporary_hunting_task_meta(reason=None, *args, **kwargs):
    task = build_hunting_task_meta(*args, **kwargs)
    task['reason'] = reason
    return task


def _find_static_analysis_result(sample_info):
    tc_result = result_evaluation.tc_metadata(sample_info)
    scanner_results = safely_traverse_dict(sample_info, 'static_analysis_classification.scanner_result')
    if not scanner_results:
        return

    scanner_result = scanner_results[0]
    component_name = scanner_result.get('name')

    reason = Reason.parse_static_analysis(sample_info, component_name)
    threat = build_threat_field(tc_result.classification, scanner_result.get('result'), scanner_result.get('factor'))

    return _build_temporary_hunting_task_meta(
        reason=reason,
        query_type=HuntingCategory.STATIC_ANALYSIS,
        query_term=component_name,
        status=HuntingStatus.COMPLETED, threats=[threat], **tc_result
    )


def _find_dynamic_analysis_results(sample_info):
    dynamic_analysis = sample_info.get('dynamic_analysis_classification', [])

    hunting_tasks = []
    for analysis in dynamic_analysis:
        result        = result_evaluation.dynamic_analysis(analysis)
        analysis_name = analysis.get('name')
        reason        = Reason.DYNAMIC_ANALYSIS.format(analysis_name)
        threat        = build_threat_field(result.classification, analysis.get('result'), analysis.get('factor'))
        hunting_task  = _build_temporary_hunting_task_meta(reason=reason,
                                                           query_type=HuntingCategory.DYNAMIC_ANALYSIS,
                                                           query_term=analysis_name,
                                                           status=HuntingStatus.COMPLETED,
                                                           threats=[threat], **result)
        hunting_tasks.append(hunting_task)

    return hunting_tasks


class FinalClassification(OrderedDict):

    def __init__(self, task=None, whitelisted_container=False):
        super(FinalClassification, self).__init__()
        self.whitelisted_container = whitelisted_container

        if task is None:
            task = {}
        self.propagated = task.get('propagated')

        self['classification'] = task.get('classification', Classification.UNDECIDED)
        self['description']    = task.get('description', Description.UNDECIDED)
        self['reason']         = Reason.parse_from_task(task)

        threats = task.get('threats')
        worst_threat = threats[0] if threats else {}
        self['threat'] = OrderedDict()
        self['threat']['name']        = worst_threat.get('name')
        self['threat']['factor']      = worst_threat.get('factor')

        self.query_type     = safely_traverse_dict(task, 'query.type')
        self.classification = self['classification']

    def __lt__(self, other):
        if self.query_type == HuntingCategory.DYNAMIC_ANALYSIS:
            return self.dynamic_analysis_is_less_malicious(self, other)

        if other.query_type == HuntingCategory.DYNAMIC_ANALYSIS:
            return not self.dynamic_analysis_is_less_malicious(dynamic_analysis=other, other=self)

        if other.interest_score is None:
            return False

        if self.interest_score is None:
            return True

        return self.interest_score < other.interest_score

    @staticmethod
    def dynamic_analysis_is_less_malicious(dynamic_analysis, other):
        return (not dynamic_analysis.is_malware() and other.is_malware()) or \
               (dynamic_analysis.classification == Classification.SUSPICIOUS and other.classification == Classification.MALICIOUS) or \
               (dynamic_analysis.classification == Classification.UNDECIDED and other.classification != Classification.UNDECIDED)

    @property
    def interest_score(self):
        if self['reason'] is None and self['classification'] == Classification.UNDECIDED:
            return None

        if self.is_malware():
            return calculate_malware_interest_score(self['classification'], self['threat']['factor'], self['threat']['name'])

        if self['description'] == Description.HIGH_TRUST and self.propagated:
            return None

        return calculate_non_malware_interest_score(self['classification'], self['threat']['factor'])

    def is_malware(self):
        return Classification.is_malware(self['classification'])

    def is_final(self):
        return self.whitelisted_container or self.is_malware()
