
from collections import OrderedDict

from rl_threat_hunting.constants import Description
from rl_threat_hunting.constants import Classification
from rl_threat_hunting.constants import JoeClassification
from rl_threat_hunting.constants import CloudDynamicAnalysisClassification
from rl_threat_hunting.constants import DynamicAnalysisType
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.utils import translate_into_factor

_UNTRUSTED   = 5
_MAX_TRUSTED = 1
_LOW_THREAT  = 2
_LOW_THREAT_RCA2 = 7
_MIN_SIGNIFICANT_BUCKET = 8

_CERTIFICATE_RESULT_NAME = ('TitaniumCore Certificate Lists', 'TitaniumCore Certificate Validator')


def tc_metadata(sample_info):
    classification = safely_traverse_dict(sample_info, 'static_analysis_classification.classification')
    factor         = safely_traverse_dict(sample_info, 'static_analysis_classification.factor')

    if classification == Classification.GOODWARE:
        scanner_result = safely_traverse_dict(sample_info, 'static_analysis_classification.scanner_result')
        description    = _check_for_whitelisted_cert(scanner_result)
    elif Classification.is_malware(classification):
        description    = _calculate_threat_severity(factor)
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def rca2(data):
    classification = data.get('classification')
    factor         = data.get('factor')

    if classification == Classification.GOODWARE:
        description = _calculate_trust_confidence(factor)
    elif Classification.is_malware(classification):
        description = _calculate_threat_severity(factor, use_rca2_scale=True)
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def malware_presence(data):
    classification = _read_classification(data)
    factor         = _read_factor(classification, data)

    if classification in (Classification.KNOWN, Classification.GOODWARE):
        classification = Classification.GOODWARE
        description    = _calculate_trust_confidence(factor)
    elif Classification.is_malware(classification):
        classification = classification
        description    = _calculate_threat_severity(factor)
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def _read_factor(classification, data):
    factor = data.get('factor')
    if factor is None:
        threat_level = data.get('threat_level')
        trust_factor = data.get('trust_factor', _UNTRUSTED)
        factor       = translate_into_factor(classification, trust_factor, threat_level)
    return factor


def _read_classification(data):
    for key in ['status', 'threat_status']:
        try:
            status = data[key]
        except KeyError:
            continue

        if Classification.is_valid(status):
            return status.lower()
    else:
        return data.get('classification', Classification.UNKNOWN)


def rha1_analytics(data):
    data  = _read_rha_counters(data)
    total = data['total']
    known = data['known']

    if known == 0 and total >= _MIN_SIGNIFICANT_BUCKET:
        classification = Classification.MALICIOUS
        description    = Description.HIGH_THREAT
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def _read_rha_counters(data):
    counters = data.get('sample_counters')
    if counters is None:
        return data
    return counters


def certificate_analytics(data):
    counters = _get_certificate_counters(data)

    total      = counters['total']
    known      = counters['known']
    malicious  = counters['malicious']
    suspicious = counters['suspicious']

    if known == total and total >= _MIN_SIGNIFICANT_BUCKET:
        classification = Classification.GOODWARE
        description    = Description.LOW_TRUST
    elif malicious + suspicious >= _MIN_SIGNIFICANT_BUCKET:
        classification = Classification.MALICIOUS
        description    = Description.HIGH_THREAT
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def _get_certificate_counters(data):
    counters = data.get('statistics')
    if counters:
        return counters
    return data


def uri_analytics(data):
    counters = _get_uri_counters(data)

    malicious  = counters['malicious']
    suspicious = counters['suspicious']
    known      = counters['known']

    if malicious + suspicious >= _MIN_SIGNIFICANT_BUCKET and known == 0:
        classification = Classification.MALICIOUS
        description    = Description.HIGH_THREAT
    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def _get_uri_counters(data):
    counters = data.get('counters')
    if counters:
        return counters
    return data


def advanced_search_query(data):
    malicious = data.get('malicious', 0)
    known     = data.get('known', 0)

    if malicious >= _MIN_SIGNIFICANT_BUCKET and known == 0:
        classification = Classification.MALICIOUS

        threats = data.get('threats', [])
        if len(threats) >= 1:
            highest_threat = threats[0]
            factor         = _get_adv_search_threat_level(highest_threat)
            description    = _calculate_threat_severity(factor)
        else:
            description = Description.LOW_THREAT

    elif known >= _MIN_SIGNIFICANT_BUCKET and malicious == 0:
        classification = Classification.GOODWARE
        description    = Description.LOW_TRUST

    else:
        classification = Classification.UNDECIDED
        description    = Description.UNDECIDED

    return ClassificationSummary(classification, description)


def _get_adv_search_threat_level(highest_threat):
    for key in ['threatlevel', 'threat_level']:
        try:
            return highest_threat[key]
        except KeyError as error:
            continue
    raise error


def dynamic_analysis(data):
    analysis_name = data.get('name')

    if analysis_name == DynamicAnalysisType.JOE_SANDBOX:
        classification, description = JoeClassification.from_adapted_report(data)
        return ClassificationSummary(classification, description)

    if analysis_name == DynamicAnalysisType.CLOUD_DYNAMIC_ANALYSIS:
        classification, description = CloudDynamicAnalysisClassification.from_adapted_report(data)
        return ClassificationSummary(classification, description)


def classify_empty_response():
    return ClassificationSummary(Classification.UNDECIDED, Description.UNDECIDED)


def _check_for_whitelisted_cert(scanner_result):
    for result in scanner_result:
        if result['classification'] == Classification.GOODWARE \
                and result['name'] in _CERTIFICATE_RESULT_NAME \
                and result['factor'] <= _MAX_TRUSTED:
            return Description.HIGH_TRUST
    return Description.LOW_TRUST


def _calculate_trust_confidence(factor):
    if factor <= _MAX_TRUSTED:
        return Description.HIGH_TRUST
    else:
        return Description.LOW_TRUST


def _calculate_threat_severity(factor, use_rca2_scale=False):
    low_threat_threshold = _LOW_THREAT_RCA2 if use_rca2_scale else _LOW_THREAT
    if factor <= low_threat_threshold:
        return Description.LOW_THREAT
    else:
        return Description.HIGH_THREAT


class ClassificationSummary(OrderedDict):

    def __init__(self, classification, description):
        super(ClassificationSummary, self).__init__([('classification', classification), ('description', description)])

    @property
    def classification(self):
        return self.get('classification')

    @property
    def description(self):
        return self.get('description')

    def is_whitelisted(self):
        return self.classification == Classification.GOODWARE and self.description == Description.HIGH_TRUST

    def is_malware(self):
        return Classification.is_malware(self.classification)
