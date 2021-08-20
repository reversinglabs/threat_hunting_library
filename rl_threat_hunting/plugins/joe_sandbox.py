
from collections import OrderedDict

from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import DynamicAnalysisType
from rl_threat_hunting.adapter.threat_hunting import ThreatHuntingReports
from rl_threat_hunting.tc_metadata_adapter import generate_readable_summary


CLASSIFICATION_FIELDS = ['whitelisted', 'malicious', 'suspicious', 'clean', 'unknown']


class EmptyJoeReport(Exception):
    pass


def add_dynamic_analysis(tc_meta, api_response_data):
    if not api_response_data:
        raise EmptyJoeReport('Empty Joe report passed as the argument. Please provide an valid report.')

    strategy = safely_traverse_dict(api_response_data, 'analysis.signaturedetections.strategy')

    empiric_strategy = _get_empiric_strategy(strategy)
    dynamic_analysis = compose_dynamic_analysis(empiric_strategy)

    sample_info = tc_meta['sample_info']
    tc_meta_dynamic_analysis = sample_info.setdefault('dynamic_analysis_classification', [])
    tc_meta_dynamic_analysis.append(dynamic_analysis)

    readable_summary = generate_readable_summary(tc_meta)
    if readable_summary:
        tc_meta['readable_summary'] = readable_summary


def _get_empiric_strategy(strategy):
    for entry in strategy:
        if entry['@name'] == 'empiric':
            return entry


def compose_dynamic_analysis(empiric_strategy):
    dynamic_analysis = OrderedDict()

    for name, value in [('name'           , DynamicAnalysisType.JOE_SANDBOX),
                        ('classification' , _get_classification(empiric_strategy)),
                        ('result'         , _get_result(empiric_strategy))]:
        if value:
            dynamic_analysis[name] = value

    return dynamic_analysis


def _get_classification(empiric_strategy):
    for class_field in CLASSIFICATION_FIELDS:
        value = empiric_strategy.get(class_field)
        if value:
            return class_field


def _get_result(empiric_strategy):
    threatname = empiric_strategy.get('threatname')
    if threatname != 'Unknown':
        return threatname
