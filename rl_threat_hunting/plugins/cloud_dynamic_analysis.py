
from collections import OrderedDict

from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.constants import DynamicAnalysisType
from rl_threat_hunting.tc_metadata_adapter import generate_readable_summary


class EmptyCloudDynamicAnalysisReport(Exception):
    pass


def add_dynamic_analysis(tc_meta, api_response_data):
    if not api_response_data:
        message = 'Empty dynamic analysis report passed as an argument. Please provide valid report.'
        raise EmptyCloudDynamicAnalysisReport(message)

    report           = safely_traverse_dict(api_response_data, 'rl.report')
    dynamic_analysis = compose_dynamic_analysis(report)

    sample_info = tc_meta['sample_info']
    tc_meta_dynamic_analysis = sample_info.setdefault('dynamic_analysis_classification', [])
    tc_meta_dynamic_analysis.append(dynamic_analysis)

    readable_summary = generate_readable_summary(tc_meta)
    if readable_summary:
        tc_meta['readable_summary'] = readable_summary


def compose_dynamic_analysis(report):
    dynamic_analysis = OrderedDict()

    for name, value in [('name'           , DynamicAnalysisType.CLOUD_DYNAMIC_ANALYSIS),
                        ('classification' , report.get('classification'))]:
        if value:
            dynamic_analysis[name] = value

    return dynamic_analysis
