
import heapq
from collections import OrderedDict

from rl_threat_hunting.utils import build_sample_type
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.utils import translate_into_factor

from rl_threat_hunting.constants import ClassificationResultTC
from rl_threat_hunting.constants import Classification

from rl_threat_hunting.filter.sample_importance import MIN_MALWARE_SCORE
from rl_threat_hunting.filter.sample_importance import calculate_malware_interest_score
from rl_threat_hunting.filter.sample_importance import calculate_non_malware_interest_score_by_type


class InterestingChildren(object):

    def __init__(self, child_limit, include_all_malware):
        self.child_limit         = child_limit
        self.include_all_malware = include_all_malware

        self.children = []
        heapq.heapify(self.children)

    def add_child(self, child):
        if child.interest_score is None:
            return

        if len(self.children) < self.child_limit or self._should_add_malware_despite_limit(child.interest_score):
            heapq.heappush(self.children, child)
            return

        min_score_child = self.children[0]
        if child > min_score_child:
            heapq.heapreplace(self.children, child)

    def _should_add_malware_despite_limit(self, child_interest_score):
        return self.include_all_malware and child_interest_score >= MIN_MALWARE_SCORE

    def __len__(self):
        return len(self.children)

    def __iter__(self):
        for child in sorted(self.children, reverse=True):
            yield child

    def __repr__(self):
        return str(list(self))


class Child(object):

    @classmethod
    def parse_from_a1000_extracted_files_result(cls, sample_data):
        child = sample_data.get('sample', {})
        sha1  = child.get('sha1')

        file_type    = child.get('file_type')
        file_subtype = child.get('file_subtype')
        file_identification = child.get('file_identification')
        sample_type = build_sample_type(file_type, file_subtype, file_identification)

        classification = child.get('threat_status')
        threat_name    = child.get('threat_name')

        threat_level = child.get('threat_level')
        trust_factor = child.get('trust_factor')
        factor       = translate_into_factor(classification, trust_factor=trust_factor, threat_level=threat_level)

        return cls(sha1, classification, factor, threat_name, sample_type)

    @classmethod
    def parse_from_tiscale_single_result(cls, tc_report):
        sha1 = _extract_sha1(tc_report)
        sample_type = _extract_sample_type(tc_report)

        tc_classification, tc_factor, tc_threat_name = _extract_tc_classification(tc_report)
        cloud_classification, cloud_factor, cloud_threat_name = _extract_cloud_classification(tc_report)

        tc_child    = cls(sha1, tc_classification, tc_factor, tc_threat_name, sample_type, tc_report)
        cloud_child = cls(sha1, cloud_classification, cloud_factor, cloud_threat_name, sample_type, tc_report)

        if cloud_child > tc_child or \
           (cloud_child == tc_child and not all([tc_classification, tc_factor, tc_threat_name])):
            return cloud_child

        return tc_child

    def __init__(self, sha1, classification, factor, threat_name, sample_type, tc_report=None):
        self.sha1           = sha1
        self.classification = classification
        self.factor         = factor
        self.threat_name    = threat_name
        self.sample_type    = sample_type
        self.tc_report      = tc_report

        self.interest_score = self._calculate_interest_score()

    def get_tc_report(self):
        if self.tc_report:
            return self.tc_report

        return _build_minimal_tc_report(self)

    def update_tc_report(self, updates):
        if self.tc_report:
            self.tc_report.update(updates)
        else:
            self.tc_report = updates

    def _calculate_interest_score(self):
        if Classification.is_malware(self.classification):
            return calculate_malware_interest_score(self.classification, self.factor, self.threat_name)

        return calculate_non_malware_interest_score_by_type(self.sample_type)

    def __lt__(self, other):
        if other is None:
            return False
        if self.interest_score is None:
            return True

        return self.interest_score < other

    def __gt__(self, other):
        if other is None:
            return True
        if self.interest_score is None:
            return False

        return self.interest_score > other

    def __str__(self):
        return self.sha1

    def __repr__(self):
        return 'Child({sha1}, interest_score={interest_score})'.format(**vars(self))

    def add_static_analysis(self, tc_report):
        assert tc_report.get('sha1') == self.sha1
        self.tc_report = tc_report


def _extract_sha1(tc_report):
    for hash_data in safely_traverse_dict(tc_report, 'info.file.hashes', []):
        if hash_data['name'] == 'sha1':
            return hash_data['value'].encode('utf-8')


def _extract_sample_type(tc_report):
    file_type      = safely_traverse_dict(tc_report, 'info.file.file_type')
    file_subtype   = safely_traverse_dict(tc_report, 'info.file.file_subtype')
    identification = safely_traverse_dict(tc_report, 'info.identification.name')
    return build_sample_type(file_type, file_subtype, identification)


def _extract_tc_classification(tc_report):
    scan_results = safely_traverse_dict(tc_report, 'classification.scan_results')
    if not scan_results:
        return None, None, None

    top_scan_result = scan_results[0]

    classification = ClassificationResultTC.from_enum(top_scan_result.get('classification'))
    factor         = top_scan_result.get('factor')
    threat_name    = top_scan_result.get('result')

    return classification, factor, threat_name


def _extract_cloud_classification(tc_report):
    cloud_reputation = tc_report.get('cloud_reputation', {})

    classification = cloud_reputation.get('classification')
    factor         = cloud_reputation.get('factor')
    threat_name    = cloud_reputation.get('threat_name')

    return classification, factor, threat_name


def _build_minimal_tc_report(child):
    report = OrderedDict()

    _format_sha1_value(report, child.sha1)
    _format_sample_type(report, child.sample_type)

    return report


def _format_sha1_value(report, sha1):
    hash_entry = OrderedDict([
        ('name', 'sha1'),
        ('value', sha1)
    ])

    report['info'] = OrderedDict()
    report['info']['file'] = OrderedDict()
    report['info']['file']['hashes'] = [hash_entry]


def _format_sample_type(report, sample_type):
    sample_type = sample_type.split('/')

    report['info']['file']['file_type'] = sample_type[0]

    if len(sample_type) > 1:
        report['info']['file']['file_subtype'] = sample_type[1]

    if len(sample_type) > 2:
        report['info']['identification'] = OrderedDict()
        report['info']['identification']['name'] = sample_type[2]
