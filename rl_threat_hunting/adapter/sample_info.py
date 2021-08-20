
import re

from collections import OrderedDict

from rl_threat_hunting.constants import ClassificationTypeTC
from rl_threat_hunting.constants import ClassificationResultTC
from rl_threat_hunting.filter.uris import is_interesting_uri
from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.utils import build_sample_type
from rl_threat_hunting.utils import is_valid_tc_factor
from rl_threat_hunting.utils import is_valid_ipv4_address
from rl_threat_hunting.utils import is_valid_ipv6_address
from rl_threat_hunting.adapter.email import compose_email_field
from rl_threat_hunting.adapter.documents import compose_document_field


CERTIFICATE_FIELDS    = ['version', 'signature_algorithm', 'signature', 'valid_from', 'valid_to', 'serial_number',
                         'thumbprint_algorithm', 'thumbprint', 'subject', 'issuer', 'extensions']
RESOURCES_FILEDS      = ['name', 'type']
MALWARE_CONFIG_FIELDS = ['botFTPServer', 'botServer', 'botURL']

CERT_COMMON_NAME       = re.compile(r'.*?commonName=(?P<common_name>.*?)(?:$|,\w+=.*$)')
CERT_ORGANIZATION_NAME = re.compile(r'.*?organizationName=(?P<organization_name>.*?)(?:$|,\w+=.*$)')
CERT_ORGANIZATIONAL_UNIT_NAME = re.compile(r'.*?organizationalUnitName=(?P<unit_name>.*?)(?:$|,\w+=.*$)')
CERT_DISTINGUISHED_NAMES      = ['common_name', 'organization_name', 'unit_name', 'country_name']
TIMESTAMP_NAME_KEYS           = {'X509v3 Extended Key Usage', 'Extended Key Usage', 'X509v3 Key Usage'}

INTERESTING_HASHES     = ['md5', 'sha1', 'sha256', 'ssdeep', 'imphash']
VERSION_INFO_FILENAMES = ['OriginalFilename', 'InternalName']

INTERESTING_URI_CATEGORIES = {'http', 'https', 'ftp', 'malito', 'ipv4', 'ipv6'}
URI_ADAPTED_HTTP_CATEGORY  = {'http', 'https'}

NOT_EXTRACTED_CONTAINER = 1


def compose_sample_info(tc_report):
    sample_info = OrderedDict()

    interesting_hashes = extract_interesting_hashes(tc_report)
    sample_info.update(interesting_hashes)

    metadata = tc_report.get('metadata', tc_report)
    for name, value in [('filename'                       , extract_pe_filename(metadata)),
                        ('sample_type'                    , extract_sample_type(tc_report)),
                        ('sample_size'                    , safely_traverse_dict(tc_report, 'info.file.size')),
                        ('description'                    , tc_report.get('story')),
                        ('extracted'                      , extract_number_of_children(tc_report)),
                        ('uri'                            , extract_uris(tc_report)),
                        ('pe'                             , compose_pe_field(metadata)),
                        ('document'                       , compose_document_field(metadata)),
                        ('email'                          , compose_email_field(metadata)),
                        ('static_analysis_indicators'     , tc_report.get('indicators')),
                        ('static_analysis_classification' , compose_classification_field(tc_report)),
                        ('cloud_reputation'               , tc_report.get('cloud_reputation')),
                        ('signer_certificate_list'        , compose_signer_certificate_field(metadata)),
                        ('tags'                           , tc_report.get('tags')),
                        ('attack'                         , tc_report.get('attack', []))]:
        if value:
            sample_info[name] = value

    return sample_info


def extract_interesting_hashes(tc_report):
    interesting_hashes = OrderedDict()

    for hash_name in INTERESTING_HASHES:
        hash_value = extract_hash(tc_report, hash_name)
        if hash_value:
            interesting_hashes[hash_name] = hash_value

    return interesting_hashes


def extract_hash(tc_report, hash_type):
    for hash_data in safely_traverse_dict(tc_report, 'info.file.hashes', []):
        if hash_data['name'] == hash_type:
            return hash_data['value']


def extract_pe_filename(tc_report):
    version_info = safely_traverse_dict(tc_report, 'application.pe.version_info', [])

    filenames = {}
    for info in version_info:
        if info['name'] in VERSION_INFO_FILENAMES and 'value' in info:
            filename_type = info['name']
            filenames[filename_type] = info['value']

    for filename_type in VERSION_INFO_FILENAMES:
        if filename_type in filenames:
            return filenames[filename_type]

    return safely_traverse_dict(tc_report, 'application.pe.exports.name')


def extract_sample_type(tc_report):
    file_type      = safely_traverse_dict(tc_report, 'info.file.file_type')
    file_subtype   = safely_traverse_dict(tc_report, 'info.file.file_subtype')
    identification = safely_traverse_dict(tc_report, 'info.identification.name')
    return build_sample_type(file_type, file_subtype, identification)


def extract_number_of_children(tc_report):
    statistics = safely_traverse_dict(tc_report, 'info.statistics.file_stats', [])
    extracted_children = 0
    for file_type_statistic in statistics:
        extracted_children += file_type_statistic.get('count', 0)

    return extracted_children - NOT_EXTRACTED_CONTAINER


def extract_uris(tc_report):
    uris = []
    uris.extend(extract_static_strings(tc_report))
    uris.extend(extract_malware_configuration(tc_report))
    return uris


def extract_static_strings(tc_report):
    interesting_strings = tc_report.get('interesting_strings', [])

    uris = []
    for entry in interesting_strings:
        if entry['category'] not in INTERESTING_URI_CATEGORIES:
            continue

        values = entry.get('values', [])
        for value in values:
            if is_interesting_uri(value):
                uri_type    = map_tc_uri_category_to_type(entry['category'])
                adapted_uri = format_uri(value, uri_type, category='static_strings')
                uris.append(adapted_uri)

    return uris


def extract_malware_configuration(tc_report):
    bot_packages = safely_traverse_dict(tc_report, 'info.package.properties', [])

    uris = []
    for bot_info in bot_packages:
        field_name = bot_info.get('name', '')

        if any(field_name.startswith(malware_config) for malware_config in MALWARE_CONFIG_FIELDS):
            value = bot_info.get('value')
            if value:
                uri_type    = 'ftp' if field_name.startswith('botFTPServer') else _parse_uri_type(value)
                adapted_uri = format_uri(value, uri_type, category='malware_configuration')
                uris.append(adapted_uri)

    return uris


def map_tc_uri_category_to_type(tc_uri_category):
    return 'http' if tc_uri_category in URI_ADAPTED_HTTP_CATEGORY else tc_uri_category


def format_uri(value, uri_type, category):
    return OrderedDict([
        ('category' , category),
        ('type'     , uri_type),
        ('value'    , value)
    ])


def _parse_uri_type(uri):
    if is_valid_ipv4_address(uri):
        return 'ipv4'
    if is_valid_ipv6_address(uri):
        return 'ipv6'
    return 'http'


def compose_pe_field(metadata):
    pe = OrderedDict()
    for name, value in [('compile_time'     , extract_pe_compile_time(metadata)),
                        ('company_name'     , extract_pe_company_name(metadata)),
                        ('product_name'     , extract_pe_product_name(metadata)),
                        ('original_name'    , extract_pe_original_name(metadata)),
                        ('section'          , extract_pe_section(metadata)),
                        ('resource'         , extract_pe_resources(metadata)),
                        ('net_mvid'         , extract_dotnet_module_id(metadata)),
                        ('pdb_path'         , extract_pdb_paths(metadata)),
                        ('export'           , extract_pe_exports(metadata)),
                        ('import'           , extract_pe_imports(metadata))]:
        if value:
            pe[name] = value

    return pe


def extract_pe_compile_time(metadata):
    return safely_traverse_dict(metadata, 'application.pe.file_header.time_date_stamp')


def extract_pe_company_name(metadata):
    return _extract_from_version_info(metadata, 'CompanyName')


def extract_pe_product_name(metadata):
    return _extract_from_version_info(metadata, 'ProductName')


def extract_pe_original_name(metadata):
    return _extract_from_version_info(metadata, 'OriginalFilename')


def _extract_from_version_info(metadata, field_name):
    version_info = safely_traverse_dict(metadata, 'application.pe.version_info', [])
    for data in version_info:
        if data['name'] == field_name:
            if 'value' not in data:
                continue
            return data['value']


def extract_pe_section(metadata):
    sections = safely_traverse_dict(metadata, 'application.pe.sections', [])

    extracted_sections = []
    for section in sections:
        section_data = OrderedDict()
        section_name = section.get('name')
        if not section_name:
            continue

        section_data['name'] = section_name
        sha1 = _extract_sha1_hash(section)
        if sha1:
            section_data['sha1'] = sha1

        extracted_sections.append(section_data)

    return extracted_sections


def extract_pe_resources(metadata):
    resources = safely_traverse_dict(metadata, 'application.pe.resources', [])

    resources_reduced = []
    for resource in resources:
        reduced_resource = OrderedDict([(key, resource[key])
                                        for key in RESOURCES_FILEDS if key in resource])
        if not resource:
            continue

        sha1 = _extract_sha1_hash(resource)
        if sha1:
            reduced_resource['sha1'] = sha1

        resources_reduced.append(reduced_resource)

    return resources_reduced


def _extract_sha1_hash(data):
    for hash_data in data.get('hashes', []):
        if hash_data['name'] == 'sha1':
            return hash_data['value']


def extract_dotnet_module_id(metadata):
    return safely_traverse_dict(metadata, 'application.dotnet.mvid')


def extract_pdb_paths(metadata):
    codeviews = safely_traverse_dict(metadata, 'application.pe.codeviews', [])

    pdb_paths = []
    for pdb_path_data in codeviews:
        pdb_paths.append(pdb_path_data['pdb_path'])
    return pdb_paths


def extract_pe_exports(metadata):
    return safely_traverse_dict(metadata, 'application.pe.exports.apis', [])


def extract_pe_imports(metadata):
    imports = safely_traverse_dict(metadata, 'application.pe.imports', [])

    grouped_imports = OrderedDict()
    for group in imports:
        import_name = group.get('name')
        import_apis = group.get('apis', [])

        if import_name and import_apis:
            grouped_imports[import_name] = import_apis

    return grouped_imports


def compose_classification_field(tc_report):
    classification = OrderedDict()

    result_classification = extract_sample_classification(tc_report)
    for name, value in [('propagated'     , safely_traverse_dict(tc_report, 'classification.propagation_source.value')),
                        ('classification' , result_classification),
                        ('factor'         , safely_traverse_dict(tc_report, 'classification.factor')),
                        ('result'         , extract_sample_classification_result(tc_report)),
                        ('scanner_result' , extract_scanner_result(tc_report))]:
        if value or (name == 'factor' and is_valid_tc_factor(value, result_classification)):
            classification[name] = value

    return classification


def extract_sample_classification(tc_report):
    classification = safely_traverse_dict(tc_report, 'classification.classification')
    if classification is not None and isinstance(classification, int):
        classification = ClassificationResultTC.from_enum(classification)
    return classification


def extract_sample_classification_result(tc_report):
    scan_results = safely_traverse_dict(tc_report, 'classification.scan_results', [])
    if not scan_results:
        return

    final_result = scan_results[0]
    return final_result.get('result')


def extract_scanner_result(tc_report):
    scan_results = safely_traverse_dict(tc_report, 'classification.scan_results', [])

    scanner_result = []
    for result in scan_results:
        formatted_result = format_scanner_result(result)
        if formatted_result:
            scanner_result.append(formatted_result)
    return scanner_result


def format_scanner_result(scanner_result):
    result = OrderedDict()

    classification = _extract_scanner_result_classification(scanner_result)
    for name, value in [('name'           , scanner_result.get('name')),
                        ('version'        , scanner_result.get('version')),
                        ('type'           , _extract_scanner_result_type(scanner_result)),
                        ('classification' , classification),
                        ('factor'         , scanner_result.get('factor')),
                        ('result'         , scanner_result.get('result'))]:
        if value or (name == 'factor' and is_valid_tc_factor(value, classification)):
            result[name] = value

    return result


def _extract_scanner_result_classification(scanner_result):
    classification = scanner_result.get('classification')
    if classification is not None and isinstance(classification, int):
        return ClassificationResultTC.from_enum(classification)


def _extract_scanner_result_type(scanner_result):
    component_type = scanner_result.get('type')
    if component_type is not None and isinstance(component_type, int):
        return ClassificationTypeTC.from_enum(component_type)


def compose_signer_certificate_field(metadata):
    certificates = extract_signer_certificates(metadata)
    if not certificates:
        return extract_tc4_signer_certificates(metadata)

    return [refactor_signer_certificate_fields(certificate) for certificate in certificates]


def extract_signer_certificates(tc_report):
    certificates = safely_traverse_dict(tc_report, 'certificate.certificates', [])
    signer_info  = safely_traverse_dict(tc_report, 'certificate.signer_info')
    if not signer_info:
        return

    certificate_subjects = []
    certificate_issuers  = []
    for certificate in certificates:
        certificate_issuer  = certificate['issuer']
        certificate_subject = certificate['subject']

        certificate_issuers.append(extract_distinguished_names(certificate_issuer))
        certificate_subjects.append(extract_distinguished_names(certificate_subject))

    signer_certificates = []
    for certificate_subject, certificate in zip(certificate_subjects, certificates):
        if certificate_subject in certificate_issuers or is_timestamp(certificate):
            continue

        signer_certificates.append(certificate)

    return signer_certificates


def extract_tc4_signer_certificates(tc_report):
    signatures = tc_report.get('signatures', [])
    for signature in signatures:
        signer_certificate = signature.get('certificate')
        if signer_certificate:
            _extract_tc4_thumbprint(signer_certificate)
            _extract_tc4_distinguished_names(signer_certificate, 'subject')
            _extract_tc4_distinguished_names(signer_certificate, 'issuer')

            return [signer_certificate]


def _extract_tc4_thumbprint(signer_certificate):
    thumbprints = signer_certificate.get('thumbprints', [])
    for thumbprint in thumbprints:
        if thumbprint['name'] == 'SHA256':
            signer_certificate['thumbprint_algorithm'] = 'sha256'
            signer_certificate['thumbprint'] = thumbprint['value']
            del signer_certificate['thumbprints']
            break


def _extract_tc4_distinguished_names(certificate, name):
    subject = certificate.get(name, [])
    certificate[name] = {name: '' for name in CERT_DISTINGUISHED_NAMES}
    for field in subject:
        if field['name'] == 'commonName':
            certificate[name]['common_name'] = field['value']
        elif field['name'] == 'organizationName':
            certificate[name]['organization_name'] = field['value']
        elif field['name'] == 'unitName':
            certificate[name]['unit_name'] = field['value']
        elif field['name'] == 'countryName':
            certificate[name]['country_name'] = field['value']


def extract_distinguished_names(description):
    distinguished_names = OrderedDict()
    for regex, group_name in [(CERT_COMMON_NAME              , 'common_name'),
                              (CERT_ORGANIZATION_NAME        , 'organization_name'),
                              (CERT_ORGANIZATIONAL_UNIT_NAME , 'unit_name')]:
        extracted_name = execute_regex_return_group_on_match(regex, description, group_name)
        distinguished_names[group_name] = extracted_name
    return distinguished_names


def execute_regex_return_group_on_match(regex, search_string, group):
    match = re.match(regex, search_string)
    if match:
        return match.group(group)


def is_timestamp(certificate):
    for certificate_extension in certificate.get('extensions', []):
        certificate_extension_name = certificate_extension['name']
        certificate_extension_value = certificate_extension['value']

        if certificate_extension_name in TIMESTAMP_NAME_KEYS and certificate_extension_value == 'Time Stamping':
            return True


def refactor_signer_certificate_fields(certificate):
    for party in ['issuer', 'subject']:
        party_raw_distinguished_names = certificate.get(party)
        if not party_raw_distinguished_names:
            continue

        distinguished_names = extract_distinguished_names(party_raw_distinguished_names)

        party_distinguished_names = OrderedDict()
        for name in CERT_DISTINGUISHED_NAMES:
            value = distinguished_names.get(name)
            if value:
                party_distinguished_names[name] = value

        certificate[party] = party_distinguished_names

    return format_certificate(certificate)


def format_certificate(certificate):
    formatted_certificate = OrderedDict()
    for field in CERTIFICATE_FIELDS:
        value = certificate.get(field)
        if value:
            value = lower_if_thumbprint_meta(field, value)
            formatted_certificate[field] = value

    return formatted_certificate


def lower_if_thumbprint_meta(field, value):
    if field == 'thumbprint' or field == 'thumbprint_algorithm':
        return value.lower()
    return value
