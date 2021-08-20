
import re
import collections

from rl_threat_hunting.utils import safely_traverse_dict
from rl_threat_hunting.utils import iteritems
from rl_threat_hunting.utils import is_python2_executing
from rl_threat_hunting.filter import WhitelistedSearchValues

from rl_threat_hunting.constants import SearchParameters
from rl_threat_hunting.constants import MIN_NAME_LEN, MAX_NAME_LEN
from rl_threat_hunting.constants import NUM_IMPORT_FUNCTIONS, MAX_IMPORT_NAME
from rl_threat_hunting.constants import SPECIAL_SECTION_NAME_PREFIX, MIN_SECTION_NAME, MAX_SECTION_NAME
from rl_threat_hunting.constants import RESOURCE_NUMBER_PATTERNS, MAX_RESOURCE_NAME
from rl_threat_hunting.constants import PDB_PATH_DRIVE_PREFIX
from rl_threat_hunting.constants import FUNCTION_HEX_VALUES

try:
    from itertools import izip_longest
except ImportError:
    from itertools import zip_longest as izip_longest


NONPOLYMORPHIC_MALWARE   = 'AND (classification:malicious AND NOT threatname:*.Virus*)'
MALICIOUS_CERTIFICATES   = 'AND (classification:malicious AND NOT tag:cert-malformed AND NOT tag:cert-invalid)'
MALICIOUS_EMAILS         = 'AND ((classification:malicious AND tag:email-attachment) OR '\
                           '(tag:email-subject-spam OR tag:email-subject-phishing OR '\
                           'tag:email-impersonation OR tag:email-deceptive-sender))'
CONTAINS_MALICIOUS_FILES = 'AND (classification:malicious AND (tag:contains-pe OR tag:capability-scripting))'

MAX_PARAMETERS_IN_QUERY = 25

MIN_SELECTED_MODULES         = 1
MIN_SELECTED_FUNCTIONS       = 20
MIN_SELECTED_FUNCTIONS_RATIO = 0.95
MAX_SELECTED_FUNCTIONS_RATIO = 1.0


def generate_search_queries(sample_info):
    queries = []

    for search_parameter, extraction_function in [
        (SearchParameters.PE_IMPORT_LIBS     , _extract_interesting_import_libs),
        (SearchParameters.PE_SECTION_NAME    , _extract_interesting_section_names),
        (SearchParameters.PE_IMPORT_FUNCTIONS, _extract_interesting_import_functions),
        (SearchParameters.PE_EXPORT_FUNCTIONS, _extract_interesting_export_functions),
        (SearchParameters.PE_RESOURCE_NAME   , _extract_interesting_resource_names),
        (SearchParameters.PDB_PATH           , _extract_interesting_pdb_paths),
    ]:

        parameter_values = extraction_function(sample_info)
        if parameter_values:
            queries.extend(_format_search_parameters(search_parameter, parameter_values))

    return sort_by_priority(queries)


def _extract_interesting_import_libs(sample_info):
    imports = safely_traverse_dict(sample_info, 'pe.import', {})

    interesting_imports = set()
    for import_lib, import_functions in iteritems(imports):
        if len(import_functions) > NUM_IMPORT_FUNCTIONS:
            continue

        import_lib = import_lib.lower()
        import_lib = filter_by_name_length([import_lib], MIN_NAME_LEN, MAX_IMPORT_NAME)

        interesting_imports.update(import_lib)

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PE_IMPORT_LIBS)
    interesting_imports.difference_update(whitelist)
    return interesting_imports


def _extract_interesting_import_functions(sample_info):
    imports = safely_traverse_dict(sample_info, 'pe.import', {})

    interesting_functions = set()
    for _, import_functions in iteritems(imports):
        import_functions = filter_by_name_length(import_functions, MIN_NAME_LEN, MAX_NAME_LEN)
        import_functions = remove_hex_values(import_functions)

        import_functions = {function.lower() for function in import_functions}
        interesting_functions.update(import_functions)

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PE_IMPORT_FUNCTIONS)
    interesting_functions.difference_update(whitelist)
    return interesting_functions


def _extract_interesting_export_functions(sample_info):
    exports = safely_traverse_dict(sample_info, 'pe.export', [])

    export_functions = filter_by_name_length(exports, MIN_NAME_LEN, MAX_NAME_LEN)
    export_functions = remove_hex_values(export_functions)

    export_functions = {function.lower() for function in export_functions}

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PE_EXPORT_FUNCTIONS)
    export_functions.difference_update(whitelist)

    return export_functions


def _extract_interesting_resource_names(sample_info):
    pe_resource = safely_traverse_dict(sample_info, 'pe.resource', [])

    interesting_resource_names = set()
    for resource in pe_resource:
        name = resource.get('name', '').lower()
        if not name or name.isdigit() or re.match(RESOURCE_NUMBER_PATTERNS, name):
            continue

        name = filter_by_name_length([name], MIN_NAME_LEN, MAX_RESOURCE_NAME)
        interesting_resource_names.update(name)

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PE_RESOURCE_NAME)
    interesting_resource_names.difference_update(whitelist)
    return interesting_resource_names


def _extract_interesting_pdb_paths(sample_info):
    pdb_paths = safely_traverse_dict(sample_info, 'pe.pdb_path', [])

    interesting_pdb_paths = set()
    for path in pdb_paths:
        path = path.lower()
        path = _remove_pdb_path_drive_letter(path)
        interesting_pdb_paths.add(path)

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PDB_PATH)
    interesting_pdb_paths.difference_update(whitelist)
    return interesting_pdb_paths


def _remove_pdb_path_drive_letter(pdb_path):
    drive_split = re.sub(PDB_PATH_DRIVE_PREFIX, '', pdb_path)
    if pdb_path != drive_split:
        pdb_path = drive_split

    return pdb_path.lstrip('\\')


def _extract_interesting_section_names(sample_info):
    sections = safely_traverse_dict(sample_info, 'pe.section', [])

    interesting_section_names = set()
    for section in sections:
        name = section.get('name').lower()
        name = normalize_prefix(name)
        if name.isdigit():
            continue

        name = filter_by_name_length([name], MIN_SECTION_NAME, MAX_SECTION_NAME)
        interesting_section_names.update(name)

    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.PE_SECTION_NAME)
    interesting_section_names.difference_update(whitelist)
    return interesting_section_names


def filter_by_name_length(names, min_len, max_len):
    return [name for name in names if min_len <= len(name) <= max_len]


def remove_hex_values(names):
    return [name for name in names if not re.match(FUNCTION_HEX_VALUES, name)]


def normalize_prefix(section_name):
    first_char = section_name[0]
    if not first_char.isalnum() and first_char not in SPECIAL_SECTION_NAME_PREFIX:
        section_name = section_name[1:]
    return section_name


def generate_complex_search_queries(sample_info):
    queries = []

    search_data = extract_search_data(sample_info)

    for search_parameters, additional_tags in [
        (SearchParameters.NONPOLYMORPHIC_MALWARE_SINGLE_PARAMETERS, NONPOLYMORPHIC_MALWARE),
        (SearchParameters.MALICIOUS_CERTIFICATES_SINGLE_PARAMETERS, MALICIOUS_CERTIFICATES),
        (SearchParameters.MALICIOUS_EMAILS_SINGLE_PARAMETERS      , MALICIOUS_EMAILS)
    ]:

        formatted_queries = compose_single_keyword_query(search_parameters, additional_tags, search_data)
        queries.extend(formatted_queries)

    for search_parameters, additional_tags in [
        (SearchParameters.MALICIOUS_CERTIFICATES_MULTIPLE_PARAMETERS  , MALICIOUS_CERTIFICATES),
        (SearchParameters.CONTAINS_MALICIOUS_FILES_MULTIPLE_PARAMETERS, CONTAINS_MALICIOUS_FILES)
    ]:

        formatted_queries = compose_multiple_keyword_query(search_parameters, additional_tags, search_data)
        queries.extend(formatted_queries)

    return sort_by_priority(queries)


def extract_search_data(sample_info):
    search_data = {}

    for search_parameter, extraction_function in [
        (SearchParameters.PDB_PATH            , _extract_interesting_pdb_paths),
        (SearchParameters.CERT_SERIAL         , _extract_cert_serial),
        (SearchParameters.CERT_SUBJECT_NAME   , _extract_cert_subject_name),
        (SearchParameters.CERT_SUBJECT_COUNTRY, _extract_cert_subject_country),
        (SearchParameters.IMPHASH             , _extract_imphash)
    ]:
        parameter_values = extraction_function(sample_info)
        if parameter_values:
            search_data[search_parameter] = generate_query_term(search_parameter, parameter_values)

    for search_parameter in [SearchParameters.PE_COMPANY_NAME,
                             SearchParameters.PE_PRODUCT_NAME,
                             SearchParameters.PE_ORIGINAL_NAME,
                             SearchParameters.DOTNET_MODULE_ID,
                             SearchParameters.DOCUMENT_AUTHOR ,
                             SearchParameters.DOCUMENT_SUBJECT,
                             SearchParameters.DOCUMENT_TITLE,
                             SearchParameters.EMAIL_FROM,
                             SearchParameters.EMAIL_SUBJECT]:
        parameter_value = _extract_single_string_values(sample_info, search_parameter)
        if parameter_value:
            search_data[search_parameter] = generate_query_term(search_parameter, [parameter_value])

    return search_data


def _extract_cert_serial(sample_info):
    signer_certificate_list = safely_traverse_dict(sample_info, 'signer_certificate_list', [])

    serial_numbers = set()
    for signer_certificate in signer_certificate_list:
        serial_number = signer_certificate.get('serial_number')
        if serial_number:
            serial_numbers.add(serial_number)

    return serial_numbers


def _extract_cert_subject_name(sample_info):
    signer_certificate_list = safely_traverse_dict(sample_info, 'signer_certificate_list', [])

    common_names = set()
    for signer_certificate in signer_certificate_list:
        common_name = safely_traverse_dict(signer_certificate, 'subject.common_name')
        if common_name:
            common_names.add(common_name)

    return common_names


def _extract_cert_subject_country(sample_info):
    signer_certificate_list = safely_traverse_dict(sample_info, 'signer_certificate_list', [])

    common_names = set()
    for signer_certificate in signer_certificate_list:
        country_name = safely_traverse_dict(signer_certificate, 'subject.country_name')
        if country_name:
            common_names.add(country_name)

    return common_names


def _extract_imphash(sample_info):
    imphash   = safely_traverse_dict(sample_info, SearchParameters.IMPHASH)
    whitelist = WhitelistedSearchValues.get_whitelist(SearchParameters.IMPHASH)
    if not imphash or imphash in whitelist:
        return

    selected_modules = _extract_interesting_import_libs(sample_info)

    imports = safely_traverse_dict(sample_info, 'pe.import', {})
    total_functions_cnt = 0
    for functions in imports.values():
        total_functions_cnt += len(functions)

    selected_functions = _extract_interesting_import_functions(sample_info)

    selected_functions_ratio = 0.0
    if total_functions_cnt != 0:
        selected_functions_ratio = len(selected_functions) / float(total_functions_cnt)

    has_only_functions_selected       = not selected_modules \
                                        and selected_functions_ratio == MAX_SELECTED_FUNCTIONS_RATIO
    has_module_and_functions_selected = len(selected_modules) == MIN_SELECTED_MODULES \
                                        and len(selected_functions) > MIN_SELECTED_FUNCTIONS \
                                        and selected_functions_ratio >= MIN_SELECTED_FUNCTIONS_RATIO

    if has_only_functions_selected \
       or has_module_and_functions_selected \
       or len(selected_modules) > MIN_SELECTED_MODULES:
        return [imphash]


def _extract_single_string_values(sample_info, search_parameter):
    value_path = SearchParameters.get_data_path(search_parameter)
    value      = safely_traverse_dict(sample_info, value_path)
    if not value:
        return

    whitelist = WhitelistedSearchValues.get_whitelist(search_parameter)
    if search_parameter in WhitelistedSearchValues.CASE_SENSITIVE_WHITELISTS:
        is_whitelisted = value in whitelist
    else:
        is_whitelisted = value.lower() in whitelist

    if not is_whitelisted:
        return value


def generate_complex_info_search_queries(sample_info):
    queries = []

    search_data = extract_informative_search_data(sample_info)

    for search_parameters, compose_function in [
        (SearchParameters.INFO_NONPOLYMORPHIC_MALWARE_SINGLE_PARAMETERS  , compose_single_keyword_query),
        (SearchParameters.INFO_NONPOLYMORPHIC_MALWARE_MULTIPLE_PARAMETERS, compose_multiple_keyword_query)
    ]:

        formatted_queries = compose_function(search_parameters, NONPOLYMORPHIC_MALWARE, search_data)
        queries.extend(formatted_queries)

    return queries


def extract_informative_search_data(sample_info):
    search_data = {}

    for search_parameter, extraction_function in [
        (SearchParameters.PE_SECTION_SHA1    , _extract_section_sha1),
        (SearchParameters.PE_SECTION_NAME    , _extract_interesting_section_names),
        (SearchParameters.PE_RESOURCE_SHA1   , _extract_resource_sha1),
        (SearchParameters.PE_EXPORT_FUNCTIONS, _extract_interesting_export_functions),
        (SearchParameters.PE_IMPORT_LIBS     , _extract_interesting_import_libs),
        (SearchParameters.PE_IMPORT_FUNCTIONS, _extract_interesting_import_functions),
        (SearchParameters.PE_RESOURCE_NAME   , _extract_interesting_resource_names)
    ]:
        parameter_values = extraction_function(sample_info)
        if parameter_values:
            search_data[search_parameter] = generate_query_term(search_parameter, parameter_values)

    parameter_values = _extract_resource_types(sample_info)
    if parameter_values:
        search_data[SearchParameters.PE_RESOURCE_TYPE] = generate_query_term('pe-resource', parameter_values)

    for search_parameter in [SearchParameters.FILENAME,
                             SearchParameters.SAMPLETYPE,
                             SearchParameters.PE_TIMESTAMP]:

        search_parameter_data_path = SearchParameters.get_data_path(search_parameter)
        parameter_value = safely_traverse_dict(sample_info, search_parameter_data_path)
        if parameter_value:
            search_data[search_parameter] = generate_query_term(search_parameter, [parameter_value])

    return search_data


def _extract_section_sha1(sample_info):
    sections = safely_traverse_dict(sample_info, 'pe.section', [])

    section_hashes = set()
    for section in sections:
        section_sha1 = section.get('sha1')
        if section_sha1:
            section_hashes.add(section_sha1)

    return section_hashes


def _extract_resource_sha1(sample_info):
    resources = safely_traverse_dict(sample_info, 'pe.resource', [])

    resource_hashes = set()
    for resource in resources:
        resource_sha1 = resource.get('sha1')
        if resource_sha1:
            resource_hashes.add(resource_sha1)

    return resource_hashes


def _extract_resource_types(sample_info):
    resources = safely_traverse_dict(sample_info, 'pe.resource', [])

    resource_types = set()
    for resource in resources:
        resource_type = resource.get('type')
        if resource_type:
            resource_types.add(resource_type)

    return resource_types


def generate_query_term(search_parameter, parameter_values):
    if len(parameter_values) == 1:
        value = list(parameter_values)[0]
        return '{}:{}'.format(search_parameter, _format_value(value))

    formatted_parameter_values = _format_search_parameters(search_parameter, parameter_values)
    values = sorted_from_longest(formatted_parameter_values)[:MAX_PARAMETERS_IN_QUERY]

    return '({})'.format(' OR '.join(values))


def _format_search_parameters(field_name, field_values):
    queries = []
    for value in field_values:
        queries.append('{}:{}'.format(field_name, _format_value(value)))
    return queries


def _format_value(value):
    if is_python2_executing():
        text = _encode_value(value)
    else:
        text = str(value)

    if any(char in text for char in [' ', '*', '?', '_']):
        text = '"{}"'.format(text)
    return text


def _encode_value(value):
    try:
        return value.encode('utf-8')
    except (UnicodeDecodeError, AttributeError):
        return str(value)


def compose_single_keyword_query(search_parameters, additional_tags, search_data):
    formatted_queries = []
    for search_parameter in search_parameters:
        parameter_values = search_data.get(search_parameter)
        formatted_query = append_additional_search_tags([parameter_values], additional_tags)
        formatted_queries.extend(formatted_query)

    return formatted_queries


def compose_multiple_keyword_query(search_parameters, additional_tags, search_data):
    formatted_queries = []
    for search_parameter_collection in search_parameters:
        parameter_values = [search_data.get(search_parameter) for search_parameter in search_parameter_collection]
        formatted_query = append_additional_search_tags(parameter_values, additional_tags)
        formatted_queries.extend(formatted_query)

    return formatted_queries


def append_additional_search_tags(parameter_values, additional_tags):
    if None in parameter_values:
        return []
    query = '{} {}'.format(' AND '.join(parameter_values), additional_tags)

    return [query]


def sort_by_priority(search_queries):
    queries_by_keyword = collections.defaultdict(list)
    for query in sorted_from_longest(search_queries):
        primary_keyword = query.split(':')[0]
        queries_by_keyword[primary_keyword].append(query)

    for data in izip_longest(*queries_by_keyword.values(), fillvalue=''):
        for item in sorted_from_longest(data):
            if item:
                yield item


def sorted_from_longest(data):
    return sorted(data, key=lambda item: len(item), reverse=True)
