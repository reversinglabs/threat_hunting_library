import re

from rl_threat_hunting.constants import SearchParameters
from rl_threat_hunting.constants import HuntingCategory


APPENDED_PARAMETERS = ['classification', 'tag', 'threatname']

QUERY_DESCRIPTIONS = {
    SearchParameters.PE_IMPORT_LIBS      : 'Searching for PE files by the names of imported libraries they contain.',
    SearchParameters.PE_IMPORT_FUNCTIONS : 'Searching for PE files by API-related metadata they contain.',
    SearchParameters.PE_EXPORT_FUNCTIONS : 'Searching for PE files by exported symbols they contain.',
    SearchParameters.PE_SECTION_NAME     : 'Searching for PE files by names of the sections they contain.',
    SearchParameters.PE_SECTION_SHA1     : 'Searching for PE files by hashes of the sections they contain.',
    SearchParameters.PE_RESOURCE_NAME    : 'Searching for PE files by name or type of resources they contain.',
    SearchParameters.PE_RESOURCE_SHA1    : 'Searching for PE files by the hash of resources they contain.',
    SearchParameters.PE_COMPANY_NAME     : 'Searching for PE files by the contents of their company name metadata field.',
    SearchParameters.PE_PRODUCT_NAME     : 'Searching for PE files by the contents of their product name metadata field.',
    SearchParameters.PE_ORIGINAL_NAME    : 'Searching for PE files by the contents of their original filename metadata field.',
    SearchParameters.PE_TIMESTAMP        : 'Searching for PE files by the date when they were compiled.',
    SearchParameters.PDB_PATH            : 'Searching for files by the specific PDB paths.',
    SearchParameters.CERT_SERIAL         : 'Searching for files by the serial number of the file certificate provided by the CA that issued the certificate.',
    SearchParameters.CERT_SUBJECT_NAME   : 'Searching for files by the name of the organization/system to which the certificate has been issued.',
    SearchParameters.CERT_SUBJECT_COUNTRY: 'Searching for files by the country of the organization/system to which the certificate has been issued.',
    SearchParameters.DOCUMENT_AUTHOR     : 'Searching for files by the contents of their document author metadata property.',
    SearchParameters.DOCUMENT_SUBJECT    : 'Searching for files by the contents of their document subject metadata property.',
    SearchParameters.DOCUMENT_TITLE      : 'Searching for files by the contents of their document title metadata property.',
    SearchParameters.EMAIL_FROM          : 'Searching for files by the sender email address.',
    SearchParameters.EMAIL_SUBJECT       : 'Searching for files by the subject email address.',
    SearchParameters.FILENAME            : 'Searching for files by its full or partial file name, or by its extension.',
    SearchParameters.SAMPLETYPE          : 'Searching for files by type as detected by TitaniumCore.',
    SearchParameters.DOTNET_MODULE_ID    : 'Searching for .NET files by IDs of modules they contain.',
    SearchParameters.IMPHASH             : 'Searching hash based on library/API names and their specific order within the executable.'
}

COMPLEX_QUERY_DESCRIPTION = {
    SearchParameters.CERT_SUBJECT_NAME  : 'Searching for files by the name and country of the organization/system to which the certificate has been issued.',
    SearchParameters.DOCUMENT_TITLE     : 'Searching for files by the contents of their document author and title metadata property.',
    SearchParameters.DOCUMENT_SUBJECT   : 'Searching for files by the contents of their document author and subject metadata property.',
    SearchParameters.FILENAME           : 'Searching for files by its full or partial file name, or by its extension and by type as detected by TitaniumCore.',
    SearchParameters.PE_TIMESTAMP       : 'Searching for PE files by the date when they were compiled and by type as detected by TitaniumCore.',
    SearchParameters.PE_IMPORT_FUNCTIONS: 'Searching for PE files by the names of imported libraries and API-related metadata they contain.'
}

APPENDED_PARAMETER_DESCRIPTIONS = {
    'email'                 : 'Also searching for strictly malicious files with email attachments or emails tagged as phishing emails.',
    'embedded_file'         : 'Also searching for strictly malicious files with embedded PE files or scripts.',
    'malicious_certificate' : 'Also searching for strictly malicious files without malformed or invalid certificates.',
    'nonpolymorphic_malware': 'Also searching for strictly non-polymorphic malicious files.'

}

QUERY_TYPE_DESCRIPTIONS = {
    HuntingCategory.CLOUD_REPUTATION         : 'Cloud reputation query determines the threat classification of a given file.',
    HuntingCategory.URI_ANALYTICS            : 'URI analytics determines the number of times given URI has been spotted in malicious files.',
    HuntingCategory.CERTIFICATE_ANALYTICS    : 'Certificate analytics determines the number of times given certificate has been spotted in malicious files.',
    HuntingCategory.FILE_SIMILARITY_ANALYTICS: 'File similarity analytics determines the number of malicious files similar to the given file.'
}


def build_query_type_description(query_type, query_term):
    if 'search' in query_type:
        return build_advanced_search_description(query_term)

    return QUERY_TYPE_DESCRIPTIONS.get(query_type)


def build_advanced_search_description(query_term):
    filtered_query_term = remove_parentheses(query_term)
    query_term_elements = re.split(' AND NOT | AND | OR ', filtered_query_term)

    search_parameters = set()
    appended_search_values = []
    for query_term_element in query_term_elements:
        search_parameter = query_term_element.split(':')
        if search_parameter[0] in APPENDED_PARAMETERS:
            search_value = search_parameter[1]
            appended_search_values.append(search_value)
            continue

        search_parameters.add(search_parameter[0])

    description_beginning = _get_description(search_parameters)
    description_ending    = _get_ending(appended_search_values)

    return _format_final_description(description_beginning, description_ending)


def _format_final_description(description_beginning, description_ending):
    if description_beginning and description_ending:
        return '{} {}'.format(description_beginning, description_ending)
    if description_beginning:
        return description_beginning
    if description_ending:
        return description_ending


def remove_parentheses(query_term):
    return query_term\
           .replace('(', '')\
           .replace(')', '')


def _get_description(search_parameters):
    if len(search_parameters) == 1:
        return QUERY_DESCRIPTIONS.get(list(search_parameters)[0])

    for search_parameter in search_parameters:
        complex_description = COMPLEX_QUERY_DESCRIPTION.get(search_parameter)
        if complex_description:
            return complex_description


def _get_ending(search_values):
    if 'email-attachment' in search_values:
        return APPENDED_PARAMETER_DESCRIPTIONS.get('email')
    if 'contains-pe' in search_values:
        return APPENDED_PARAMETER_DESCRIPTIONS.get('embedded_file')
    if 'cert-malformed' in search_values:
        return APPENDED_PARAMETER_DESCRIPTIONS.get('malicious_certificate')
    if '*.Virus*' in search_values:
        return APPENDED_PARAMETER_DESCRIPTIONS.get('nonpolymorphic_malware')
