
import re


class Classification(object):
    UNKNOWN    = 'unknown'
    UNDECIDED  = 'undecided'
    KNOWN      = 'known'
    GOODWARE   = 'goodware'
    SUSPICIOUS = 'suspicious'
    MALICIOUS  = 'malicious'

    _DEFINED_CLASSIFICATIONS = {constant for constant in vars().values()
                                if isinstance(constant, str) and not constant.startswith('_')}

    @classmethod
    def is_malware(cls, value):
        try:
            return value.lower() in (cls.SUSPICIOUS, cls.MALICIOUS)
        except AttributeError:
            return False

    @classmethod
    def is_valid(cls, value):
        try:
            return value.lower() in cls._DEFINED_CLASSIFICATIONS
        except AttributeError:
            return False


class Description(object):
    HIGH_TRUST  = 'high trust'
    LOW_TRUST   = 'low trust'
    UNDECIDED   = 'not enough data'
    LOW_THREAT  = 'low threat'
    HIGH_THREAT = 'high threat'


class JoeClassification(object):
    WHITELISTED = 'whitelisted'
    CLEAN       = 'clean'

    CLASSIFICATION_MAPPING = {
        WHITELISTED               : (Classification.GOODWARE   , Description.HIGH_TRUST),
        CLEAN                     : (Classification.GOODWARE   , Description.LOW_TRUST),
        Classification.SUSPICIOUS : (Classification.SUSPICIOUS , Description.LOW_THREAT),
        Classification.MALICIOUS  : (Classification.MALICIOUS  , Description.HIGH_THREAT),
        Classification.UNKNOWN    : (Classification.UNDECIDED  , Description.UNDECIDED)
    }

    @classmethod
    def from_adapted_report(cls, report):
        classification = report.get('classification')
        if not classification:
            return Classification.UNDECIDED, Description.UNDECIDED

        return cls.CLASSIFICATION_MAPPING[classification]


class CloudDynamicAnalysisClassification(object):
    CLASSIFICATION_MAPPING = {
        Classification.KNOWN      : (Classification.GOODWARE, Description.LOW_TRUST),
        Classification.SUSPICIOUS : (Classification.SUSPICIOUS, Description.LOW_THREAT),
        Classification.MALICIOUS  : (Classification.MALICIOUS, Description.HIGH_THREAT),
        Classification.UNKNOWN    : (Classification.UNDECIDED, Description.UNDECIDED)
    }

    @classmethod
    def from_adapted_report(cls, report):
        classification = report.get('classification')
        if not classification:
            return Classification.UNDECIDED, Description.UNDECIDED

        classification = classification.lower()
        return cls.CLASSIFICATION_MAPPING[classification]


class Enum(object):
    ENUMS = {}

    @classmethod
    def from_enum(cls, value):
        return cls.ENUMS.get(value, Classification.UNKNOWN)


class ClassificationResultTC(Enum):
    UNKNOWN    = Classification.UNKNOWN
    GOODWARE   = Classification.GOODWARE
    SUSPICIOUS = Classification.SUSPICIOUS
    MALICIOUS  = Classification.MALICIOUS

    ENUMS = {
        0  : UNKNOWN,
        1  : GOODWARE,
        2  : SUSPICIOUS,
        3  : MALICIOUS,
    }


class ClassificationTypeTC(Enum):
    GENERIC   = 'generic'
    ANTIVIRUS = 'antivirus'
    SANDBOX   = 'sandbox'
    VALIDATOR = 'validator'
    UNPACKER  = 'unpacker'
    INTERNAL  = 'internal'
    CLOUD     = 'cloud'
    USER_OVERRIDE = 'user_override'
    CERTIFICATE = 'certificate'
    WHITELISTING = 'whitelisting'
    ANALYST_OVERRIDE = 'analyst_override'
    NEXT_GEN_AV = 'next_gen_av'

    ENUMS = {
        0   : GENERIC,
        1   : ANTIVIRUS,
        2   : SANDBOX,
        3   : VALIDATOR,
        4   : UNPACKER,
        5   : INTERNAL,
        6   : CLOUD,
        7   : USER_OVERRIDE,
        8   : CERTIFICATE,
        9   : WHITELISTING,
        10  : ANALYST_OVERRIDE,
        11  : NEXT_GEN_AV,
    }


MIN_NAME_LEN      = 4
MIN_SECTION_NAME  = 2
MAX_SECTION_NAME  = 8
MAX_RESOURCE_NAME = 128
MAX_IMPORT_NAME   = 256
MAX_NAME_LEN      = 512

NUM_IMPORT_FUNCTIONS = 10

SPECIAL_SECTION_NAME_PREFIX = ['_', '$']
RESOURCE_NUMBER_PATTERNS    = re.compile(r'^[\.,:;\-_!\?\'\"\$\%\&\/\(\)\[\]\{\}\=<>]+[0-9]$')
PDB_PATH_DRIVE_PREFIX       = re.compile(r'^[a-zA-Z]:')
FUNCTION_HEX_VALUES         = re.compile(r'(0x)?[0-9a-f]{4,5}')


class SearchParameters(object):
    PE_IMPORT_LIBS       = 'pe-import'
    PE_IMPORT_FUNCTIONS  = 'pe-function'
    PE_EXPORT_FUNCTIONS  = 'pe-export'
    PE_SECTION_NAME      = 'pe-section-name'
    PE_SECTION_SHA1      = 'pe-section-sha1'
    PE_RESOURCE_NAME     = 'pe-resource'
    PE_RESOURCE_SHA1     = 'pe-resource-sha1'
    PE_RESOURCE_TYPE     = 'pe-resource-type'
    PE_COMPANY_NAME      = 'pe-company-name'
    PE_PRODUCT_NAME      = 'pe-product-name'
    PE_ORIGINAL_NAME     = 'pe-original-name'
    PE_TIMESTAMP         = 'pe-timestamp'
    PDB_PATH             = 'pdb-path'
    CERT_SERIAL          = 'cert-serial'
    CERT_SUBJECT_NAME    = 'cert-subject-name'
    CERT_SUBJECT_COUNTRY = 'cert-subject-country'
    DOCUMENT_AUTHOR      = 'document-author'
    DOCUMENT_SUBJECT     = 'document-subject'
    DOCUMENT_TITLE       = 'document-title'
    EMAIL_FROM           = 'email-from'
    EMAIL_SUBJECT        = 'email-subject'
    DOTNET_MODULE_ID     = 'dotnet-module-id'
    IMPHASH              = 'imphash'
    FILENAME             = 'filename'
    SAMPLETYPE           = 'sampletype'

    NONPOLYMORPHIC_MALWARE_SINGLE_PARAMETERS        = [IMPHASH,
                                                       PDB_PATH,
                                                       DOTNET_MODULE_ID]

    MALICIOUS_CERTIFICATES_SINGLE_PARAMETERS        = [PE_COMPANY_NAME,
                                                       PE_PRODUCT_NAME,
                                                       PE_ORIGINAL_NAME,
                                                       CERT_SERIAL]

    MALICIOUS_CERTIFICATES_MULTIPLE_PARAMETERS      = [(CERT_SUBJECT_NAME, CERT_SUBJECT_COUNTRY)]

    MALICIOUS_EMAILS_SINGLE_PARAMETERS              = [EMAIL_FROM,
                                                       EMAIL_SUBJECT]

    CONTAINS_MALICIOUS_FILES_MULTIPLE_PARAMETERS    = [(DOCUMENT_AUTHOR, DOCUMENT_SUBJECT),
                                                       (DOCUMENT_AUTHOR, DOCUMENT_TITLE)]

    INFO_NONPOLYMORPHIC_MALWARE_SINGLE_PARAMETERS   = [PE_SECTION_SHA1,
                                                       PE_SECTION_NAME,
                                                       PE_RESOURCE_SHA1,
                                                       PE_RESOURCE_TYPE,
                                                       PE_RESOURCE_NAME,
                                                       PE_EXPORT_FUNCTIONS]

    INFO_NONPOLYMORPHIC_MALWARE_MULTIPLE_PARAMETERS = [(FILENAME   , SAMPLETYPE),
                                                       (SAMPLETYPE , PE_TIMESTAMP),
                                                       (PE_IMPORT_LIBS, PE_IMPORT_FUNCTIONS)]

    DATA_PATHS = {
        IMPHASH         : 'imphash',
        PE_COMPANY_NAME : 'pe.company_name',
        PE_PRODUCT_NAME : 'pe.product_name',
        PE_ORIGINAL_NAME: 'pe.original_name',
        DOTNET_MODULE_ID: 'pe.net_mvid',
        DOCUMENT_AUTHOR : 'document.author',
        DOCUMENT_SUBJECT: 'document.subject',
        DOCUMENT_TITLE  : 'document.title',
        EMAIL_FROM      : 'email.sender',
        EMAIL_SUBJECT   : 'email.subject',
        FILENAME        : 'filename',
        SAMPLETYPE      : 'sample_type',
        PE_TIMESTAMP    : 'pe.compile_time',
    }

    @classmethod
    def get_data_path(cls, search_parameter):
        return cls.DATA_PATHS.get(search_parameter)


class IsGeneric(object):
    TRUE  = True
    FALSE = False


FACTOR_5 = 5
FACTOR_4 = 4
FACTOR_3 = 3
FACTOR_2 = 2
FACTOR_1 = 1
FACTOR_0 = 0


class HuntingCategory(object):
    STATIC_ANALYSIS             = 'static_analysis'
    CLOUD_REPUTATION            = 'cloud_reputation'
    URI_ANALYTICS               = 'uri_analytics'
    CERTIFICATE_ANALYTICS       = 'certificate_analytics'
    FILE_SIMILARITY_ANALYTICS   = 'file_similarity_analytics'
    ADVANCED_SEARCH             = 'search'
    ADVANCED_SEARCH_INFORMATIVE = 'search (informative)'
    DYNAMIC_ANALYSIS            = 'dynamic_analysis'
    OTHER                       = 'other'

    CLOUD_CATEGORIES = {CLOUD_REPUTATION, URI_ANALYTICS, CERTIFICATE_ANALYTICS, FILE_SIMILARITY_ANALYTICS, ADVANCED_SEARCH}

    @classmethod
    def validate_task_category(cls, task_type):
        if task_type not in cls.CLOUD_CATEGORIES:
            listed_categories = ','.join(HuntingCategory.CLOUD_CATEGORIES)
            raise ValueError('Unsupported task type. '
                             'Available categories are: {}'.format(listed_categories))


class HuntingStatus(object):
    PENDING   = 'pending'
    COMPLETED = 'completed'
    SKIPPED   = 'skipped'
    FAILED    = 'failed'

    DEFAULT_FOR_HUNTING_CATEGORY = {
        HuntingCategory.STATIC_ANALYSIS           : COMPLETED,  # this is the trigger for everything else so it should be completed
        HuntingCategory.CLOUD_REPUTATION          : COMPLETED,  # either already completed or we need to set pending manually
        HuntingCategory.URI_ANALYTICS             : PENDING,
        HuntingCategory.CERTIFICATE_ANALYTICS     : PENDING,
        HuntingCategory.FILE_SIMILARITY_ANALYTICS : PENDING,
        HuntingCategory.ADVANCED_SEARCH           : PENDING,
    }
    ALL_STATUSES = [PENDING, SKIPPED, COMPLETED, FAILED]

    @classmethod
    def get_default(cls, category):
        return cls.DEFAULT_FOR_HUNTING_CATEGORY[category]


class DynamicAnalysisType(object):
    JOE_SANDBOX            = 'Joe Sandbox'
    CLOUD_DYNAMIC_ANALYSIS = 'Cloud Dynamic Analysis'
