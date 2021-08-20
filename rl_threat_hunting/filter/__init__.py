
from rl_threat_hunting.constants import SearchParameters

from rl_threat_hunting.filter.import_libs       import COMMON_IMPORT_LIBS
from rl_threat_hunting.filter.section_names     import COMMON_SECTION_NAMES
from rl_threat_hunting.filter.resource_names    import COMMON_RESOURCE_NAMES
from rl_threat_hunting.filter.import_functions  import COMMON_IMPORT_FUNCTIONS
from rl_threat_hunting.filter.export_functions  import COMMON_EXPORT_FUNCTIONS
from rl_threat_hunting.filter.pdb_paths         import COMMON_PDB_PATHS
from rl_threat_hunting.filter.pe_company_names  import COMMON_COMPANY_NAMES
from rl_threat_hunting.filter.pe_product_names  import COMMON_PRODUCT_NAMES
from rl_threat_hunting.filter.pe_original_names import COMMON_ORIGINAL_NAMES
from rl_threat_hunting.filter.dotnet_module_id  import COMMON_DOTNET_MODULE_ID
from rl_threat_hunting.filter.document_authors  import COMMON_DOCUMENT_AUTHORS
from rl_threat_hunting.filter.document_subjects import COMMON_DOCUMENT_SUBJECTS
from rl_threat_hunting.filter.document_titles   import COMMON_DOCUMENT_TITLES
from rl_threat_hunting.filter.email_from        import COMMON_EMAIL_FROM
from rl_threat_hunting.filter.email_subjects    import COMMON_EMAIL_SUBJECTS
from rl_threat_hunting.filter.imphash_override  import WHITELISTED_IMPHASH


class WhitelistedSearchValues(object):
    WHITELISTS = {
        SearchParameters.PE_IMPORT_LIBS     : COMMON_IMPORT_LIBS,
        SearchParameters.PE_SECTION_NAME    : COMMON_SECTION_NAMES,
        SearchParameters.PE_RESOURCE_NAME   : COMMON_RESOURCE_NAMES,
        SearchParameters.PE_IMPORT_FUNCTIONS: COMMON_IMPORT_FUNCTIONS,
        SearchParameters.PE_EXPORT_FUNCTIONS: COMMON_EXPORT_FUNCTIONS,
        SearchParameters.PE_COMPANY_NAME    : COMMON_COMPANY_NAMES,
        SearchParameters.PE_PRODUCT_NAME    : COMMON_PRODUCT_NAMES,
        SearchParameters.PE_ORIGINAL_NAME   : COMMON_ORIGINAL_NAMES,
        SearchParameters.DOTNET_MODULE_ID   : COMMON_DOTNET_MODULE_ID,
        SearchParameters.DOCUMENT_AUTHOR    : COMMON_DOCUMENT_AUTHORS,
        SearchParameters.DOCUMENT_SUBJECT   : COMMON_DOCUMENT_SUBJECTS,
        SearchParameters.DOCUMENT_TITLE     : COMMON_DOCUMENT_TITLES,
        SearchParameters.EMAIL_FROM         : COMMON_EMAIL_FROM,
        SearchParameters.EMAIL_SUBJECT      : COMMON_EMAIL_SUBJECTS,
        SearchParameters.IMPHASH            : WHITELISTED_IMPHASH,
    }

    CASE_SENSITIVE_WHITELISTS = {SearchParameters.PE_COMPANY_NAME, SearchParameters.PE_PRODUCT_NAME}

    @classmethod
    def get_whitelist(cls, search_parameter):
        return cls.WHITELISTS.get(search_parameter, set())
