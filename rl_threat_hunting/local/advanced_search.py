
from rl_threat_hunting.cloud.advanced_search import AdvancedSearchInterface as CloudAdvancedSearchInterface


class AdvancedSearchInterface(CloudAdvancedSearchInterface):
    CLASSIFICATION = 'status'
    THREAT_NAME    = 'threat_name'
    THREAT_LEVEL   = 'threat_level'
