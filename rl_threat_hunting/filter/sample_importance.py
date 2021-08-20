
from rl_threat_hunting.utils import is_generic

from rl_threat_hunting.constants import Classification, IsGeneric
from rl_threat_hunting.constants import FACTOR_0, FACTOR_1, FACTOR_2, FACTOR_3, FACTOR_4, FACTOR_5


NON_MALWARE_PREFIXES = [
    'PE',
    'ELF',
    'MachO',
    'DEX',
    'ODEX',
]

NON_MALWARE_TYPES = [
    'PE',
    'ELF',
    'MachO',
    'DEX',
    'ODEX',
    'Text/None/EICAR',
    'Text/None/VBE',
    'Binary/None/VBE',
    'Text/VBA',
    'Text/EBM',
    'Text/PowerShell',
    'Text/VBS',
    'Binary/None/Certutil',
    'Text/Batch',
    'Text/None/InternetShortcut',
    'Document/None/InternetShortcut',
    'Binary/None/InternetShortcut',
    'Document/None/SYLK',
    'Document/None/IQY',
    'Text/None/IQY',
    'Document/None/MicrosoftREG',
    'Text/Shell',
    'Text/Acrobat JavaScript',
    'Text/JScript',
    'Text/JavaScript',
    'Text/WebExtensions JavaScript',
    'Text/Python',
    'Text/Perl',
    'Text/Perl6',
    'Text/None/SettingContent',
    'Binary/None/SettingContent',
    'Text/XML/SettingContent',
    'Binary/None/CLASS'
    'Binary/Archive/ActiveX'
    'Binary/None/ActiveX'
    'Document/None/ExtraBasicMacro'
    'Binary/None/CxMacro'
    'Document/None/Torrent'
    'Text/None/MIME',
    'Binary/Archive/OutlookMSG',
    'Binary/Archive/OutlookEmbeddedMSG',
    'Binary/Archive/ActiveMimeMSO',
    'Binary/None/ActiveMimeMSO',
    'Document/None/MicrosoftOfficeEncrypted',
    'Text/XML/MicrosoftOfficeXML',
    'Text/None/MicrosoftOfficeXML',
    'Document/None/MicrosoftExcel',
    'Document/None/MicrosoftWord',
    'Document/None/MicrosoftPowerPoint',
    'Document/None/MicrosoftPublisher',
    'Document/None/MSOneNoteONE',
    'Document/None/RTF',
    'Document/None/PDF',
    'Document/HTML',
    'Text/HTML',
    'Document/None/OpenDocumentText',
    'Document/None/OpenDocumentSpreadsheet',
    'Document/None/OpenDocumentPresentation',
    'Document/None/OpenDocumentGraphics',
    'Document/None/OpenDocumentFormula',
    'Document/None/OpenDocumentChart',
    'Document/None/OpenDocumentDatabase',
    'Document/None/OpenDocumentMaster',
    'Document/None/OpenDocumentWebPage',
    'Document/None/OpenDocumentImage',
    'Document/None/OpenOfficeGraphics',
    'Document/None/OpenOfficePresentation',
    'Document/None/OpenOfficeSpreadsheet',
    'Document/None/OpenOfficeFormula',
    'Document/None/OpenOfficeHTML',
    'Document/None/OpenOfficeMaster',
    'Document/None/OpenOfficeDatabase',
    'Document/None/OpenOfficeText',
    'Document/None/WordPerfect',
]

NON_MALWARE_SCORE_BY_TYPE = {non_malware_type: len(NON_MALWARE_TYPES) - idx
                             for idx, non_malware_type in enumerate(NON_MALWARE_TYPES)}

NON_MALWARE_PRIORITY_BY_CLASSIFICATION = [
    (FACTOR_0, Classification.GOODWARE),
    (FACTOR_1, Classification.GOODWARE),
    (FACTOR_2, Classification.GOODWARE),
    (FACTOR_3, Classification.GOODWARE),
    (FACTOR_4, Classification.GOODWARE),
    (FACTOR_5, Classification.GOODWARE),
    (None,     Classification.GOODWARE),
    (None,     Classification.UNDECIDED),
]

MAX_NON_MALWARE_SCORE = max(len(NON_MALWARE_TYPES), len(NON_MALWARE_PRIORITY_BY_CLASSIFICATION))

NON_MALWARE_SCORE_BY_CLASSIFICATION = {combination: MAX_NON_MALWARE_SCORE - idx
                                       for idx, combination in enumerate(NON_MALWARE_PRIORITY_BY_CLASSIFICATION)}

MALWARE_PRIORITY_LIST = [
    (FACTOR_5, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_5, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_5, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_5, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (FACTOR_4, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_4, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_4, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_4, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (FACTOR_3, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_3, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_3, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_3, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (FACTOR_2, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_2, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_2, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_2, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (FACTOR_1, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_1, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_1, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_1, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (FACTOR_0, Classification.MALICIOUS , IsGeneric.FALSE),
    (FACTOR_0, Classification.MALICIOUS , IsGeneric.TRUE),
    (FACTOR_0, Classification.SUSPICIOUS, IsGeneric.FALSE),
    (FACTOR_0, Classification.SUSPICIOUS, IsGeneric.TRUE),
    (None,     Classification.MALICIOUS,  IsGeneric.TRUE),
    (None,     Classification.SUSPICIOUS, IsGeneric.TRUE),
]

MAX_MALWARE_SCORE = len(MALWARE_PRIORITY_LIST)

MALWARE_SCORE = {combination: MAX_NON_MALWARE_SCORE + MAX_MALWARE_SCORE - idx
                 for idx, combination in enumerate(MALWARE_PRIORITY_LIST)}

MIN_MALWARE_SCORE = min(MALWARE_SCORE.values())
assert MIN_MALWARE_SCORE > MAX_NON_MALWARE_SCORE


def calculate_malware_interest_score(classification, factor, threat_name):
    return MALWARE_SCORE[factor, classification, is_generic(threat_name)]


def calculate_non_malware_interest_score_by_type(sample_type):
    score = NON_MALWARE_SCORE_BY_TYPE.get(sample_type)
    if score:
        return score

    for prefix in NON_MALWARE_PREFIXES:
        if sample_type.startswith(prefix):
            return NON_MALWARE_SCORE_BY_TYPE.get(prefix)


def calculate_non_malware_interest_score(classification, factor):
    if classification == Classification.UNDECIDED:
        factor = None
    return NON_MALWARE_SCORE_BY_CLASSIFICATION[factor, classification]
