
import sys
import socket

from collections import OrderedDict
from rl_threat_hunting.constants import Classification


def is_python2_executing():
    return sys.version_info.major == 2


def iteritems(d):
    if is_python2_executing():
        return d.iteritems()
    else:
        return iter(d.items())


def safely_traverse_dict(container, dot_delimited_key, default=None):
    keys = dot_delimited_key.split('.', 1)
    key  = keys[0]
    try:
        value = container[key]
    except (KeyError, IndexError):
        return default

    if len(keys) == 1:
        return value

    return safely_traverse_dict(value, keys[1], default)


def build_sample_type(file_type, file_subtype, identification):
    if identification:
        return '{}/{}/{}'.format(file_type, file_subtype, identification)

    return '{}/{}'.format(file_type, file_subtype)


def get_factor(data, classification):
    trust_factor = data.get('trust_factor')
    threat_level = data.get('threat_level')
    return translate_into_factor(classification, trust_factor=trust_factor, threat_level=threat_level)


def translate_into_factor(classification, trust_factor=None, threat_level=None):
    if Classification.is_malware(classification):
        return threat_level
    return trust_factor


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        return False


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False


def is_valid_tc_factor(factor, classification):
    return factor is not None and classification != Classification.UNKNOWN


def is_generic(threat_name):
    if not threat_name:
        return True
    family_name = threat_name.split('.')[-1]
    return family_name == 'Generic'


def encode_unicode(data):
    if isinstance(data, unicode):
        return data.encode('utf-8', 'ignore')

    elif isinstance(data, list):
        return [encode_unicode(item) for item in data]

    elif isinstance(data, dict):
        encoded_dict = OrderedDict()
        for key, value in data.iteritems():
            key   = encode_unicode(key)
            value = encode_unicode(value)
            encoded_dict[key] = value

        return encoded_dict

    return data
