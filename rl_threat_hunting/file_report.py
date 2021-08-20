
import json

from rl_threat_hunting.utils import is_python2_executing


def write_json(hunting_meta, file_path):
    with open(file_path, 'w') as report:
        json.dump(hunting_meta, report, ensure_ascii=False, indent=4, separators=(',', ':'))
    return file_path


def read_json(file_path):
    with open(file_path) as hunting_meta:
        if is_python2_executing():
            return json.load(hunting_meta, object_pairs_hook=encode_unicode_utf8)
        else:
            return json.load(hunting_meta)


def encode_unicode_utf8(pairs):
    new_pairs = []
    for key, value in pairs:
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list) and value and isinstance(value[0], unicode):
            value = [item.encode('utf-8') for item in value]
        new_pairs.append((key, value))
    return dict(new_pairs)
