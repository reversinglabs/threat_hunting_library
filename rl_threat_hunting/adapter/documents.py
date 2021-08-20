
from collections import OrderedDict

DOCUMENT_FIELDS = ['author', 'language', 'title', 'subject', 'description',
                   'creation_date', 'modified_date', 'version', 'pages', 'word_count']
SCRIPT_FIELDS   = ['sha1', 'filename', 'sample_type', 'sample_size']


def compose_document_field(metadata):
    tc_document = metadata.get('document')
    if not tc_document:
        return

    document = OrderedDict()
    for field in DOCUMENT_FIELDS:
        value = tc_document.get(field)
        if value:
            field = _rename_word_count(field)
            document[field] = value

    return document


def _rename_word_count(field):
    if field == 'word_count':
        return 'words'
    return field


def extract_scripts(children_sample_info):
    scripts = []
    for sample_info in children_sample_info:
        tags = sample_info.get('tags')
        if tags and is_script(tags):
            script = format_script(sample_info)
            scripts.append(script)
    return scripts


def is_script(tags):
    return 'script' in tags


def format_script(sample_info):
    script = OrderedDict()
    for field in SCRIPT_FIELDS:
        value = sample_info.get(field)
        if value:
            script[field] = value
    return script
