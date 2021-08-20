
from collections import OrderedDict

from rl_threat_hunting.utils import safely_traverse_dict


ATTACHMENT_INDICATORS = ['attachment', '/attachment', 'core_email_data/attachment']
ATTACHMENT_FIELDS     = ['sha1', 'filename', 'sample_type', 'sample_size']

SENDER_EMAIL_HEADERS = ['from', 'reply_to']


def compose_email_field(metadata):
    tc_email = metadata.get('email')
    if not tc_email:
        return

    email = OrderedDict()

    for name, value in [('subject'   , extract_subject(metadata)),
                        ('sender'    , extract_sender(metadata)),
                        ('recipient' , extract_recipient(metadata)),
                        ('header'    , extract_interesting_headers(metadata))]:
        if value:
            email[name] = value

    return email


def extract_subject(metadata):
    return safely_traverse_dict(metadata, 'email.message.subject')


def extract_sender(metadata):
    for email_header in SENDER_EMAIL_HEADERS:
        header_metadata_path = 'email.message.{}'.format(email_header)
        header_values        = safely_traverse_dict(metadata, header_metadata_path)

        if header_values:
            sender = header_values[0]
            return sender['email']


def extract_recipient(metadata):
    recipients = safely_traverse_dict(metadata, 'email.message.recipients', [])
    return [recipient['email'] for recipient in recipients]


def extract_interesting_headers(metadata):
    headers = safely_traverse_dict(metadata, 'email.message.headers', [])

    extended_headers = []
    for header in headers:
        if is_extended_header(header):
            extended_headers.append(header)

    return extended_headers


def is_extended_header(header):
    return header['name'].startswith('X-')


def extract_attachments(children_tc_reports, children_sample_info):
    attachments = []
    for tc_report, sample_info in zip(children_tc_reports, children_sample_info):
        file_path = safely_traverse_dict(tc_report, 'info.file.file_path')

        if file_path and is_attachment(file_path):
            attachment = format_attachment(sample_info)
            if attachment:
                attachments.append(attachment)

    return attachments


def is_attachment(file_path):
    return any(file_path.startswith(prefix) for prefix in ATTACHMENT_INDICATORS)


def format_attachment(sample_info):
    attachment = OrderedDict()
    for field in ATTACHMENT_FIELDS:
        field_value = sample_info.get(field)
        if field_value:
            attachment[field] = field_value
    return attachment
