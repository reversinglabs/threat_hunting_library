
from collections import OrderedDict

from rl_threat_hunting import utils
from rl_threat_hunting import tc_metadata_adapter


HASHES = 'sha1', 'md5', 'sha256'
INTEGER_FIELDS = {'factor', 'scanner_count', 'scanner_match'}


def parse_mwp_metadata(service_response):
    try:
        mwp = _parse_bulk_query_response(service_response)
    except TypeError:
        mwp = _parse_single_query_response(service_response)

    adapted_meta = OrderedDict()
    sample_info  = generate_sample_info(mwp)
    if sample_info:
        adapted_meta['sample_info'] = sample_info
        tc_metadata_adapter.build_hunting_tasks_and_summarize(adapted_meta)

    return adapted_meta


def _parse_bulk_query_response(response):
    mwp_entries = utils.safely_traverse_dict(response, 'rl.entries')
    return mwp_entries[0]


def _parse_single_query_response(response):
    return utils.safely_traverse_dict(response, 'rl.malware_presence')


def generate_sample_info(mwp):
    sample_info = OrderedDict()

    cloud_reputation = compose_cloud_reputation(mwp)
    if cloud_reputation:
        sample_info['cloud_reputation'] = cloud_reputation

    hashes = compose_hash_values(mwp)
    sample_info.update(hashes)

    return sample_info


def compose_cloud_reputation(mwp):
    cloud_reputation = OrderedDict()

    classification = mwp.get('status', '').lower()
    for name, value in [('classification', classification),
                        ('threat_name'   , mwp.get('threat_name', '')),
                        ('factor'        , utils.get_factor(mwp, classification)),
                        ('first_seen'    , mwp.get('first_seen')),
                        ('last_seen'     , mwp.get('last_seen')),
                        ('scanner_count' , mwp.get('scanner_count')),
                        ('scanner_match' , mwp.get('scanner_match'))]:
        if value or (name in INTEGER_FIELDS and value == 0):
            cloud_reputation[name] = value

    return cloud_reputation


def compose_hash_values(mwp):
    values = {}
    for hash_type in HASHES:
        value = mwp.get(hash_type)
        if value:
            values[hash_type] = value

    if not values:
        # unknown record has no hashes
        values = mwp.get('query_hash')

    return values
