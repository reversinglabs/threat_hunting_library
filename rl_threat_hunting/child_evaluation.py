
from rl_threat_hunting.filter.intersting_children import Child
from rl_threat_hunting.filter.intersting_children import InterestingChildren


def a1000_select_interesting_extracted_files(a1000_extracted_files_response, interesting_child_limit=10, include_all_malware=False):
    children = a1000_extracted_files_response.get('results', [])
    return _select_interesting_children(children, Child.parse_from_a1000_extracted_files_result,
                                        interesting_child_limit, include_all_malware)


def tiscale_select_interesting_children(tiscale_reports, interesting_child_limit=10, include_all_malware=False):
    return _select_interesting_children(tiscale_reports, Child.parse_from_tiscale_single_result,
                                        interesting_child_limit, include_all_malware)


def _select_interesting_children(children_data, parsing_method, interesting_child_limit, include_all_malware):
    selected_children = InterestingChildren(interesting_child_limit, include_all_malware)

    processed_children = set()
    for sample_data in children_data:
        child = parsing_method(sample_data)
        if not child.classification or not child.sha1 or child.sha1 in processed_children:
            continue

        processed_children.add(child.sha1)
        selected_children.add_child(child)

    return selected_children


def a1000_fetch_child_metadata(a1000_fetch_function, interesting_children):
    """
    :param a1000_fetch_function: this is a function that reads ticore result from a1000 for specific sha1 hash.
                                 function is called with only one parameter - sample sha1 hash.
    :param interesting_children: list of interesting_children
    :return: interesting_children with ticore results
    """
    enriched_children = []
    for child in interesting_children:
        child_meta = a1000_fetch_function(child.sha1)
        if child_meta:
            child.add_static_analysis(child_meta)
        enriched_children.append(child)
    return enriched_children


def a1000_combine_container_and_children(container, interesting_children):
    tiscale_format_report = {'tc_report': [container]}
    for child in interesting_children:
        report = child.get_tc_report()
        tiscale_format_report['tc_report'].append(report)
    return tiscale_format_report
