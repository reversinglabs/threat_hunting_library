#!/bin/python

import os
import sys
import json
import urllib3
import requests

urllib3.disable_warnings()

TOKEN = 'BadAcce55C0deBadAccessC0deBadAcce55C0deB'  # replace with a proper hex token

utils_dir = os.path.dirname(os.path.abspath(__file__))
DIRECTORY = os.path.join(utils_dir, '../tests/a1000_report/{}.json')


# echo 085e400d8bcad796cfe17ea211e78a08acddcaea | ./utils/fetch_a1000_report.py


def main():
    for line in sys.stdin:
        sample_sha1 = line.strip()
        tc_report   = get_tc_report(sample_sha1)

        dump_path = DIRECTORY.format(sample_sha1)
        dump_report(tc_report, dump_path)


def get_tc_report(sample_sha1):
    response = requests.get('https://a1000-analyst.rl.lan/api/samples/{}/ticore/'.format(sample_sha1),
                            headers={'Authorization': 'Token %s' % TOKEN}, verify=False)
    return response.json()


def dump_report(tc_report, path):
    with open(path, 'w') as dump_file:
        json.dump(tc_report, dump_file)


if __name__ == '__main__':
    main()
