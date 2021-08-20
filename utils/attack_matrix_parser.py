#!/usr/bin/python

from __future__ import print_function

import csv
import pprint

# From source: https://docs.google.com/spreadsheets/d/1x8c30YU4T7_1dVXDUQe8WcCq3n92Nb6AtTxDpfQnaQU/edit#gid=42408762
# Download 3 TSV files for parsing:
#     ATT&CK Matrix Mappings - TiCore.tsv
#     ATT&CK Matrix Mappings - Techniques.tsv
#     ATT&CK Matrix Mappings - Tactics.tsv
#
# ./attack_matrix_parser.py > ../rl_threat_hunting/atlas/attack_matrix.py

MAPPINGS_TEMPLATE = '''
TC_INDICATORS = {}
    
TECHNIQUES = {}
    
TACTICS = {}
'''


def main():
    tc_indicators = parse_ricc_ids()
    techniques    = parse_techniques()
    tactics       = parse_tactics()

    text = MAPPINGS_TEMPLATE.format(pprint.pformat(tc_indicators , indent=4),
                                    pprint.pformat(techniques    , indent=4),
                                    pprint.pformat(tactics       , indent=4))
    print(text)


def parse_ricc_ids():
    unique_ids = {}

    with open('ATT&CK Matrix Mappings - TiCore.tsv') as input_file:
        for data in csv.DictReader(input_file, delimiter='\t'):
            ricc_id    = data['Indicator']
            techniques = data['Techniques']
            if not techniques:
                continue

            techniques = techniques.split(';')
            unique_ids[ricc_id] = techniques

    return unique_ids


def parse_techniques():
    unique_ids = {}

    with open('ATT&CK Matrix Mappings - Techniques.tsv') as input_file:
        for data in csv.DictReader(input_file, delimiter='\t'):
            technique   = data['Id']
            tactics     = data['Tactics'].split(';')
            name        = data['Name']
            description = data['Description']

            unique_ids[technique] = {'tactics': tactics, 'name': name, 'description': description}

    return unique_ids


def parse_tactics():
    unique_ids = {}

    with open('ATT&CK Matrix Mappings - Tactics.tsv') as input_file:
        for data in csv.DictReader(input_file, delimiter='\t'):
            tactic      = data['Id']
            scope       = data['Scope']
            name        = data['Name']
            description = data['Description']

            unique_ids[tactic] = {'scope': scope, 'name': name, 'description': description}

    return unique_ids


if __name__ == '__main__':
    main()
