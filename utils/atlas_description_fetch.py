#!/bin/python

import psycopg2
from psycopg2.extras import RealDictCursor

MALWARE_TYPE_COMMAND   = 'select type_name, type_description from malware_type'
MALWARE_FAMILY_COMMAND = 'select family_name, family_description from malware_family'


CONNECTION_PARAMETERS = {
    'user'    : 'atlas',
    'password': 'Da4suque',
    'host'    : 'alt-pgsql01.rl.lan',
    'port'    : '5432',
    'database': 'atlas'
}


def fetch_malware_family_descriptions():
    query_data = execute_postgres_query(CONNECTION_PARAMETERS, MALWARE_FAMILY_COMMAND)
    malware_family_descriptions = {}

    for item in query_data:
        malware_family_descriptions[item["family_name"]] = item["family_description"]

    return malware_family_descriptions


def fetch_malware_type_descriptions():
    query_data = execute_postgres_query(CONNECTION_PARAMETERS, MALWARE_TYPE_COMMAND)
    malware_type_descriptions = {}

    for item in query_data:
        malware_type_descriptions[item["type_name"]] = item["type_description"]

    return malware_type_descriptions


def execute_postgres_query(connection_parameters, query):
    with psycopg2.connect(cursor_factory=RealDictCursor, **connection_parameters) as connection:
        cursor = connection.cursor()
        cursor.execute(query)
        response = cursor.fetchall()

    return response


def main():
    print(fetch_malware_type_descriptions())
    print(fetch_malware_family_descriptions())


if __name__ == "__main__":
    main()
