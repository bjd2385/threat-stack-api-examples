#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Collect all rulesets' rules to local file and convert them to CSV.
"""

from typing import Dict, Optional

import requests
import json
import logging
import csv

from mohawk import Sender
from urllib.error import URLError
from settings import env
from utils import retry


logging.basicConfig(level=env['LOGLEVEL'])


@retry(URLError)
def get_rulesets(credentials: Dict[str, str], org_id: str) -> Optional[Dict]:
    """
    Make a GET request to acquire a list of all rulesets and rules under an org.

    Args:
        credentials: dictionary containing a user's API credentials.
        org_id: the unique ID of the organization you're pulling the entries from.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing all rulesets in the org.
    """
    url = 'https://api.threatstack.com/v2/rulesets'
    logging.info(url)
    sender = Sender(
        credentials=credentials,
        url=url,
        method='GET',
        always_hash_content=False,
        content_type='application/json',
        ext=org_id
    )
    response = requests.get(
        url=url,
        headers={
            'Authorization': sender.request_header,
            'Content-Type': 'application/json'
        }
    )
    try:
        return response.json()
    except json.JSONDecodeError:
        raise URLError(
            'Did not get valid JSON in response: '
            f'{response.text if response.text else response.reason} '
            f'{response.status_code}'
        )


@retry(URLError, delay=30.0)
def get_ruleset_rule(credentials: Dict[str, str], org_id: str, ruleset_id: str, rule_id: str) -> Optional[Dict]:
    """
    Make a GET request to acquire a specific rule's data under a ruleset.

    Args:
        credentials: dictionary containing a user's API credentials.
        org_id: the unique ID of the organization you're pulling the entries from.
        ruleset_id: a unique ruleset ID.
        rule_id: a unique rule ID under the ruleset's ID.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing the rule's data.
    """
    url = f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules/{rule_id}'
    logging.info(url)
    sender = Sender(
        credentials=credentials,
        url=url,
        method='GET',
        always_hash_content=False,
        content_type='application/json',
        ext=org_id
    )
    response = requests.get(
        url=url,
        headers={
            'Authorization': sender.request_header,
            'Content-Type': 'application/json'
        }
    )
    try:
        return response.json()
    except json.JSONDecodeError:
        raise URLError(
            'Did not get valid JSON in response: '
            f'{response.text if response.text else response.reason} '
            f'{response.status_code}'
        )


def main() -> None:
    rulesets = get_rulesets(
        credentials={
            'id': env['API_ID'],
            'key': env['API_KEY'],
            'algorithm': 'sha256'
        },
        org_id=env['ORG_ID']
    )

    # List of all potential top-level fields in a returned rule's JSON response/object.
    # https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-a-rule-for-a-ruleset
    rule_fieldnames = [
        'rulesetId',
        'id',
        'name',
        'title',
        'type',
        'createdAt',
        'updatedAt',
        'severityOfAlerts',
        'alertDescription',
        'aggregateFields',
        'filter',
        'window',
        'threshold',
        'suppressions',
        'enabled',
        'fileIntegrityPaths',
        'ignoreFiles',
        'eventsToMonitor'
    ]

    with open(file=f'rules.csv', mode='w') as f:
        for ruleset in rulesets['rulesets']:
            # Unpack a ruleset's metadata
            i = ruleset['id']
            ruleset_name = ruleset['name']
            ruleset_description = ruleset['description']
            rule_ids = ruleset['rules']
            dict_writer = csv.DictWriter(f, fieldnames=rule_fieldnames, restval='NA', extrasaction='raise')

            # Now unpack rules' metadata on this ruleset.
            for rule_id in rule_ids:
                rule_data = get_ruleset_rule(
                    credentials={
                        'id': env['API_ID'],
                        'key': env['API_KEY'],
                        'algorithm': 'sha256'
                    },
                    org_id=env['ORG_ID'],
                    ruleset_id=i,
                    rule_id=rule_id
                )
                logging.debug(json.dumps(rule_data))
                for field in rule_fieldnames:
                    if field in rule_data and type(rule_data[field]) is dict:
                        # Convert these nested objects to strings to flatten the data.
                        rule_data['field'] = str(rule_data['field'])
                dict_writer.writerow(rule_data)


if __name__ == '__main__':
    main()
