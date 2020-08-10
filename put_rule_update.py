#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
An example PUT request on our rules endpoint.
"""


from typing import Dict, Optional

import requests
import json

from mohawk import Sender


def put_rule(credentials: Dict[str, str], org_id: str, ruleset_id: str, rule_id: str, rule: dict) -> Optional[dict]:
    """
    Make a PUT request to update a rule in an org.

    Returns:
        A dictionary containing the request response, otherwise prints the error and returns None.
    """
    url = 'https://api.threatstack.com/v2/rulesets/' + ruleset_id + '/rules/' + rule_id
    rule_data = json.dumps(rule)
    sender = Sender(
        credentials=credentials,
        url=url,
        content=rule_data,
        method='PUT',
        always_hash_content=False,
        content_type='application/json',
        ext=org_id
    )
    response = requests.put(
        url=url,
        data=rule_data,
        headers={
            'Authorization': sender.request_header,
            'Content-Type': 'application/json'
        }
    )
    try:
        return response.json()
    except json.JSONDecodeError:
        if response.text:
            print('Did not get valid JSON in response - probably an error, instead:', response.text)
        else:
            print('Did not get valid JSON in response - probably an error, instead:', response.reason)


def main() -> None:
    from settings import env

    payload = {
        "name": "Example Rule",
        "type": "Host",
        "title": "Example Rule Alert",
        # I want to update the severity to 1.
        "severityOfAlerts": 1,
        # We need to fix this field in the documentation as it's required. Also, the documentation is wrong, I got an
        # error message -
        # {'errors': ['Validation failed: body has invalid alertDescription value.  Must be between 1 and 300 characters long.']}
        "alertDescription": "Hello",
        "aggregateFields": [],
        "filter": "exe = \"example\"",
        "window": 86400,
        "threshold": 1,
        "suppressions": [],
        "enabled": True
    }

    print(
        put_rule(
            credentials={
                'id': env['API_ID'],
                'key': env['API_KEY'],
                'algorithm': 'sha256'
            },
            org_id=env['ORG_ID'],
            ruleset_id='0d72a9fc-e77c-11e9-a1ca-371a929df77a',
            rule_id='e4756d95-db32-11ea-983d-6145923f3c40',
            rule=payload
        )
    )


if __name__ == '__main__':
    main()
