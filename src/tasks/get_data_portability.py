#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Get a Data Portability setup.
"""

from typing import Dict, Optional

import requests
import json
import logging

from mohawk import Sender
from urllib.error import URLError
from settings import env
from utils import retry


logging.basicConfig(level=env['LOGLEVEL'])


@retry(URLError)
def get_data_portability(credentials: Dict[str, str], org_id: str) -> Optional[Dict]:
    """
    Make a GET request to see the Data Portability setup on an organization.

    Args:
        credentials: dictionary containing a user's API credentials.
        org_id: organization identifier/ID.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing the data portability setup on an organization.
    """
    url = 'https://api.threatstack.com/v2/integrations/s3export'
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
    print(
        json.dumps(
            get_data_portability(
                credentials={
                    'id': env['API_ID'],
                    'key': env['API_KEY'],
                    'algorithm': 'sha256'
                },
                org_id=env['ORG_ID']
            )
        )
    )


if __name__ == '__main__':
    main()
