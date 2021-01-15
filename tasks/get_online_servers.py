#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Get online servers by region.
"""

from typing import Dict, Optional, Literal, Callable, Sequence, Any

import requests
import json
import logging

from mohawk import Sender
from urllib.error import URLError
from settings import env
from utils import retry
from functools import wraps


logging.basicConfig(level=env['LOGLEVEL'])

Status = Literal['online', 'offline']


def paginate_agents(f: Callable[..., Optional[Dict]]) -> Callable[..., Dict[str, Sequence[str]]]:
    """
    Paginate the GET agents API endpoint.

    Args:
        f: a method that makes an API call that is paginated, according to our documentation.
           https://apidocs.threatstack.com/v2/rest-api-v2/pagination

    Returns:
        A JSON object from a completely paginated/exhausted endpoint.
    """

    @wraps(f)
    def new_f(*args: Any, **kwargs: Any) -> Dict[str, Sequence[str]]:
        obj = {
            'agents': [],
            'token': ''
        }
        while (s := f(*args, **kwargs)) is not None:
            logging.debug(s)
            obj['agents'] += s['agents']
            logging.info(len(obj['agents']))
            if s['token'] is None or s['token'] == '':
                break
            else:
                kwargs['token'] = s['token']
        return obj

    return new_f


@paginate_agents
@retry(URLError)
def get_agents(credentials: Dict[str, str], org_id: str, status: Status, token: Optional[str] = None) -> Optional[Dict]:
    """
    Make a GET request to acquire logs from your org's audit endpoint.

    Args:
        credentials: dictionary containing a user's API credentials.
        org_id: the unique ID of the organization you're pulling the audit log entries from.
        status: state of the agent, be it online or offline.
        token: pagination token.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing the first 100 results of the remaining agent entries in your organizaton.
    """
    url = 'https://api.threatstack.com/v2/agents'
    if token:
        url += f'?status={status}&token={token}'
    elif status:
        url += f'?status={status}'
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
            get_agents(
                credentials={
                    'id': env['API_ID'],
                    'key': env['API_KEY'],
                    'algorithm': 'sha256'
                },
                org_id=env['ORG_ID'],
                status='online'
            )
        )
    )


if __name__ == '__main__':
    main()
