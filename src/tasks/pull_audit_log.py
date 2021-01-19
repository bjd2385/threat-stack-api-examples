#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A script that will pull your organization's audit log and append it to an existing local *.csv file.

TODO: Write this collection to disk.
"""

from typing import Callable, Dict, Any, Optional, Union, Sequence, Type

import requests
import json
import logging

from mohawk import Sender
from functools import wraps
from datetime import datetime, timedelta
from time import sleep
from urllib.error import URLError
from settings import env
from utils import retry


logging.basicConfig(level=env['LOGLEVEL'])


def paginate_audit(f: Callable[..., Optional[Dict]]) -> Callable[..., Dict[str, Sequence[str]]]:
    """
    Paginate the audit API call.

    Args:
        f: a method that makes an API call that is paginated, according to our documentation.
           https://apidocs.threatstack.com/v2/rest-api-v2/pagination

    Returns:
        A JSON object from a completely paginated/exhausted endpoint.
    """

    @wraps(f)
    def new_f(*args: Any, **kwargs: Any) -> Dict[str, Sequence[str]]:
        obj = {
            'recs': [],
            'token': ''
        }
        while (s := f(*args, **kwargs)) is not None:
            obj['recs'] += s['recs']
            logging.info(len(obj['recs']))
            if s['token'] is None or s['token'] == '':
                break
            else:
                kwargs['token'] = s['token']
                if 'window' in kwargs and kwargs['window']:
                    kwargs.pop('window')
        return obj

    return new_f


@paginate_audit
@retry(URLError)
def get_audit(credentials: Dict[str, str], org_id: str, window: Optional[str] = None,
              token: Optional[str] = None) -> Optional[Dict]:
    """
    Make a GET request to acquire logs from your org's audit endpoint.

    Args:
        credentials: dictionary containing a user's API credentials.
        org_id: the unique ID of the organization you're pulling the audit log entries from.
        window: period of time from which to acquire audit log events.
        token: pagination token.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing the first 50 results of the remaining audit log entries in your organizaton.
    """
    url = 'https://api.threatstack.com/v2/auditlogs'
    if window and token:
        url += f'?{window}&token={token}'
    elif window:
        url += f'?{window}'
    elif token:
        url += f'?token={token}'
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
    days = 1
    iso_window = f'from={(datetime.utcnow() - timedelta(days=days)).isoformat()}&until={datetime.utcnow().isoformat()}'

    print(
        json.dumps(
            get_audit(
                credentials={
                    'id': env['API_ID'],
                    'key': env['API_KEY'],
                    'algorithm': 'sha256'
                },
                org_id=env['ORG_ID'],
                window=iso_window
            )
        )
    )


if __name__ == '__main__':
    main()
