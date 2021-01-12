#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A script that will pull your organization's audit log and enter it in a SQL database.

TODO: Write this collection to disk.
"""

from typing import Callable, Dict, Any, Optional, Sequence, Type, List

import requests
import json
import logging

from mohawk import Sender
from functools import wraps
from datetime import datetime, timedelta
from time import sleep
from urllib.error import URLError
from mysql.connector import connect, Error as MySQLError
from mysql.connector.cursor_cext import CMySQLCursor
from settings import env


logging.basicConfig(level=env['LOGLEVEL'])


def retry(exc: Type[Exception], tries: int = 3, delay: float = 3.0) -> Callable:
    """
    A general request retry decorator with optional time delay.

    Args:
        exc: exception to catch and retry on.
        tries: number of times to retry the wrapped function call. When `0`, retries indefinitely.
        delay: positive wait period.

    Raises:
        A RetryLimitExceeded exception in the event that the call could not be completed after the
        allotted number of attempts.

    Returns:
        Either the result of a successful function call (be it via retrying or not).
    """
    if tries < 0 or delay < 0:
        raise ValueError('Expected positive `tries` and `delay` values, received: '
                         f'tries {tries}, delay {delay}')

    def _f(f: Callable) -> Callable:

        class RetryLimitExceeded(OSError):
            pass

        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Any:
            res: Any = None

            def call() -> bool:
                nonlocal res
                try:
                    res = f(*args, **kwargs)
                    return True
                except exc as msg:
                    logging.info(f'Retrying: {msg} ~ {res}')
                    sleep(delay)
                    return False

            if tries > 0:
                for _ in range(tries):
                    if call():
                        return res
                else:
                    raise RetryLimitExceeded(
                        f'Exceeded max of {tries} tries. Raise the delay limit of {delay} or number of tries'
                    )
            else:
                while not call():
                    pass
                else:
                    return res
        return new_f
    return _f


class AuditSchema:
    """
    Helper class to format and parse audit events for submission to the SQL table.
    """
    def __init__(self, event_id: str, user_email: str, user_id: str, org_id: str,
                 result: str, cred: str, action: str, source: str, description: str,
                 event_time: str, context: str, godMode: str) -> None:
        self.godMode = godMode
        self.context = context
        self.event_time = event_time
        self.description = description
        self.source = source
        self.action = action
        self.cred = cred
        self.result = result
        self.org_id = org_id
        self.user_id = user_id
        self.user_email = user_email
        self.event_id = event_id




class SQL:
    """
    Helper class for interfacing with a SQL database.
    """

    _checked_org_ids = []

    def __init__(self, connection: CMySQLCursor) -> None:
        self.connection = connection

    def _check_table_exists(self, org_id: str) -> None:
        """
        Check that a table corresponding to an org. ID exists and create one if it does not.

        Args:
            org_id: table name to create if it does not exist.

        Returns:
            Nothing.
        """
        if self.connection.execute(f'SHOW TABLES LIKE \'{org_id}\';'):
            self.connection.execute(
                f'create table if not exists {org_id} ('
                f'id VARCHAR(40),'
                f'userId VARCHAR(30),'
                f''
                f'primary key (id));'
            )
        self._checked_org_ids.append(org_id)

    def write(self, records: List[dict]) -> None:
        """
        Flush audit log records to a MySQL database for further examination.

        Args:
            records: audit log records to commit to organization's table.

        Returns:
            Nothing.
        """
        for record in records:
            org = record['organizationId']
            if org not in self._checked_org_ids:
                self._check_table_exists(org)



def paginate_audit(connection: Optional[CMySQLCursor] =None) -> Callable:
    """
    Paginate the audit API call and optionally write records to a SQL database.

    Args:
        connection: Optional SQL database connection to publish the acquired results. By default,
            attempt to write to a table with name `env['ORG_ID']`.

    Returns:
        Nothing if a SQL database connection is provided. Otherwise, optionally, a JSON
        object from a completely paginated/exhausted endpoint.
    """
    def _f(f: Callable[..., Optional[Dict]]) -> Callable[..., Dict[str, Sequence[str]]]:
        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Optional[Dict[str, Sequence[str]]]:
            if connection:
                # Commit retrieved records to a SQL database. Create table with `env['ORG_ID']` if it
                # does not exist. Objective here is to not overflow memory by stashing all records
                # there until they're later flushed to a file or db.
                writer = SQL(connection)
                while (s := f(*args, **kwargs)) is not None:
                    logging.info(len(s['recs']))
                    writer.write(s['recs'])
                    if s['token'] is None or s['token'] == '':
                        break
                    else:
                        kwargs['token'] = s['token']
                        if 'window' in kwargs and kwargs['window']:
                            kwargs.pop('window')
                return None
            else:
                # If there's no database to commit these data to, then we're just dumping this to file
                # or somewhere else. Just collect all the events to memory and return the object.
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
    return _f


@retry(URLError)
def get_audit(ts_credentials: Dict[str, str], org_id: str, window: Optional[str] = None,
              token: Optional[str] = None) -> Optional[Dict]:
    """
    Make a GET request to acquire logs from your org's audit endpoint.

    Args:
        ts_credentials: dictionary containing a user's API credentials.
        org_id: the unique ID of the organization you're pulling the audit log entries from.
        window: period of time from which to acquire audit log events.
        token: pagination token.

    Raises:
        A URLError in the event that the response from a request is not valid/parseable JSON.

    Returns:
        A JSON object containing the first 50 results of the remaining audit log entries
        in the defined window in your organization.
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
        credentials=ts_credentials,
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
    # Number of days back to collect audit events from (from current moment in time).
    days = 1
    iso_window = f'from={(datetime.utcnow() - timedelta(days=days)).isoformat()}&until={datetime.utcnow().isoformat()}'

    with connect(user=env['SQL_USER'], password=env['SQL_PASSWORD'], host=env['SQL_HOST'], database=env['SQL_DATABASE']) as sql:
        cursor = sql.cursor(buffered=True)
        print(
            # Meant to be a decorator, so this syntax is a little odd. But, this is an example.
            paginate_audit(cursor)(get_audit)(**{
                    'ts_credentials': {
                        'id': env['API_ID'],
                        'key': env['API_KEY'],
                        'algorithm': 'sha256'
                    },
                    'org_id': env['ORG_ID'],
                    'window': iso_window
                }
            )
        )


if __name__ == '__main__':
    main()
