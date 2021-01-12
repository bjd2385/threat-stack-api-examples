#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from dotenv import load_dotenv

load_dotenv()

import os

__all__ = [
    'env'
]


log_level = os.getenv('LOGLEVEL')
if not log_level:
    log_level = 'WARNING'


env = {
    # TS
    'API_KEY': os.getenv('API_KEY'),
    'API_ID': os.getenv('API_ID'),
    'ORG_ID': os.getenv('ORG_ID'),
    'LOGLEVEL': log_level.upper(),
    # SQL (optional)
    'SQL_USER': os.getenv('SQL_USER'),
    'SQL_PASSWORD': os.getenv('SQL_PASSWORD'),
    'SQL_HOST': os.getenv('SQL_HOST'),
    'SQL_DATABASE': os.getenv('SQL_DATABASE')
}
