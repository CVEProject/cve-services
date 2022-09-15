import datetime as dt
import json
from src import env

import logging

logger = logging.getLogger(__name__)

CURRENT_YEAR = dt.datetime.now().year

# HTTP response codes
HTTP_OK = 200

# headers attached to every cve-services request
# org is always mitre, api user depends on setup, but is likely `cps`
BASE_HEADERS = {
    'CVE-API-KEY': env.AWG_API_KEY,
    'CVE-API-ORG': 'mitre',
    'CVE-API-USER': env.AWG_USER_NAME
}

# used to check invalid pagination errors
BAD_PAGE_ERROR_DETAILS = [{
    "msg": "Invalid value",
    "param": "page",
    "location": "query"
}]

def assert_contains(response, has_this, count=1):
    if count == 1:
        assert has_this in response.content.decode()
    else:
        assert response.content.decode().count(has_this) == count


def response_contains(response, has_this):
    assert_contains(response, has_this)


def response_contains_json(response, json_key, is_this, msg=None):
    assert json.loads(response.content.decode())[json_key] == is_this, msg


def ok_response_contains(response, has_this):
    assert response.status_code == HTTP_OK
    assert_contains(response, has_this)


def ok_response_contains_json(response, json_key, is_this):
    assert response.status_code == HTTP_OK
    assert json.loads(response.content.decode())[json_key] == is_this


def get_now_timestamp(fmt = '%Y-%m-%dT%H:%M:%S'):
    """
    Return the a string timestamp for the current date and time.
    
    The default format is ISO8601 without microseconds.
    """
    return dt.datetime.now(tz=dt.timezone.utc).strftime(fmt)