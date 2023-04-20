"""
Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""
import base64
import requests
from connectors.cyops_utilities.builtins import create_file_from_string
from connectors.core.connector import get_logger, ConnectorError

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('taxii2-threat-intel-feed')


class TAXIIFeed(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'

        self.username = config.get('username')
        self.password = config.get('password')
        usr_pass = self.username + ":" + self.password
        usr_pass = usr_pass.encode()
        b64val = base64.b64encode(usr_pass)
        token = 'Basic {}'.format(b64val.decode("utf-8"))
        self.headers = {'Authorization': token}
        self.verify_ssl = config.get('verify_ssl')
        self.error_msg = {
            400: 'The parameters are invalid.',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            404: 'The requested resource was not found',
            409: 'The requested settings conflict with the current settings',
            410: 'Cannot find the specified object',
            422: 'Unable to process the request because system lockdown is currently disabled, or some file fingerprint lists or file names were already assigned',
            423: 'The resource to update is locked and cannot be updated',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'}

    def make_request(self, endpoint, headers=None, params=None, data=None, method='GET', api_info=None):
        try:
            headers = {**self.headers, **headers} if headers is not None and headers != '' else self.headers
            response = requests.request(method,
                                        endpoint,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params)
            if (response.status_code == 200 or response.status_code == 206) and api_info == 'api_root_info':
                return {'Content-Type': response.headers['Content-Type']}
            if response.status_code == 200 or response.status_code == 206:
                return response.json()
            if self.error_msg[response.status_code]:
                logger.error('{}'.format(response.content))
                raise ConnectorError('{}'.format(self.error_msg[response.status_code]))
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(self.error_msg['time_out']))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))

    def get_api_root_information(self, endpoint, **kwargs):
        api_root = self.make_request(endpoint=self.server_url + endpoint, headers={'Content-Type': 'application/json'})
        try:
            resp = api_root['api_roots'][0]
            return resp
        except:
            return self.server_url + 'taxii2'


def get_params(params):
    if params.get('collection_type'):
        params.pop('collection_type')
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_output_schema(config, params, **kwargs):
    if params.get('file_response'):
        return ({
            "md5": "",
            "sha1": "",
            "sha256": "",
            "filename": "",
            "content_length": "",
            "content_type": ""
        })
    else:
        return ({
            "id": "",
            "objects": [
                {
                    "created": "",
                    "description": "",
                    "id": "",
                    "labels": [
                    ],
                    "modified": "",
                    "name": "",
                    "object_marking_refs": [
                    ],
                    "pattern": "",
                    "type": "",
                    "valid_from": ""
                }
            ],
            "spec_version": "",
            "type": ""
        })


def get_collections(config, params, **kwargs):
    taxii = TAXIIFeed(config)
    api_root = taxii.get_api_root_information(endpoint='taxii2/', **kwargs)
    response_headers = taxii.make_request(endpoint=api_root, api_info='api_root_info')
    headers = {'Accept': response_headers['Content-Type']}
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    if params:
        response = taxii.make_request(endpoint=api_root + '/collections/' + str(params['collectionID']) + '/',
                                      headers=headers)
    else:
        response = taxii.make_request(endpoint=api_root + '/collections/', headers=headers)
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params, **kwargs):
    taxii = TAXIIFeed(config)
    api_root = taxii.get_api_root_information(endpoint='taxii2/', **kwargs)
    response_headers = taxii.make_request(endpoint=api_root, api_info='api_root_info')
    headers = {'Accept': response_headers['Content-Type']}
    params = get_params(params)
    wanted_keys = set(['added_after'])
    mode = params.get('output_mode')
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    try:
        response = taxii.make_request(endpoint=api_root + '/collections/' + str(params['collectionID']) + '/objects',
                                      params=query_params, headers=headers)
        response = response.get("objects", [])
        filtered_indicators = [indicator for indicator in response if indicator["type"] == "indicator"]
    except Exception as e:
        if mode == 'Create as Feed Records in FortiSOAR':
            return 'No records ingested'
        raise ConnectorError(str(e))
    if mode == 'Create as Feed Records in FortiSOAR':
        create_pb_id = params.get("create_pb_id")
        trigger_ingest_playbook(filtered_indicators, create_pb_id, parent_env=kwargs.get('env', {}), batch_size=1000,
                                dedup_field="pattern")
        return 'Successfully triggered playbooks to create feed records'
    seen = set()
    deduped_indicators = [x for x in filtered_indicators if [x["pattern"] not in seen, seen.add(x["pattern"])][0]]
    if mode == 'Save to File':
        return create_file_from_string(contents=deduped_indicators, filename=params.get('filename'))
    else:
        return deduped_indicators


def _check_health(config, **kwargs):
    try:
        taxii = TAXIIFeed(config)
        res = taxii.get_api_root_information(endpoint='taxii2/', **kwargs)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_collections': get_collections,
    'get_objects_by_collection_id': get_objects_by_collection_id,
    'get_output_schema': get_output_schema
}
