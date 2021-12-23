import base64
import tempfile
from datetime import datetime

import requests
from connectors.cyops_utilities.builtins import create_file_from_string

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('taxii2-threat-intel-feed')


class TaxiiFeed(object):
    def __init__(self, config):
        self.crt = None
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        if 'Basic Authentication' in config.get('auth_type'):
            self.username = config.get('username')
            self.password = config.get('password')
            usr_pass = self.username + ":" + self.password
            usr_pass = usr_pass.encode()
            b64val = base64.b64encode(usr_pass)
            token = 'Basic {}'.format(b64val.decode("utf-8"))
            self.headers = {'Authorization': token}
        else:
            self.client_certificate = config.get('client_certificate')
            self.key_certificate = config.get('key_certificate')
            client_certificate_list = self.client_certificate.split('-----')
            # replace spaces with newline characters
            client_certificate_fixed = '-----'.join(
                client_certificate_list[:2] + [client_certificate_list[2].replace(' ', '\n')] + client_certificate_list[
                                                                                                3:])
            crt_file = tempfile.NamedTemporaryFile(delete=False)
            crt_file.write(client_certificate_fixed.encode())
            crt_file.flush()

            key_certificate_list = self.key_certificate.split('-----')
            # replace spaces with newline characters
            key_certificate_fixed = '-----'.join(
                key_certificate_list[:2] + [key_certificate_list[2].replace(' ', '\n')] + key_certificate_list[3:])
            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(key_certificate_fixed.encode())
            key_file.flush()
            self.crt = (crt_file.name, key_file.name)
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
                                        cert=self.crt,
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

    def get_api_root_information(self, endpoint):
        api_root = self.make_request(endpoint=self.server_url + endpoint, headers={'Content-Type': 'application/json'})
        return api_root['api_roots'][0]


def get_params(params):
    if params.get('collection_type'):
        params.pop('collection_type')
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_output_schema(config, params, *args, **kwargs):
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


def get_collections(config, params):
    taxii = TaxiiFeed(config)
    api_root = taxii.get_api_root_information(endpoint='taxii/')
    response_headers = taxii.make_request(endpoint=api_root, api_info='api_root_info')
    headers = {'Accept': response_headers['Content-Type']}
    if 'Collection ID' in params.get('collection_type'):
        response = taxii.make_request(endpoint=api_root + 'collections/' + str(params['collectionID']) + '/',
                                      headers=headers)
    else:
        if params.get('limit') is not None or params.get('limit') != '':
            headers.update(
                {'Range': 'items {0}-{1}'.format(str(params.get('offset')), str(params.get('limit')))})
        response = taxii.make_request(endpoint=api_root + 'collections/', headers=headers)
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params):
    taxii = TaxiiFeed(config)
    api_root = taxii.get_api_root_information(endpoint='taxii/')
    response_headers = taxii.make_request(endpoint=api_root, api_info='api_root_info')
    headers = {'Accept': response_headers['Content-Type']}
    created_after = params.get('added_after')
    if created_after and type(created_after) == int:
        # convert to epoch
        created_after = datetime.fromtimestamp(created_after).strftime('%Y-%m-%dT%H:%M:%SZ')
    if not created_after or created_after == '':
        created_after = '1970-01-01T00:00:00.000Z'
    if params.get('limit') is None or params.get('limit') == '':
        server_url = config.get('server_url')
        if not server_url.startswith('https://'):
            server_url = 'https://' + server_url
        if not server_url.endswith('/'):
            server_url += '/'
        username = config.get('username')
        password = config.get('password')
        if ' version=2.0' in headers['Accept']:
            from taxii2client.v20 import Collection, as_pages
        else:
            from taxii2client.v21 import Collection, as_pages
        collection = Collection(
            api_root + 'collections/' + str(params.get('collectionID')) + '/',
            user=username, password=password)
        response = []
        for bundle in as_pages(collection.get_objects, added_after=created_after, start=params.get('offset'),
                               per_request=1000):
            if bundle.get("objects"):
                response.extend(bundle["objects"])
            else:
                break
    else:
        params = get_params(params)
        wanted_keys = set(['added_after'])
        query_params = {k: params[k] for k in params.keys() & wanted_keys}
        query_params.update({'match[type]': 'indicator'})
        headers.update({'Range': 'items {0}-{1}'.format(str(params.get('offset')), str(params.get('limit')))})
        response = taxii.make_request(
            endpoint=api_root + 'collections/' + str(params.get('collectionID')) + '/objects/',
            params=query_params, headers=headers)
        response = response.get("objects", [])
    try:
        # dedup
        filtered_indicators = [indicator for indicator in response if indicator["type"] == "indicator"]
        seen = set()
        deduped_indicators = [x for x in filtered_indicators if
                              [(x["type"], x["pattern"]) not in seen, seen.add((x["type"], x["pattern"]))][0]]
    except Exception as e:
        logger.exception("Import Failed")
        raise ConnectorError('Ingestion Failed with error: ' + str(e))
    mode = params.get('output_mode')
    if mode == 'Save to File':
        return create_file_from_string(contents=deduped_indicators, filename=params.get('filename'))
    else:
        return deduped_indicators


def _check_health(config):
    try:
        taxii = TaxiiFeed(config)
        res = taxii.get_api_root_information(endpoint='taxii/')
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
