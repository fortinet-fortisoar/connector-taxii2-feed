import base64
import tempfile
import time

import requests
from connectors.cyops_utilities.builtins import create_file_from_string, extract_artifacts
from taxii2client.v20 import Collection, as_pages
from taxii2client.v21 import Collection, as_pages

from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('taxii2_feed')


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
                client_certificate_list[:2] + [client_certificate_list[2].replace(' ', '\n')] + client_certificate_list[3:])
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


def get_epoch(_date):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in _date else '%Y-%m-%dT%H:%M:%SZ'
        return int(time.mktime(time.strptime(_date, pattern)))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def max_age(params, ioc):
    if params.get("expiry") is not None and params.get("expiry") != '':
        return get_epoch(ioc["valid_from"]) + (params.get("expiry") * 86400)
    elif "valid_until" in ioc.keys():
        return get_epoch(ioc["valid_until"])
    else:
        return None


def tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params):
    if params.get('tlp') == 'RED':
        return TLP_RED
    if params.get('tlp') == 'AMBER':
        return TLP_AMBER
    if params.get('tlp') == 'GREEN':
        return TLP_GREEN
    if params.get('tlp') == 'WHITE':
        return TLP_WHITE


def stix_spec(ioc, _version, params):
    return {
        "type": "indicator",
        "spec_version": _version,
        "created": get_epoch(ioc["created"]),
        "modified": get_epoch(ioc["modified"]),
        "recordTags": ioc["indicator_types"] if "indicator_types" in ioc else ioc['labels'],
        "name": ioc["name"],
        "description": ioc["description"] if "description" in ioc else None,
        "indicators": extract_artifacts(data=ioc["pattern"]),
        "valid_from": get_epoch(ioc["valid_from"]),
        "confidence": params.get("confidence") if params.get("confidence") is not None and params.get(
            "confidence") != '' else 0,
        "reputation": REPUTATION_MAP.get(params.get("reputation")) if params.get(
            'Suspicious') is not None and params.get("Suspicious") != '' else REPUTATION_MAP.get("Suspicious"),
        "tlp": TLP_MAP.get(params.get("tlp")) if params.get("tlp") is not None and params.get(
            "tlp") != '' else TLP_MAP.get("White"),
        "valid_until": max_age(params, ioc)
    }


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
    response = []
    api_root = taxii.get_api_root_information(endpoint='taxii/')
    response_headers = taxii.make_request(endpoint=api_root, api_info='api_root_info')
    headers = {'Accept': response_headers['Content-Type']}
    if params.get('limit') is None or params.get('limit') == '':
        server_url = config.get('server_url')
        if not server_url.startswith('https://'):
            server_url = 'https://' + server_url
        if not server_url.endswith('/'):
            server_url += '/'
        username = config.get('username')
        password = config.get('password')
        collection = Collection(
            api_root + 'collections/' + str(params.get('collectionID')) + '/',
            user=username, password=password)
        for bundle in as_pages(collection.get_objects, added_after=params.get('added_after') if (
                params.get('added_after') is not None and params.get(
            'added_after') != '') else '1970-01-01T00:00:00.000Z', start=params.get('offset'),
                               per_request=1000):
            if 'objects' not in bundle.keys():
                response.append(bundle)
                break
            for ioc in bundle["objects"]:
                if ioc["type"] == "indicator" and "spec_version" in ioc.keys():
                    response.append(stix_spec(ioc, "2.1", params))
                elif ioc["type"] == "indicator" and "spec_version" not in ioc.keys():
                    response.append(stix_spec(ioc, "2.0", params))
    else:
        params = get_params(params)
        wanted_keys = set(['added_after'])
        query_params = {k: params[k] for k in params.keys() & wanted_keys}
        query_params.update({'match[type]': 'indicator'})
        headers.update({'Range': 'items {0}-{1}'.format(str(params.get('offset')), str(params.get('limit')))})
        res = taxii.make_request(
            endpoint=api_root + 'collections/' + str(params.get('collectionID')) + '/objects/',
            params=query_params, headers=headers)
        for ioc in res["objects"]:
            if ioc["type"] == "indicator" and "spec_version" in ioc.keys():
                response.append(stix_spec(ioc, "2.1", params))
            elif ioc["type"] == "indicator" and "spec_version" not in ioc.keys():
                response.append(stix_spec(ioc, "2.0", params))
    if params.get('file_response'):
        return create_file_from_string(contents=response, filename=params.get('filename'))
    else:
        return response


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
