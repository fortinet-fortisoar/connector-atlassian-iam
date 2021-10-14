""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import json
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('atlassian-iam')


class AtlassianIam():
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/') + '/scim/directory/{directoryId}'.format(
                directoryId=config.get('directoryId'))
        else:
            self.server_url = 'https://{0}'.format(self.server_url.strip('/')) + '/scim/directory/{directoryId}'.format(
                directoryId=config.get('directoryId'))
        self.access_token = config.get('access_token')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):
        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)
        logger.info('Request URL {0}'.format(url))
        headers = {"Authorization": "Bearer {0}".format(self.access_token), "Accept": "application/json",
                   "Content-Type": "application/json"}
        try:
            response = requests.request(method=method, url=url, params=params, data=data, json=json,
                                        headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                result = response.json()
                if result.get('error'):
                    raise ConnectorError('{}'.format(result.get('error').get('message')))
                if response.status_code == 204:
                    return {"Status": "Success", "Message": "Executed successfully"}
                return result
            elif messages_codes[response.status_code]:
                logger.error('{0}'.format(messages_codes[response.status_code]))
                raise ConnectorError('{0}'.format(messages_codes[response.status_code]))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['timeout_error']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def build_payload(params, input_params_list):
    result = {k: v for k, v in params.items() if v is not None and v != '' and k in input_params_list}
    return result


def check_health(config):
    try:
        logger.info("Invoking check_health")
        atlassianiam = AtlassianIam(config)
        response = atlassianiam.make_api_call(method='GET', endpoint='/Users')
        if response:
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def create_user(config, params):
    try:
        obj = AtlassianIam(config)
        result = build_payload(params, action_input_parameters.get('create_user'))
        payload = {}
        if result:
            if result.get('emails'):
                payload.update({"emails": [{"value": result.get('emails')}]})
            if result.get('custom_filter'):
                payload.update(result.get('custom_filter'))
                # payload.get('filters').update(result.get('custom_filter'))
                result.pop('custom_filter')
            payload.update(result)

        response = obj.make_api_call(method='POST', endpoint='/Users', data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_users(config, params):
    try:
        obj = AtlassianIam(config)

        response = obj.make_api_call(method='GET', endpoint='/Users')
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def update_user(config, params):
    try:
        obj = AtlassianIam(config)
        result = build_payload(params, action_input_parameters.get('update_user'))
        payload = {}
        if result:
            if result.get('emails'):
                payload.update({"emails": [{"value": result.get('emails')}]})
            if result.get('custom_filter'):
                payload.update(result.get('custom_filter'))
                # payload.get('filters').update(result.get('custom_filter'))
                result.pop('custom_filter')
            payload.update(result)

        response = obj.make_api_call(method='PUT', endpoint='/Users/{userId}'.format(userId=result.get('userId')),
                                     data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def deactivate_user(config, params):
    try:
        obj = AtlassianIam(config)
        result = build_payload(params, action_input_parameters.get('deactivate_user'))

        response = obj.make_api_call(method='DELETE', endpoint='/Users/{userId}'.format(userId=result.get('userId')))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


operations = {
    'create_user': create_user,
    'get_users': get_users,
    'update_user': update_user,
    'deactivate_user': deactivate_user

}
