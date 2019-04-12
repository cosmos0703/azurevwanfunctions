import logging

import azure.functions as func
from azure.mgmt.storage import StorageManagementClient
from msrestazure.azure_active_directory import MSIAuthentication
from  azure.mgmt.network import NetworkManagementClient
import  urllib.request, urllib.error, requests
import json, itertools,unicodedata
from azure.common.credentials import ServicePrincipalCredentials




#Your Subscription 

TENANT_ID = '942b80cd-1b14-42a1-8dcf-4b21dece61ba'

# Your Service Principal App ID
CLIENT = '4d966119-56a0-4e35-9692-7edd1e90c686'

# Your Service Principal Password
KEY = 'GlfazBnkHuJYrE91wWgzYV+KdSOzc0Q3SEMIdkTPTRI='

SUB_ID='4f27b38c-ad3f-43d8-a9a3-01182e5e2f9a'
RSG_HUB = 'plokeshWANTestRG'
vWAN_NAME = 'plokeshvWAN'
location = 'uksouth'
RSG = 'microsoft-network-' + location
virtual_wan='/subscriptions/'+SUB_ID+'/resourceGroups/'+RSG_HUB+'/providers/Microsoft.Network/virtualWans/'+vWAN_NAME

#
credentials = ServicePrincipalCredentials(
    client_id=CLIENT,
    secret=KEY,
    tenant=TENANT_ID
)


storage_client = StorageManagementClient(credentials, SUB_ID)
network_client = NetworkManagementClient(credentials,SUB_ID)


#!/usr/bin/env python
import requests, sys
from pprint import pprint
from base64 import b64encode
import json
from pprint import pprint
import urllib3
urllib3.disable_warnings()

import warnings
warnings.filterwarnings("ignore")


class FGT(object):
    """
    Base class to provide GET/POST/PUT/DELETE request to FGT's APIs
        . Monitor API v2
        . CMDB API v2
    All requests share the same session (cookies and CSRF token)
    Only single session is maintained (login will restart existing session)
    """
    def __init__(self, host, https=True, api_key=None, auth_header=False):
        self.host = host
        s = "s" if https else ""
        self.url_prefix = "http" + s + "://" + self.host
        self.api_key = api_key
        self.auth_header=auth_header

    def update_csrf(self):
        # Retrieve server csrf and update session's headers
        for cookie in self.session.cookies:
            if cookie.name == "ccsrftoken":
                csrftoken = cookie.value[1:-1]  # token stored as a list
                self.session.headers.update({'X-CSRFTOKEN': csrftoken})

    def login(self, name="admin", key="", csrf=True):
        # Close existing session if any
        self.logout()

        # Start fresh new session
        self.session = requests.session()
        url = self.url_prefix + "/logincheck"
        try:
            res = self.session.post(
                url,
                #url + "?username=" + name + "&secretkey=" + key,
                #params={"username": name,
                #       "secretkey": key},
                #data="username=" + name + "&secretkey=" + key,
                data={"username": name,
                      "secretkey": key,
                      "ajax": 1
                      },
                verify=False
                )

        except requests.exceptions.RequestException as e:
            print(e)
            exit()

        if res.text.find("error") != -1:
            # Found some error in the response, consider login failed
            print("LOGIN FAILED")
            return False

        # Update session's csrftoken
        if csrf:
            self.update_csrf()
        return True

    def logout(self):
        # Logout of existing session if any
        if hasattr(self, "session"):
            url = self.url_prefix + "/logout"
            self.session.post(url)

    def set_vdom_cookie(self, vdom):
        res = self.get('/api/v2/monitor/web-ui/state')
        vdom_cookie = res.json()['results']['vdom_cookie_name']
        cookie_dict = {vdom_cookie: vdom}
        requests.utils.add_dict_to_cookiejar(self.session.cookies, cookie_dict)

    def get(self, url_postfix, **options):
        url = self.url_prefix + url_postfix
        params=options.get("params") or {}
        try:
            if self.api_key:
                if self.auth_header:
                    # Pass api key via header
                    res = requests.get(
                        url,
                        headers={'Authorization': 'Bearer ' + self.api_key},
                        params=params,
                        verify=False
                    )
                else:
                    # Pass api key via URL parameter
                    params.update({'access_token': self.api_key})
                    res = requests.get(
                        url,
                        params=params,
                        verify=False
                    )
            else:
                # Use login session otherwise
                res = self.session.get(
                    url,
                    params=params,
                )
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        #return res
        return self.check_response(res)

    def post(self, url_postfix, override=None, **options):
        url = self.url_prefix + url_postfix
        params=options.get("params") or {}
        data = repr(options.get("data")) if options.get("data") else None
        files=options.get("files")
        try:
            if self.api_key:
                if self.auth_header:
                    # Pass api key via header
                    res = requests.post(
                        url,
                        headers={'Authorization': 'Bearer ' + self.api_key},
                        params=params,
                        data=data,
                        files=files,
                        verify=False
                    )
                else:
                    # Pass api key via URL parameter
                    params.update({'access_token': self.api_key})
                    res = requests.post(
                        url,
                        params=params,
                        data=data,
                        files=files,
                        verify=False
                    )
            else:
                # Use login session otherwise
                if override:
                    self.session.headers.update({'X-HTTP-Method-Override': override})
                res = self.session.post(
                    url,
                    params=params,
                    data=data,
                    files=files
                )
        except requests.exceptions.RequestException as e:
            print(e)
            exit()

        # Restore original session
        if override:
            del self.session.headers['X-HTTP-Method-Override']
        #return res
        return self.check_response(res)

    def put(self, url_postfix, **options):
        url = self.url_prefix + url_postfix
        params=options.get("params") or {}
        data = repr(options.get("data")) if options.get("data") else None
        try:
            if self.api_key:
                if self.auth_header:
                    # Pass api key via header
                    res = requests.put(
                        url,
                        headers={'Authorization': 'Bearer ' + self.api_key},
                        params=params,
                        data=data,
                        verify=False
                    )
                else:
                    # Pass api key via URL parameter
                    params.update({'access_token': self.api_key})
                    res = requests.put(
                        url,
                        params=params,
                        data=data,
                        verify=False
                    )
            else:
                # Use login session otherwise
                res = self.session.put(
                    url,
                    params=params,
                    data=data,
                )
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        #return res
        return self.check_response(res)

    def delete(self, url_postfix, **options):
        url = self.url_prefix + url_postfix
        params=options.get("params") or {}
        try:
            if self.api_key:
                if self.auth_header:
                    # Pass api key via header
                    res = requests.delete(
                        url,
                        headers={'Authorization': 'Bearer ' + self.api_key},
                        params=params,
                        verify=False
                    )
                else:
                    # Pass api key via URL parameter
                    params.update({'access_token': self.api_key})
                    res = requests.delete(
                        url,
                        params=params,
                        verify=False
                    )
            else:
                # Use login session otherwise
                res = self.session.delete(
                    url,
                    params=params,
                )
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        #return res
        return self.check_response(res)

    def get_etag(self, response):
        if not hasattr(response, "headers"):
            # Response does not have headers
            return None

        if not "etag" in response.headers:
            # No etag in response headers
            return None

        # etag in response headers
        return response.headers['etag']

    def check_response(self, response, verbose=False):
        # if verbose:
        #     print('{0} {1}'.format(response.request.method,
        #                            response.request.url))

        # Check response status, content and compare with original request
        if response.status_code == 200:
            # Success code, now check json response
            #print response.status_code
            try:
                # Retrieve json data
                res = response.json()
            except:
                if verbose:
                    print('Fail invalid JSON response')
                    print(response.headers)
                return False

            else:
                # Check if json data is empty
                if not res:
                    if verbose:
                        print("JSON data is empty")
                        print(response.text)
                    return False

                # Check status
                if 'status' in res:
                    if res['status'] != 'success':
                        if verbose:
                            print('JSON error {0}\n{1}'.format(res['error'],
                                                               res))
                        return False

                # Check http_status if any
                if 'http_status' in res:
                    if res['http_status'] != 200:
                        if verbose:
                            print('JSON error {0}\n{1}'.format(res['error'],
                                                               res))
                        return False

                # Check http method
                if 'http_method' in res:
                    if res['http_method'] != response.request.method:
                        if verbose:
                            print('Incorrect METHOD request {0},\
                                  response {1}'.format(response.request.method,
                                                       res['http_method']))
                        return False

                # Check results
                if 'results' in res:
                    print (res['results'])
                    if not res['results']:
                        if verbose:
                            print('Results is empty')
                        return False

                # Check vdom

                # Check path

                # Check name

                # Check action

                # All pass
                if verbose:
                    #print ('Succeed status: {0}'.format(response.status_code))
                    # Print etag if any
                    #etag = self.get_etag(response)
                    #pprint(etag)
                    pprint(res)
                    #print response.headers
                return res
        else:
            try:
                # Retrieve json data
                res = response.json()
            except:
                pass
                if verbose:
                    print ('Fail status: {0}'.format(response.status_code))
            else:
                pass
                if verbose:
                    print ('Fail status: {0}'.format(response.status_code))
                    #print response.json()
            finally:
                if verbose:
                    print (response.text)
                return False

def main(req: func.HttpRequest) ->  str:
#def main(req: func.HttpRequest, vpnsites: func.Out)  :

    logging.info('Python HTTP trigger function processed a request. %s', req)
    ip = req.params.get('ip')
    #ip_vpnsites = str(getip_vpnsites())
    #ip_vpnsites_uni = str(ip_vpnsites, unicodedata)
    #return(ip_vpnsites)
    #ip_vpnsites = str(getip_vpnsites())
    #vpnsites.set(ip_vpnsites)

    # Initilize fgt connection
    fgt=FGT(ip)

    # Hard coded vdom value for all requests
    vdom = "root"

    # Authenticate using login session
    fgt.login("plokesh", "Fortinet1@34")

    # Create object
    fgt.post('/api/v2/cmdb/firewall/address',
             params={'vdom': vdom},
             data={'json': {'name': "attacker2",
                            "subnet": "1.1.1.4 255.255.255.255"}},
             verbose=True)

    # Always logout after testing is done
    fgt.logout()
    return('Test')

