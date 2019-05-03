import logging

import azure.functions as func
from azure.mgmt.storage import StorageManagementClient
from msrestazure.azure_active_directory import MSIAuthentication
from  azure.mgmt.network import NetworkManagementClient
import  urllib.request, urllib.error, requests
import json, itertools,unicodedata
from azure.common.credentials import ServicePrincipalCredentials



#Your Subscription 

TENANT_ID = 'xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx'

# Your Service Principal App ID
CLIENT = 'xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx'

# Your Service Principal Password
KEY = 'pwasswnklvnsdlkfnsdxxxxxxxx'

SUB_ID='xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx'
RSG_HUB = 'resourcegp'
vWAN_NAME = 'vWAN'
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


def get_straccount():
    #resource_group_params = {'location':location}

    for item in storage_client.storage_accounts.list():
        if 'config' in item.name:
            #print('The storage account with the vpnconfig is '), item.name
            str_acct=item.name
    return str_acct
def create_vpnsite(name,IPAddress,Address_Prefix):
    Address_Prefix1=Address_Prefix.split(',')
    test1=network_client.vpn_sites.create_or_update(resource_group_name=RSG_HUB,
                                                   vpn_site_name=name,
                                                   vpn_site_parameters={'ip_address':IPAddress,
                                                                        'address_space':{'address_prefixes':Address_Prefix1},
                                                                        'name':name,
                                                                        'location':location,
                                                                        'virtual_wan':{'id': virtual_wan}
                                                                        }
                                                   )
    return virtual_wan



def main(req: func.HttpRequest) -> func.HttpResponse:
    name = req.params.get('name')
    IPAddress = req.params.get('IPAddress')
    AddressPrefix = req.params.get('AddressPrefix')
    logging.info('Python HTTP trigger function processed a request.')
    #logging.info(name)
    vpnsites=create_vpnsite(name,IPAddress,AddressPrefix)
    return(vpnsites)


