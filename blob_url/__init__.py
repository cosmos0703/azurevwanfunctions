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

#get the keys for the storage account
def list_keys():
    storage_keys = storage_client.storage_accounts.list_keys(
        RSG,
        get_straccount())
    storage_keys = {v.key_name: v.value for v in storage_keys.keys}
    #print('\tNew key 1: {}'.format(storage_keys['key1']))
    return storage_keys['key1']

def get_straccount():
    #resource_group_params = {'location':location}

    for item in storage_client.storage_accounts.list():
        if 'config' in item.name:
            #print('The storage account with the vpnconfig is '), item.name
            str_acct=item.name
    return str_acct


def get_blob_sas_url():

    from azure.storage.blob import BlockBlobService,  ContainerPermissions
    #new file name
    blob_name='configfile'
    accountkey=list_keys()

    # create a template sas token for the container
    service = BlockBlobService(account_name=get_straccount(),
                               account_key=accountkey)

    permissions = ContainerPermissions(read=True, write=True, delete=True, list=True)
    temp_token1=service.generate_blob_shared_access_signature(container_name='vpnsiteconfig',
                                                                    blob_name=blob_name,
                                                                    permission=permissions,
                                                                    expiry='2020-01-01')
    blob_sas_template_uri=service.make_blob_url(container_name='vpnsiteconfig',
                                                       blob_name=blob_name,
                                                       protocol='https',
                                                       sas_token=temp_token1)

    test=blob_sas_template_uri

    return test


def main(req: func.HttpRequest) -> str:
    logging.info('Python HTTP trigger function processed a request.')
    blob_url=get_blob_sas_url()
    return(blob_url)
