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

def get_vpnsites():
    sites_info=[]
    test=network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)
    #print '\n\nIP', test.ip_address, '\n\nAddress_Space',test.address_space, '\n\nname',test.name, '\n\nlocation', test.location,'\n\nvwan',test.virtual_wan
    for i in test:
            str1=','.join(i.address_space.address_prefixes)
            Address_Space=unicodedata.normalize('NFKD',str1).encode('ascii','ignore')
            Name = unicodedata.normalize('NFKD', i.name).encode('ascii', 'ignore')
            IP_Address = unicodedata.normalize('NFKD', i.ip_address).encode('ascii', 'ignore')
            #print 'The IP address is', i.ip_address, 'and their address space is', i.address_space.address_prefixes, '\n\n'
            sites_info.append({'Name':Name.decode('utf-8'),
                               'Address_Space':Address_Space.decode('utf-8'),
                               'IPAddress':IP_Address.decode('utf-8'),
                               'vdom':'root'}
                              )
    return sites_info





def main(req: func.HttpRequest) -> str:
    logging.info('Python HTTP trigger function processed a request.')
    vpn_sites= str(get_vpnsites())
    print (vpn_sites)
    #vpn_sites = vpn_sites
    return(vpn_sites)
