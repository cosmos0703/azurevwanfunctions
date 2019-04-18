import logging

import azure.functions as func
from azure.mgmt.storage import StorageManagementClient
from msrestazure.azure_active_directory import MSIAuthentication
from  azure.mgmt.network import NetworkManagementClient
from  urllib.request import urlopen, URLError
import json, itertools,unicodedata
from azure.common.credentials import ServicePrincipalCredentials
import urllib3,sys
urllib3.disable_warnings()
import fgt_api
from netaddr import IPNetwork
import ipaddress
import warnings,time,logging
#from systemd import journal
warnings.filterwarnings("ignore")
#from daemon import Daemon
import requests,ssl
from base64 import b64encode
from pprint import pprint

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


# with open('/home/plokesh/FortiOS/Azure_Details.txt') as az_fh:
#     for line in az_fh:
#         SUB_ID = line.split()[0]
#         location = line.split()[1]
#         RSG_HUB = line.split()[2]
#         vWAN_NAME = line.split()[3]
# az_fh.close()
# RSG = 'microsoft-network-' + location
# virtual_wan='/subscriptions/'+SUB_ID+'/resourceGroups/'+RSG_HUB+'/providers/Microsoft.Network/virtualWans/'+vWAN_NAME



storage_client = StorageManagementClient(credentials, SUB_ID)
network_client = NetworkManagementClient(credentials,SUB_ID)

def get_straccount():
    resource_group_params = {'location':location}

    for item in storage_client.storage_accounts.list():
        if 'config' in item.name:
            #print('The storage account with the vpnconfig is '), item.name
            str_acct=item.name
    return str_acct

#get the keys for the storage account
def list_keys():
    storage_keys = storage_client.storage_accounts.list_keys(
        RSG,
        get_straccount())
    storage_keys = {v.key_name: v.value for v in storage_keys.keys}
    #print('\tNew key 1: {}'.format(storage_keys['key1']))
    return storage_keys['key1']


def get_str_account_properties():
    storage_client = StorageManagementClient(credentials, SUB_ID)
    # Get storage account properties
    print('Get storage account properties')
    storage_account = storage_client.storage_accounts.get_properties(
        RSG, get_straccount())
    print (storage_account)
    print("\n\n")


def get_blob_sas_url():

    """
    Creates a service SAS definition with access to a blob container.
    """

    from azure.storage.blob import BlockBlobService,  ContainerPermissions
    #new file name
    blob_name='configfile'
    accountkey=list_keys()
    #from azure.keyvault import SecretId

    # create the blob sas definition template
    # the sas template uri for service sas definitions contains the storage entity url with the template token
    # this sample demonstrates constructing the template uri for a blob container, but a similar approach can
    # be used for all other storage service, i.e. File, Queue, Table

    # create a template sas token for the container
    service = BlockBlobService(account_name=get_straccount(),
                               account_key=accountkey)
    '''service.create_blob_from_text(container_name='vpnsiteconfig',
                                  blob_name=blob_name,
                                  text=u'test blob data'),
    blobs = list(service.list_blobs(container_name='vpnsiteconfig'))'''

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

def get_hubconnections():
    names=get_name_vpnsites()
    #for i in names:
    hub_connections=network_client.hub_virtual_network_connections.list(resource_group_name=RSG_HUB,
                                                                            virtual_hub_name='Hub1',
                                                    )
    for i in hub_connections:
        print (i)


def get_vpn_gateway(RSG):
    vpn_gateway=network_client.vpn_gateways.list_by_resource_group(RSG_HUB)
    for i in vpn_gateway:
        print (i)


def get_hub_info():
    names=get_name_vpnsites()
    #for i in names:
    hub_connections=network_client.virtual_hubs.get(resource_group_name=RSG_HUB,
                                                                            virtual_hub_name='Hub1',
                                                    )
    print (hub_connections)

def get_vwan():
    names=get_name_vpnsites()
    #for i in names:
    hub_connections=network_client.virtual_wans.list(resource_group_name=RSG_HUB,

                                                    )
    for i in hub_connections:
        print (i)
    print (hub_connections)

def getip_vpnsites():
    ip_sites=[]
    test=network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)
    #print '\n\nIP', test.ip_address, '\n\nAddress_Space',test.address_space, '\n\nname',test.name, '\n\nlocation', test.location,'\n\nvwan',test.virtual_wan
    for i in test:
            #print 'The IP address is', i.ip_address, 'and their address space is', i.address_space.address_prefixes, '\n\n'
            ip_sites.append(i.ip_address)
    return ip_sites

def getip_vpnsites_cosmos():
    ip_sites=[]
    test=network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)
    #print '\n\nIP', test.ip_address, '\n\nAddress_Space',test.address_space, '\n\nname',test.name, '\n\nlocation', test.location,'\n\nvwan',test.virtual_wan
    for i in test:
            #print 'The IP address is', i.ip_address, 'and their address space is', i.address_space.address_prefixes, '\n\n'
            ip_sites.append(i.ip_address)
    return ip_sites

def get_name_vpnsites():
    sites_name=[]
    test=network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)
    #print '\n\nIP', test.ip_address, '\n\nAddress_Space',test.address_space, '\n\nname',test.name, '\n\nlocation', test.location,'\n\nvwan',test.virtual_wan
    for i in test:
            #print 'The IP address is', i.ip_address, 'and their address space is', i.address_space.address_prefixes, '\n\n'
            sites_name.append(i.name)
    return sites_name

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
            sites_info.append({'Name':Name,
                               'Address_Space':Address_Space,
                               'IPAddress':IP_Address,
                               'vdom':'root'}
                              )
    return sites_info

def download_config():
    try:
        vpn_sites=network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)
        sas=get_blob_sas_url()
        site=[]
        for i in vpn_sites:
            siteid=i.id
            site.append(str(siteid))
        network_client.vpn_sites_configuration.download(resource_group_name=RSG_HUB,
                                                                virtual_wan_name=vWAN_NAME,
                                                                vpn_sites=site,
                                                                output_blob_sas_url=sas,
                                                                raw=True
                                                                )


        return sas
    except Exception:
        return 'No Sites Created'



def writetofile():
    filename="configuration.json"
    attempts = 0

    url=download_config()
    if url !='No Sites Created':
        while attempts <3:

            try:
                response = urlopen(url, timeout=5)
                content = response.read()
                f = open(filename, 'w')
                f.write(content)
                f.close()
                attempts += 1
            except URLError as e:

                print (type(e))
    else:
        return 'No Sites yet'


def readjson():
    write_output= writetofile()
    if write_output!='No Sites yet':

        vpn_sites = network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)

        #reading from the local file to get the appropriate values to pass it to the ipsec.py
        filename="configuration.json"
        json_data=open(filename).read()
        json_output= json.loads(json_data)
        out_list = []
        for i,j in enumerate(json_output):
            iter= len(j['vpnSiteConnections'])
        iterator = iter - 1


        site_name_addr = []
        site_addr_tmp = []
        for i, Site in enumerate(vpn_sites):
                site_name_addr.append({"Address_Space_Client":(Site.address_space.address_prefixes),
                                  "Name":str(Site.name)})
                site_addr_tmp.append(Site.address_space.address_prefixes)

        site_addr= []
        for sublist in site_addr_tmp:
            for i in sublist:
                site_addr.append(str(i))




        # Hub_Connections=network_client.hub_virtual_network_connections.list(resource_group_name='plokeshWANTestRG',virtual_hub_name='hub1')
        # for i in Hub_Connections:
        #     print i
        # connected_subnets=[]
        # for i,Site in enumerate(json_output):
        #     print Site
        #     connected_subnets.append(Site['vpnSiteConnections'][i]['hubConfiguration']['ConnectedSubnets'])


        for i,j in enumerate(json_output):
            try:
                out_list.append(
                    {
                        'Name':(str(j['vpnSiteConfiguration']['Name'])),
                        'IPAddress':(str(j['vpnSiteConfiguration']['IPAddress'])),
                        'Instance0': (str(j['vpnSiteConnections'][iterator]['gatewayConfiguration']['IpAddresses']['Instance0'])),
                        'Instance1': (str(j['vpnSiteConnections'][iterator]['gatewayConfiguration']['IpAddresses']['Instance1'])),
                        'PSK': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['PSK']),
                        'SADataSizeInKilobytes': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['IPsecParameters']['SADataSizeInKilobytes']),
                        'SALifeTimeInSeconds': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['IPsecParameters']['SALifeTimeInSeconds']),
                        'Region': str(j['vpnSiteConnections'][iterator]['hubConfiguration']['Region']),
                        'AddressSpace': str(j['vpnSiteConnections'][iterator]['hubConfiguration']['AddressSpace']),
                        'Connected_Subnets':(j['vpnSiteConnections'][iterator]['hubConfiguration']['ConnectedSubnets'])
                    })




            except IndexError:
                return out_list

        for list1_item in site_name_addr:
            for list1_item_key in list1_item.keys():
                for list2_item in out_list:
                    for list2_item_key in list2_item.keys():
                        if (list1_item_key in list2_item.keys()) and (
                                list1_item[list1_item_key] == list2_item[list2_item_key]):
                            list2_item['Address_Space_Client']=list1_item['Address_Space_Client']

        #out_list.append(temp_list)
        #print(out_list)

        return out_list,site_addr
    else:
        return 'Initial Site is not configured'

def func_readjson():
        config_url = download_config()
        gcontext = ssl.SSLContext()
        f = urlopen(config_url, context=gcontext)
        content = f.read()
        json_output = json.loads(content)
    

        vpn_sites = network_client.vpn_sites.list_by_resource_group(resource_group_name=RSG_HUB)

        out_list = []
        for i,j in enumerate(json_output):
            iter= len(j['vpnSiteConnections'])
        iterator = iter - 1


        site_name_addr = []
        site_addr_tmp = []
        for i, Site in enumerate(vpn_sites):
                site_name_addr.append({"Address_Space_Client":(Site.address_space.address_prefixes),
                                  "Name":str(Site.name)})
                site_addr_tmp.append(Site.address_space.address_prefixes)

        site_addr= []
        for sublist in site_addr_tmp:
            for i in sublist:
                site_addr.append(str(i))




        for i,j in enumerate(json_output):
            try:
                out_list.append(
                    {
                        'Name':(str(j['vpnSiteConfiguration']['Name'])),
                        'IPAddress':(str(j['vpnSiteConfiguration']['IPAddress'])),
                        'Instance0': (str(j['vpnSiteConnections'][iterator]['gatewayConfiguration']['IpAddresses']['Instance0'])),
                        'Instance1': (str(j['vpnSiteConnections'][iterator]['gatewayConfiguration']['IpAddresses']['Instance1'])),
                        'PSK': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['PSK']),
                        'SADataSizeInKilobytes': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['IPsecParameters']['SADataSizeInKilobytes']),
                        'SALifeTimeInSeconds': str(j['vpnSiteConnections'][iterator]['connectionConfiguration']['IPsecParameters']['SALifeTimeInSeconds']),
                        'Region': str(j['vpnSiteConnections'][iterator]['hubConfiguration']['Region']),
                        'AddressSpace': str(j['vpnSiteConnections'][iterator]['hubConfiguration']['AddressSpace']),
                        'Connected_Subnets':(j['vpnSiteConnections'][iterator]['hubConfiguration']['ConnectedSubnets'])
                    })




            except IndexError:
                return out_list, site_addr

        for list1_item in site_name_addr:
                for list1_item_key in list(list1_item):
                    #print (list1_item_key,list1_item[list1_item_key])
                    for list2_item in out_list:
                        for list2_item_key in list(list2_item):
                            #print (list1_item_key,list2_item_key, list1_item[list1_item_key],list2_item[list2_item_key])
                            if (list1_item_key in list(list2_item) and (
                                    list1_item[list1_item_key] == list2_item[list2_item_key])):
                                    #print ('I am here')
                                    list2_item['Address_Space_Client']=list1_item['Address_Space_Client']

        #out_list.append(temp_list)
        #print(out_list)

        return out_list,site_addr


def completed_connections():
    writetofile()
    readjson()
    completed_connections=[]
    try:
        filename="configuration.json"
        json_data=open(filename).read()
        json_output= json.loads(json_data)
        for i,j in enumerate(json_output):
            iter= len(j['vpnSiteConnections'])
        iterator = iter - 1

        for i, j in enumerate(json_output):
            completed_connections.append((str(j[u'vpnSiteConfiguration'][u'Name'])))
        return completed_connections
    except IOError or ValueError:
        return 'Initial Site is not configured. Please configure it and rerun the script'

def get_completed_connections():
    completed_connections= []
    config_url = download_config()
    gcontext = ssl.SSLContext()
    f = urlopen(config_url, context=gcontext)
    content = f.read()
    json_output = json.loads(content)
    for i, j in enumerate(json_output):
            completed_connections.append((str(j[u'vpnSiteConfiguration'][u'Name'])))
    return (completed_connections)



def main(req: func.HttpRequest) ->  str:
#def main(req: func.HttpRequest, vpnsites: func.Out)  :

    logging.info('Python HTTP trigger function processed a request. %s', req)
    ip = req.params.get('ip')
    t1, t2 = func_readjson()
    print (t1, t2)

    return('Test')

