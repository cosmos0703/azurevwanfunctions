import logging

import azure.functions as func
from azure.mgmt.storage import StorageManagementClient
from msrestazure.azure_active_directory import MSIAuthentication
from  azure.mgmt.network import NetworkManagementClient
import  urllib.request, urllib.error, requests
import json, itertools,unicodedata
from azure.common.credentials import ServicePrincipalCredentials
import urllib3,sys
urllib3.disable_warnings()
import fgt_api
import sasurl 
from netaddr import IPNetwork
import ipaddress
import warnings,time,logging,ssl
#from systemd import journal
warnings.filterwarnings("ignore")
#from daemon import Daemon
from base64 import b64encode
from pprint import pprint
urllib3.disable_warnings()
from  urllib.request import urlopen, URLError
import get_ip_vpnsites, get_vpnsites, create_vpnsite, config_file






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




def phase1interface(name,remote_gw,psk,keylife,vdom):
    #creating a phase1 tunnel configuration

    fgt.post('/api/v2/cmdb/vpn.ipsec/phase1-interface',
            params = {'vdom': vdom},
            data={'json':{
                            "name": name,
                            "interface": "port1",
                            "ip-version": "4",
                            "ike-version": "2",
                            "remote-gw": remote_gw,
                            "mode": "aggressive",
                            "proposal": 'aes256-sha256',
                            "psksecret": psk,
                            "keylife" : keylife,
                            "dhgrp": '2'
                             }})
    interfacename=name
    return interfacename

def phase2interface(phase1name,keylife, vdom):
    #creating a phase1 tunnel configuration
    phase2name=str(phase1name)+ "-ph2"
    fgt.post('/api/v2/cmdb/vpn.ipsec/phase2-interface',
            params = {'vdom': vdom},
            data={'json':{
                            "name": phase2name,
                            "phase1name": phase1name,
                            "src-addr-type": "subnet",
                            "dst-addr-type": "subnet",
                            "src-name"  :'0.0.0.0/0',
                            "dst-name"  :'0.0.0.0/0',
                            "dhgrp": '2',
                            "proposal": 'aes256-sha256',
                            "keylifekbs": keylife
                             }})

def remote_addressobject(name,CIDR,vdom):
    #Create remote address objects
    addresses=[]

    for i,j in enumerate(CIDR):
        name=name+'_'+str(i)
        fgt.post('/api/v2/cmdb/firewall/address',
             params={'vdom': vdom},
             data={'json': {'name': name,
                            "subnet": str(j),
                            "allow-routing": "enable"
                            }},
             verbose=False)
        addresses.append(name)
        name = name[:-2]

    return addresses

def put_remote_addressobject(name,CIDR,vdom):
    #Create remote address objects
    addresses=[]
    #grpname = str(name) + "grp"
    for i,j in enumerate(CIDR):
        name=name+'_'+str(i)
        res=fgt.put('/api/v2/cmdb/firewall/address'+name,
             params={'vdom': vdom},
             data={'json': {'name': name,
                            "subnet": str(j),
                            "allow-routing": "enable"
                            }},
             verbose=False)
        print ('This is res', res)
        addresses.append(name)
        name = name[:-2]

    return addresses

def addressgroup(name,addressobjects,vdom):
    
    grpname=name
    fgt.post('/api/v2/cmdb/firewall/addrgrp',
            params={'vdom':vdom},
             data={'name': grpname,
                            'member':[addressobjects],
                                     'allow-routing':'enable'})
    return grpname

def local_addressobject(name,CIDR,vdom):
    #Create local address objects
    fgt.post('/api/v2/cmdb/firewall/address',
             params={'vdom': vdom},
             data={'json': {'name': name,
                            "subnet": CIDR,
                            "allow-routing": "enable"
                            }},
             verbose=False)

    return name

def put_local_addressobject(name,CIDR,vdom):
    #Create local address objects
    fgt.put('/api/v2/cmdb/firewall/address',
             params={'vdom': vdom},
             data={'json': {'name': name,
                            "subnet": CIDR,
                            "allow-routing": "enable"
                            }},
             verbose=False)

    return name


def outgoing_firewallpolicy(fromaddr,toaddr,srcint,dstint,vdom):
        #print fromaddr,toaddr,srcint,dstint
        #for j in toaddr:
        fgt.post('/api/v2/cmdb/firewall/policy',
            params = {'vdom': vdom},
            data = {'json': {'policyid': 0,
                     'srcintf': [{'name': srcint}],
                     'srcaddr': [{'name': fromaddr}],
                     'dstintf': [{'name': dstint}],
                     'dstaddr': [{'name': toaddr}],
                     'service': [{'name': "ALL"}],
                     'schedule': "always",
                     'action': "accept",
                     'logtraffic': "all"}})


def incoming_firewallpolicy(fromaddr,toaddr,srcint,dstint,vdom):
    #for i in fromaddr:
        fgt.post('/api/v2/cmdb/firewall/policy',
            params = {'vdom': vdom},
            data = {'json': {'policyid': 0,
                     'srcintf': [{'name': srcint}],
                     'srcaddr': [{'name': fromaddr}],
                     'dstintf': [{'name': dstint}],
                     'dstaddr': [{'name': toaddr}],
                     'service': [{'name': "ALL"}],
                     'schedule': "always",
                     'action': "accept",
                     'logtraffic': "all"}})


def staticroute(remoteaddr,interface,vdom):
    #Create the static route for VPN
    for i in remoteaddr:
        fgt.post('/api/v2/cmdb/router/static',
             params={'vdom': vdom},
             data={'json': {"device": interface,
                            "seq-num": 0,
                            "dstaddr": i}},
             verbose=True)

def backuproute(remoteaddr,interface,vdom):
    #Create the static route for VPN
    for i in remoteaddr:
        fgt.post('/api/v2/cmdb/router/static',
             params={'vdom': vdom},
             data={'json': {"device": interface,
                            "seq-num": 0,
                            "priority": 5,
                            "dstaddr": i}},
             verbose=True)

def addressobjects_lookup(vdom):

    address_objects_tmp=[]
    address_objects=[]
    addressobjects_lookup = fgt.get('/api/v2/cmdb/firewall/address',
                                    params={'vdom': vdom})
    # print addressobjects_lookup['results']
    for i in addressobjects_lookup['results']:
        if i['type'] != 'iprange':
            temp = i['subnet'].split()
            # print temp
            temp1 = '/'.join(temp)
            # print temp1
            p_ip_net = IPNetwork(temp1)
            net1 = ipaddress.ip_network(p_ip_net, strict=False)
            address_objects.append(str((net1.with_prefixlen)))
    fgt.logout
    return address_objects

def route_lookup(list1,vdom):
    policy_variables=[]
    for x, j in enumerate(list1):
        route_lookup = fgt.get('/api/v2/monitor//router/lookup',
                               params={'vdom': vdom, 'destination': j.split('/')[0]})
        # print route_lookup
        local_interface = route_lookup['results']['interface']
        # print local_interface
        local_interfaces.append(local_interface)
        localaddr = (local_addressobject('local' + site_name + str(x), j,vdom))
        # print 'The local addresses are', localaddr
        policy_variables.append({'Interface': str(local_interface),
                                 'local_Address': localaddr})
    return policy_variables

def find_remote_addresses(list1,list2):
    return [value for value in list1 if value not in list2]

def Get_Remote_Sites(url):
    
    Remote_Sites =[]
    config_url = url
    gcontext = ssl.SSLContext()
    f = urlopen(config_url,context=gcontext)
    for i in  f:
            try:
                Remote_Sites.append({'IPAddress':i.split()[2].decode('utf-8'),
                                 'Address_Space':i.split()[3].decode('utf-8'),
                                 'Name':i.split()[1].decode('utf-8'),
                                    'vdom':i.split()[6].decode('utf-8'),
                                     'user':i.split()[4].decode('utf-8'),
                                     'password':i.split()[5].decode('utf-8')})

            except IndexError:
                continue
    print (Remote_Sites)
    Remote_Sites = str(Remote_Sites)
    return Remote_Sites




def get_existing_vpn_names(Try):
    existing_vpn_names=[]
    try:
        for i in Try['results']: 
            existing_vpn_names.append(str((i['name'])))

    except TypeError:
            print ('No VPNs exist on the Firewall')
    #Try1= str(existing_vpn_names)
    return str(existing_vpn_names)

def main(req: func.HttpRequest) ->  str:
#def main(req: func.HttpRequest, vpnsites: func.Out)  :

    logging.info('Python HTTP trigger function processed a request. %s', req)
    ip = req.params.get('ip')

    # # Initilize fgt connection
    fgt = fgt_api.FGT(ip)

    # # Hard coded vdom value for all requests
    # vdom = "root"

    # Authenticate using login session
    fgt.login("plokesh", "Fortinet1@34")



    # # # Hard coded vdom value for all requests
    vdom = "root"

    Remote_Sites = Get_Remote_Sites('https://plokeshvwan.blob.core.windows.net/vpnsites/Remote_Sites.txt') 

    

    #Try = str(addressobjects_lookup(vdom))


    #Remote_Sites = str(Remote_Sites).decode('utf-8')
    
    
    Try = (fgt.get('/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                           params={'vdom':vdom}))

    existing_vpn_names = get_existing_vpn_names(Try)

    existig_sites = get_ip_vpnsites.getip_vpnsites()
    #print (existig_sites)
    vpn_completed_sites = sasurl.get_completed_connections()
    #print (str(vpn_completed_sites))

    if vpn_completed_sites=='Initial Site is not configured. Please configure it and rerun the script':
            print (vpn_completed_sites)
            exit()
    else:
            print ('The completed connections are', vpn_completed_sites)
            #journal.send('The completed connections are' + vpn_completed_sites)




    #fgt.logout()
    return(str(vpn_completed_sites))





