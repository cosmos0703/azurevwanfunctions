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




#   def phase1interface(name,remote_gw,psk,keylife,vdom):
#     #creating a phase1 tunnel configuration

#     fgt.post('/api/v2/cmdb/vpn.ipsec/phase1-interface',
#             params = {'vdom': vdom},
#             data={'json':{
#                             "name": name,
#                             "interface": "port1",
#                             "ip-version": "4",
#                             "ike-version": "2",
#                             "remote-gw": remote_gw,
#                             "mode": "aggressive",
#                             "proposal": 'aes256-sha256',
#                             "psksecret": psk,
#                             "keylife" : keylife,
#                             "dhgrp": '2'
#                              }})
#     interfacename=name
#     return interfacename

# def phase2interface(phase1name,keylife, vdom):
#     #creating a phase1 tunnel configuration
#     phase2name=str(phase1name)+ "-ph2"
#     fgt.post('/api/v2/cmdb/vpn.ipsec/phase2-interface',
#             params = {'vdom': vdom},
#             data={'json':{
#                             "name": phase2name,
#                             "phase1name": phase1name,
#                             "src-addr-type": "subnet",
#                             "dst-addr-type": "subnet",
#                             "src-name"  :'0.0.0.0/0',
#                             "dst-name"  :'0.0.0.0/0',
#                             "dhgrp": '2',
#                             "proposal": 'aes256-sha256',
#                             "keylifekbs": keylife
#                              }})

# def remote_addressobject(name,CIDR,vdom):
#     #Create remote address objects
#     addresses=[]

#     for i,j in enumerate(CIDR):
#         name=name+'_'+str(i)
#         fgt.post('/api/v2/cmdb/firewall/address',
#              params={'vdom': vdom},
#              data={'json': {'name': name,
#                             "subnet": str(j),
#                             "allow-routing": "enable"
#                             }},
#              verbose=False)
#         addresses.append(name)
#         name = name[:-2]

#     return addresses

# def put_remote_addressobject(name,CIDR,vdom):
#     #Create remote address objects
#     addresses=[]
#     #grpname = str(name) + "grp"
#     for i,j in enumerate(CIDR):
#         name=name+'_'+str(i)
#         res=fgt.put('/api/v2/cmdb/firewall/address'+name,
#              params={'vdom': vdom},
#              data={'json': {'name': name,
#                             "subnet": str(j),
#                             "allow-routing": "enable"
#                             }},
#              verbose=False)
#         print ('This is res', res)
#         addresses.append(name)
#         name = name[:-2]

#     return addresses

# def addressgroup(name,addressobjects,vdom):
    
#     grpname=name
#     fgt.post('/api/v2/cmdb/firewall/addrgrp',
#             params={'vdom':vdom},
#              data={'name': grpname,
#                             'member':[addressobjects],
#                                      'allow-routing':'enable'})
#     return grpname

# def local_addressobject(name,CIDR,vdom):
#     #Create local address objects
#     fgt.post('/api/v2/cmdb/firewall/address',
#              params={'vdom': vdom},
#              data={'json': {'name': name,
#                             "subnet": CIDR,
#                             "allow-routing": "enable"
#                             }},
#              verbose=False)

#     return name

# def put_local_addressobject(name,CIDR,vdom):
#     #Create local address objects
#     fgt.put('/api/v2/cmdb/firewall/address',
#              params={'vdom': vdom},
#              data={'json': {'name': name,
#                             "subnet": CIDR,
#                             "allow-routing": "enable"
#                             }},
#              verbose=False)

#     return name


# def outgoing_firewallpolicy(fromaddr,toaddr,srcint,dstint,vdom):
#         #print fromaddr,toaddr,srcint,dstint
#         #for j in toaddr:
#         fgt.post('/api/v2/cmdb/firewall/policy',
#             params = {'vdom': vdom},
#             data = {'json': {'policyid': 0,
#                      'srcintf': [{'name': srcint}],
#                      'srcaddr': [{'name': fromaddr}],
#                      'dstintf': [{'name': dstint}],
#                      'dstaddr': [{'name': toaddr}],
#                      'service': [{'name': "ALL"}],
#                      'schedule': "always",
#                      'action': "accept",
#                      'logtraffic': "all"}})


# def incoming_firewallpolicy(fromaddr,toaddr,srcint,dstint,vdom):
#     #for i in fromaddr:
#         fgt.post('/api/v2/cmdb/firewall/policy',
#             params = {'vdom': vdom},
#             data = {'json': {'policyid': 0,
#                      'srcintf': [{'name': srcint}],
#                      'srcaddr': [{'name': fromaddr}],
#                      'dstintf': [{'name': dstint}],
#                      'dstaddr': [{'name': toaddr}],
#                      'service': [{'name': "ALL"}],
#                      'schedule': "always",
#                      'action': "accept",
#                      'logtraffic': "all"}})


# def staticroute(remoteaddr,interface,vdom):
#     #Create the static route for VPN
#     for i in remoteaddr:
#         fgt.post('/api/v2/cmdb/router/static',
#              params={'vdom': vdom},
#              data={'json': {"device": interface,
#                             "seq-num": 0,
#                             "dstaddr": i}},
#              verbose=True)

# def backuproute(remoteaddr,interface,vdom):
#     #Create the static route for VPN
#     for i in remoteaddr:
#         fgt.post('/api/v2/cmdb/router/static',
#              params={'vdom': vdom},
#              data={'json': {"device": interface,
#                             "seq-num": 0,
#                             "priority": 5,
#                             "dstaddr": i}},
#              verbose=True)

# def addressobjects_lookup(vdom):

#     address_objects_tmp=[]
#     address_objects=[]
#     addressobjects_lookup = fgt.get('/api/v2/cmdb/firewall/address',
#                                     params={'vdom': vdom})
#     # print addressobjects_lookup['results']
#     for i in addressobjects_lookup['results']:
#         if i['type'] != 'iprange':
#             temp = i['subnet'].split()
#             # print temp
#             temp1 = '/'.join(temp)
#             # print temp1
#             p_ip_net = IPNetwork(temp1)
#             net1 = ipaddress.ip_network(p_ip_net, strict=False)
#             address_objects.append(str((net1.with_prefixlen)))
#     fgt.logout
#     return address_objects

# def route_lookup(list1,vdom):
#     policy_variables=[]
#     for x, j in enumerate(list1):
#         route_lookup = fgt.get('/api/v2/monitor//router/lookup',
#                                params={'vdom': vdom, 'destination': j.split('/')[0]})
#         # print route_lookup
#         local_interface = route_lookup['results']['interface']
#         # print local_interface
#         local_interfaces.append(local_interface)
#         localaddr = (local_addressobject('local' + site_name + str(x), j,vdom))
#         # print 'The local addresses are', localaddr
#         policy_variables.append({'Interface': str(local_interface),
#                                  'local_Address': localaddr})
#     return policy_variables

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
    #print (Remote_Sites)
    #Remote_Sites = Remote_Sites
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
    local_interfaces=[]

    Remote_Sites = Get_Remote_Sites('https://plokeshvwan.blob.core.windows.net/vpnsites/Remote_Sites.txt') 


    for i in Remote_Sites:
            sasurl.create_vpnsite(i['Name'], i['IPAddress'], i['Address_Space'])
    

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
    
    for i in Remote_Sites:
            site_name =  i['Name']
            site_IPAddress= i['IPAddress']
            site_Address_space=i['Address_Space']
            site_vdom=i['vdom']
            site_user = i['user']
            site_password = i['password']
            Sites1,site_Address_space_Client_master = sasurl.func_readjson()
            for k in Sites1:
                if site_IPAddress ==k['IPAddress']:
                    site_PSK = k['PSK']
                    site_DataSize=k['SADataSizeInKilobytes']
                    site_DataSize = k['SADataSizeInKilobytes']
                    site_LifeTime = k['SALifeTimeInSeconds']
                    site_Connected_Subnets=k['Connected_Subnets']
                    site_Instance0=k['Instance0']
                    site_Instance1=k['Instance1']
                    site_Address_space_Client = k['Address_Space_Client']
    
            if site_IPAddress not in existig_sites:
                sasurl.create_vpnsite(site_name,site_IPAddress,site_Address_space)
                print ('New VPN Site', site_name,'created')
            else:
                print ('VPN Site', site_name, 'already exsists')
                if site_name in vpn_completed_sites:

                    print ('Hub Association is done. Configuring/Check of changes at this', site_name,'site')
                    #journal.send( 'Hub Association is done. Configuring/Check of changes at this' site_name 'site')
                    #Checking to see if the FortiGate is configured if nothing exists or making changes to the existing Site
                    fgt = fgt_api.FGT(site_IPAddress)
                    fgt.login(site_user, site_password)
                    vpn0 = site_name + '0'
                    vpn1 = site_name + '1'
                    vpn0_ph2 = vpn0 + '-ph2'
                    vpn1_ph2 = vpn1 + '-ph2'
                    existing_vpns=fgt.get('/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                          params={'vdom':site_vdom})
                    #print existing_vpns
                    existing_vpn_names=[]
                    try:

                        for i in existing_vpns['results']:
                            existing_vpn_names.append(str((i['name'])))

                    except TypeError:
                        print ('No VPNs exist on the Firewall')
                        #journal.send('No VPNs exist on the Firewall')
                    print (vpn0,vpn1)
                    if vpn0 not in existing_vpn_names:
                        # phase1_0 = phase1interface(site_name + '0', site_Instance0, site_PSK,
                        #                        site_LifeTime,site_vdom)
                        fgt.post('/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                                    params = {'vdom': site_vdom},
                                                    data={'json':{
                                                                    "name": vpn0,
                                                                    "interface": "port1",
                                                                    "ip-version": "4",
                                                                    "ike-version": "2",
                                                                    "remote-gw": site_Instance0,
                                                                    "mode": "aggressive",
                                                                    "proposal": 'aes256-sha256',
                                                                    "psksecret": site_PSK,
                                                                    "keylife" : site_LifeTime,
                                                                    "dhgrp": '2'
                                                                    }})
                        fgt.post('/api/v2/cmdb/vpn.ipsec/phase2-interface',
                                                    params = {'vdom': site_vdom},
                                                    data={'json':{
                                                                    "name": vpn0_ph2,
                                                                    "phase1name": vpn0,
                                                                    "src-addr-type": "subnet",
                                                                    "dst-addr-type": "subnet",
                                                                    "src-name"  :'0.0.0.0/0',
                                                                    "dst-name"  :'0.0.0.0/0',
                                                                    "dhgrp": '2',
                                                                    "proposal": 'aes256-sha256',
                                                                    "keylifekbs": site_DataSize
                                                                    }})
                        #phase2_0 = phase2interface(phase1_0, site_DataSize,site_vdom)
                    else:
                        phase1_0 = vpn0
                    if vpn1 not in existing_vpn_names:
                        # phase1_1 = phase1interface(site_name + '1', site_Instance1, site_PSK,
                        #                        site_LifeTime,site_vdom)
                        fgt.post('/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                                    params = {'vdom': site_vdom},
                                                    data={'json':{
                                                                    "name": vpn1,
                                                                    "interface": "port1",
                                                                    "ip-version": "4",
                                                                    "ike-version": "2",
                                                                    "remote-gw": site_Instance1,
                                                                    "mode": "aggressive",
                                                                    "proposal": 'aes256-sha256',
                                                                    "psksecret": site_PSK,
                                                                    "keylife" : site_LifeTime,
                                                                    "dhgrp": '2'
                                                                    }})
                        fgt.post('/api/v2/cmdb/vpn.ipsec/phase2-interface',
                                                    params = {'vdom': site_vdom},
                                                    data={'json':{
                                                                    "name": vpn1_ph2,
                                                                    "phase1name": vpn1,
                                                                    "src-addr-type": "subnet",
                                                                    "dst-addr-type": "subnet",
                                                                    "src-name"  :'0.0.0.0/0',
                                                                    "dst-name"  :'0.0.0.0/0',
                                                                    "dhgrp": '2',
                                                                    "proposal": 'aes256-sha256',
                                                                    "keylifekbs": site_DataSize
                                                                    }})
                        #phase2_1 = phase2interface(phase1_1, site_DataSize,site_vdom)
                    else:
                        phase1_1=vpn1
                    #for i in site_Connected_Subnets:


                    list1 = map(str,(site_Address_space_Client))

                    #route table_lookup
                    variables_for_policies = []
                    for x, j in enumerate(list1):
                        route_lookup = fgt.get('/api/v2/monitor//router/lookup',
                                            params={'vdom': site_vdom, 'destination': j.split('/')[0]})
                        # print route_lookup
                        local_interface = route_lookup['results']['interface']
                        # print local_interface
                        local_interfaces.append(local_interface)
                        local_addr_name = 'local' + site_name + str(x)
                        fgt.post('/api/v2/cmdb/firewall/address',
                                            params={'vdom': site_vdom},
                                            data={'json': {'name': local_addr_name,
                                                            "subnet": j,
                                                            "allow-routing": "enable"
                                                            }},
                                                            verbose=False)
                        #localaddr = (local_addressobject('local' + site_name + str(x), j,site_vdom))
                        # print 'The local addresses are', localaddr
                        variables_for_policies.append({'Interface': str(local_interface),
                                                'local_Address': local_addr_name})
                        #variables_for_policies=route_lookup(list1,site_vdom)
                        print (variables_for_policies)

                        site_remote_address_tmp = find_remote_addresses(site_Address_space_Client_master, site_Address_space_Client)
                        site_remote_address = site_remote_address_tmp + site_Connected_Subnets

                        #remoteaddr = (remote_addressobject('remote' + site_name, site_remote_address,site_vdom))

                        remote_name = 'remote' + site_name
                        remoteaddr = []
                        for i,j in enumerate(site_remote_address):
                            remote_name=remote_name+'_'+str(i)
                            fgt.post('/api/v2/cmdb/firewall/address',
                                params={'vdom': site_vdom},
                                data={'json': {'name': remote_name,
                                                "subnet": str(j),
                                                "allow-routing": "enable"
                                                }},
                                verbose=False)
                            remoteaddr.append(remote_name)
                            remote_name = remote_name[:-2]

                        print ('The remote addresses are',remoteaddr)


                        vpn_lookup=fgt.get('/api/v2/cmdb/firewall/policy',
                                            params={
                                                    'vdom': site_vdom})
                        try:
                            src_address = []
                            src_address_tmp = []
                            for i in vpn_lookup['results']:

                            #if i['srcintf'][0]['name'] or i['dstintf'][0]['name']  in local_interfaces:
                                if (i['srcintf'][0]['name'])  == vpn0:

                                    #print i['srcintf'][0]['name'], i['dstintf'][0]['name']
                                    src = i['srcaddr'][0]['name']
                                    src_address_tmp.append(src)
                            for i in src_address_tmp:
                                    if i not in src_address:
                                        src_address.append(i)
                            #print src_address

                            for i in remoteaddr:
                                if i not in src_address:
                                    print ('new one')
                                    for a in (variables_for_policies):
                                        #def outgoing_firewallpolicy(fromaddr,toaddr,srcint,dstint,vdom):
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': a['Interface']}],
                                                                    'srcaddr': [{'name': a['local_Address']}],
                                                                    'dstintf': [{'name': vpn0}],
                                                                    'dstaddr': [{'name': i}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': a['Interface']}],
                                                                    'srcaddr': [{'name': a['local_Address']}],
                                                                    'dstintf': [{'name': vpn1}],
                                                                    'dstaddr': [{'name': i}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': vpn0}],
                                                                    'srcaddr': [{'name': i }],
                                                                    'dstintf': [{'name': a['Interface']}],
                                                                    'dstaddr': [{'name': a['local_Address']}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': vpn1 }],
                                                                    'srcaddr': [{'name': i }],
                                                                    'dstintf': [{'name': a['Interface']}],
                                                                    'dstaddr': [{'name': a['local_Address']}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                else:
                                    print ('nothing new')
                                    #journal.send('nothing new')

                        except TypeError:
                            print ('No policies')
                            for k in remoteaddr:
                                #print k
                                for a in (variables_for_policies):
                                    #print k, a['local_Address'],a['Interface'],phase1_0
                                    #journal.send('Creating new firewall policies now')

                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': a['Interface']}],
                                                                    'srcaddr': [{'name': a['local_Address']}],
                                                                    'dstintf': [{'name': vpn0}],
                                                                    'dstaddr': [{'name': k}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': a['Interface']}],
                                                                    'srcaddr': [{'name': a['local_Address']}],
                                                                    'dstintf': [{'name': vpn1}],
                                                                    'dstaddr': [{'name': k}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': vpn0}],
                                                                    'srcaddr': [{'name': k }],
                                                                    'dstintf': [{'name': a['Interface']}],
                                                                    'dstaddr': [{'name': a['local_Address']}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})
                                        fgt.post('/api/v2/cmdb/firewall/policy',
                                                            params = {'vdom': site_vdom},
                                                            data = {'json': {'policyid': 0,
                                                                    'srcintf': [{'name': vpn1 }],
                                                                    'srcaddr': [{'name': k }],
                                                                    'dstintf': [{'name': a['Interface']}],
                                                                    'dstaddr': [{'name': a['local_Address']}],
                                                                    'service': [{'name': "ALL"}],
                                                                    'schedule': "always",
                                                                    'action': "accept",
                                                                    'logtraffic': "all"}})

                        for i in remoteaddr:
                                    fgt.post('/api/v2/cmdb/router/static',
                                        params={'vdom': site_vdom},
                                        data={'json': {"device": vpn0,
                                                        "seq-num": 0,
                                                        "dstaddr": i}},
                                        verbose=True)
                                    fgt.post('/api/v2/cmdb/router/static',
                                        params={'vdom': site_vdom},
                                        data={'json': {"device": vpn1,
                                                        "seq-num": 0,
                                                        "priority": 5,
                                                        "dstaddr": i}},
                                        verbose=True)

                        fgt.logout()
    
    return(str(vpn_completed_sites))





