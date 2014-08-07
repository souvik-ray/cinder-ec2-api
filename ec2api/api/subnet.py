#    Copyright 2014 Cloudscaling Group, Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import netaddr
from neutronclient.common import exceptions as neutron_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api.api import route_table as route_table_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Subnet related API implementation
"""


def create_subnet(context, vpc_id, cidr_block,
                  availability_zone=None):
    ec2utils.validate_vpc_cidr(cidr_block, exception.InvalidSubnetRange)

    vpc = ec2utils.get_db_item(context, 'vpc', vpc_id)
    vpc_ipnet = netaddr.IPNetwork(vpc['cidr_block'])
    subnet_ipnet = netaddr.IPNetwork(cidr_block)
    if subnet_ipnet not in vpc_ipnet:
        raise exception.InvalidSubnetRange(cidr_block=cidr_block)

    # TODO(ft):
    # check availability zone
    # choose default availability zone
    gateway_ip = str(netaddr.IPAddress(subnet_ipnet.first + 1))
    start_ip = str(netaddr.IPAddress(subnet_ipnet.first + 4))
    end_ip = str(netaddr.IPAddress(subnet_ipnet.last - 1))
    main_route_table = db_api.get_item_by_id(context, 'rtb',
                                             vpc['route_table_id'])
    host_routes = route_table_api._get_subnet_host_routes(
            context, main_route_table, gateway_ip)
    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        os_network_body = {'network': {}}
        os_network = neutron.create_network(os_network_body)['network']
        cleaner.addCleanup(neutron.delete_network, os_network['id'])
        os_subnet_body = {'subnet': {'network_id': os_network['id'],
                                     'ip_version': '4',
                                     'cidr': cidr_block,
                                     'allocation_pools': [{'start': start_ip,
                                                           'end': end_ip}],
                                     'host_routes': host_routes}}
        os_subnet = neutron.create_subnet(os_subnet_body)['subnet']
        cleaner.addCleanup(neutron.delete_subnet, os_subnet['id'])
        neutron.add_interface_router(vpc['os_id'],
                                     {'subnet_id': os_subnet['id']})
        cleaner.addCleanup(neutron.remove_interface_router,
                           vpc['os_id'], {'subnet_id': os_subnet['id']})
        # TODO(Alex): Handle errors like cidr conflict or overlimit
        # TODO(ft):
        # store availability_zone
        subnet = db_api.add_item(context, 'subnet',
                                 {'os_id': os_subnet['id'],
                                  'vpc_id': vpc['id']})
        cleaner.addCleanup(db_api.delete_item, context, subnet['id'])
        ec2_subnet_id = ec2utils.get_ec2_id(subnet['id'], 'subnet')
        neutron.update_network(os_network['id'],
                               {'network': {'name': ec2_subnet_id}})
        neutron.update_subnet(os_subnet['id'],
                              {'subnet': {'name': ec2_subnet_id}})
    return {'subnet': _format_subnet(context, subnet, os_subnet,
                                          os_network)}


def delete_subnet(context, subnet_id):
    subnet = ec2utils.get_db_item(context, 'subnet', subnet_id)
    vpc = db_api.get_item_by_id(context, 'vpc', subnet['vpc_id'])
    # TODO(ft): implement search in DB layer
    network_interfaces = db_api.get_items(context, 'eni')
    if any(eni['subnet_id'] == subnet['id'] for eni in network_interfaces):
        msg = _("The subnet '%(subnet_id)s' has dependencies and "
                "cannot be deleted.") % {'subnet_id': subnet_id}
        raise exception.DependencyViolation(msg)
    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, subnet['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'subnet', subnet)
        try:
            if vpc is not None:
                neutron.remove_interface_router(vpc['os_id'],
                                                {'subnet_id': subnet['os_id']})
                cleaner.addCleanup(neutron.add_interface_router,
                                   vpc['os_id'],
                                   {'subnet_id': subnet['os_id']})
            os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
            neutron.delete_subnet(os_subnet['id'])
            neutron.delete_network(os_subnet['network_id'])
        except neutron_exception.NeutronClientException:
            # TODO(ft): do log error
            # TODO(ft): adjust catched exception classes to catch:
            # the subnet is already unplugged from the router
            # no such router
            # the subnet doesn't exist
            # some ports exist in the subnet
            # the network has other not empty subnets
            pass

    return True


def describe_subnets(context, subnet_id=None, filter=None):
    # TODO(ft): implement filters
    neutron = clients.neutron(context)
    os_subnets = neutron.list_subnets()['subnets']
    os_networks = neutron.list_networks()['networks']
    subnets = ec2utils.get_db_items(context, 'subnet', subnet_id)
    formatted_subnets = []
    for subnet in subnets:
        os_subnet = next((s for s in os_subnets
                          if s['id'] == subnet['os_id']), None)
        if not os_subnet:
            continue
        os_network = next((n for n in os_networks
                           if n['id'] == os_subnet['network_id']),
                          None)
        if os_network:
            formatted_subnets.append(_format_subnet(
                    context, subnet, os_subnet, os_network))
    return {'subnetSet': formatted_subnets}


def _format_subnet(context, subnet, os_subnet, os_network):
    status_map = {'ACTIVE': 'available',
                  'BUILD': 'pending',
                  'DOWN': 'available',
                  'ERROR': 'available'}
    return {
        'subnetId': ec2utils.get_ec2_id(subnet['id'], 'subnet'),
        'state': status_map.get(os_network['status'], 'available'),
        'vpcId': ec2utils.get_ec2_id(subnet['vpc_id'], 'vpc'),
        'cidrBlock': os_subnet['cidr'],
        'defaultForAz': 'false',
        'mapPublicIpOnLaunch': 'false',
        # 'availabilityZone' = 'nova' # TODO(Alex) implement
        # 'availableIpAddressCount' = 20 # TODO(Alex) implement
    }
