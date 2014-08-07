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


"""
Cloud Controller: Implementation of EC2 REST API calls, which are
dispatched to other nodes via AMQP RPC. State is via distributed
datastore.
"""

from oslo.config import cfg

from ec2api.api import internet_gateway
from ec2api.api import route_table
from ec2api.api import subnet
from ec2api.api import vpc
from ec2api.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CloudController(object):

    """Cloud Controller

        Provides the critical dispatch between
        inbound API calls through the endpoint and messages
        sent to the other nodes.
    """

    def __init__(self):
        pass

    def __str__(self):
        return 'CloudController'

    def create_vpc(self, context, cidr_block, instance_tenancy='default'):
        """Creates a VPC with the specified CIDR block.

        Args:
            context (RequestContext): The request context.
            cidr_block (str): The CIDR block for the VPC
                (for example, 10.0.0.0/16).
            instance_tenancy (str): The supported tenancy options for
                instances launched into the VPC.
                Valid values: default | dedicated
                Not used now.

        Returns:
            Information about the VPC.

        The smallest VPC you can create uses a /28 netmask (16 IP addresses),
        and the largest uses a /16 netmask.
        """
        return vpc.create_vpc(context, cidr_block, instance_tenancy)

    def delete_vpc(self, context, vpc_id):
        """Deletes the specified VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.

        Returns:
            true if the request succeeds.

        You must detach or delete all gateways and resources that are
        associated with the VPC before you can delete it. For example, you must
        terminate all instances running in the VPC, delete all security groups
        associated with the VPC (except the default one), delete all route
        tables associated with the VPC (except the default one), and so on.
        """
        return vpc.delete_vpc(context, vpc_id)

    def describe_vpcs(self, context, vpc_id=None, filter=None):
        """Describes one or more of your VPCs.

        Args:
            context (RequestContext): The request context.
            vpc_id (list of str): One or more VPC IDs.
                Default: Describes all your VPCs.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain VPCs.

        Returns:
            A list of VPCs.
        """
        return vpc.describe_vpcs(context, vpc_id, filter)

    def create_internet_gateway(self, context):
        """Creates an Internet gateway for use with a VPC.

        Args:
            context (RequestContext): The request context.

        Returns:
            Information about the Internet gateway.
        """
        return internet_gateway.create_internet_gateway(context)

    def attach_internet_gateway(self, context, internet_gateway_id, vpc_id):
        """Attaches an Internet gateway to a VPC.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.
            vpc_id (str): The ID of the VPC.

        Returns:
            Returns true if the request succeeds.

        Attaches an Internet gateway to a VPC, enabling connectivity between
        the Internet and the VPC.
        """
        return internet_gateway.attach_internet_gateway(context,
                                                       internet_gateway_id,
                                                       vpc_id)

    def detach_internet_gateway(self, context, internet_gateway_id, vpc_id):
        """Detaches an Internet gateway from a VPC.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.
            vpc_id (str): The ID of the VPC.

        Returns:
            Returns true if the request succeeds.

        Detaches an Internet gateway from a VPC, disabling connectivity between
        the Internet and the VPC. The VPC must not contain any running
        instances with Elastic IP addresses.
        """
        return internet_gateway.detach_internet_gateway(context,
                                                       internet_gateway_id,
                                                       vpc_id)

    def delete_internet_gateway(self, context, internet_gateway_id):
        """Deletes the specified Internet gateway.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.

        Returns:
            Returns true if the request succeeds.

        You must detach the Internet gateway from the VPC before you can
        delete it.
        """
        return internet_gateway.delete_internet_gateway(context,
                                                       internet_gateway_id)

    def describe_internet_gateways(self, context, internet_gateway_id=None,
                                   filter=None):
        """Describes one or more of your Internet gateways.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (list of str): One or more Internet gateway
                IDs.
                Default: Describes all your Internet gateways.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain Internet
                gateways.

        Returns:
            A list of Internet gateways.
        """
        return internet_gateway.describe_internet_gateways(context,
                                                          internet_gateway_id)

    def create_subnet(self, context, vpc_id, cidr_block,
                      availability_zone=None):
        """Creates a subnet in an existing VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.
            cidr_block (str): The CIDR block for the subnet.
                For example, 10.0.0.0/24.
            availability_zone (str): The Availability Zone for the subnet.
                If None or empty EC2 selects one for you.

        Returns:
            Information about the subnet.

        The subnet's CIDR block can be the same as the VPC's CIDR block,
        or a subset of the VPC's CIDR block. If you create more than one subnet
        in a VPC, the subnets' CIDR blocks must not overlap. The smallest
        subnet you can create uses a /28 netmask (16 IP addresses),
        and the largest uses a /16 netmask.

        EC2 reserves both the first four and the last IP address
        in each subnet's CIDR block. They're not available for use.

        If you add more than one subnet to a VPC, they're set up
        in a star topology with a logical router in the middle.
        """
        return subnet.create_subnet(context, vpc_id,
                                    cidr_block, availability_zone)

    def delete_subnet(self, context, subnet_id):
        """Deletes the specified subnet.

        Args:
            context (RequestContext): The request context.
            subnet_id (str): The ID of the subnet.

        Returns:
            true if the request succeeds.

        You must terminate all running instances in the subnet before
        you can delete the subnet.
        """
        return subnet.delete_subnet(context, subnet_id)

    def describe_subnets(self, context, subnet_id=None, filter=None):
        """Describes one or more of your subnets.


        Args:
            context (RequestContext): The request context.
            subnet_id (list of str): One or more subnet IDs.
                Default: Describes all your subnets.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain subnets.

        Returns:
            A list of subnets.
        """
        return subnet.describe_subnets(context, subnet_id, filter)

    def create_route_table(self, context, vpc_id):
        """Creates a route table for the specified VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.

        Returns:
            Information about the route table.

        After you create a route table, you can add routes and associate the
        table with a subnet.
        """
        return route_table.create_route_table(context, vpc_id)

    def create_route(self, context, route_table_id, destination_cidr_block,
                     gateway_id=None, instance_id=None,
                     network_interface_id=None,
                     vpc_peering_connection_id=None):
        """Creates a route in a route table within a VPC.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table for the route.
            destination_cidr_block (str): The CIDR address block used for the
                destination match. Routing decisions are based on the most
                specific match.
            gateway_id (str): The ID of an Internet gateway or virtual private
                gateway attached to your VPC.
            instance_id (str): The ID of a NAT instance in your VPC.
                The operation fails if you specify an instance ID unless
                exactly one network interface is attached.
            network_interface_id (str): The ID of a network interface.
            vpc_peering_connection_id (str): The ID of a VPC peering
                connection.

        Returns:
            true if the requests succeeds.

        The route's target can be an Internet gateway or virtual private
        gateway attached to the VPC, a VPC peering connection, or a NAT
        instance in the VPC.
        """
        return route_table.create_route(context, route_table_id,
                                        destination_cidr_block, gateway_id,
                                        instance_id, network_interface_id,
                                        vpc_peering_connection_id)

    def replace_route(self, context, route_table_id, destination_cidr_block,
                      gateway_id=None, instance_id=None,
                      network_interface_id=None,
                      vpc_peering_connection_id=None):
        """Replaces an existing route within a route table in a VPC.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table for the route.
            destination_cidr_block (str): The CIDR address block used for the
                destination match. Routing decisions are based on the most
                specific match.
            gateway_id (str): The ID of an Internet gateway or virtual private
                gateway attached to your VPC.
            instance_id (str): The ID of a NAT instance in your VPC.
                The operation fails if you specify an instance ID unless
                exactly one network interface is attached.
            network_interface_id (str): The ID of a network interface.
            vpc_peering_connection_id (str): The ID of a VPC peering
                connection.

        Returns:
            true if the requests succeeds.
        """
        return route_table.replace_route(context, route_table_id,
                                         destination_cidr_block,
                                         gateway_id, instance_id,
                                         network_interface_id,
                                         vpc_peering_connection_id)

    def delete_route(self, context, route_table_id, destination_cidr_block):
        """Deletes the specified route from the specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            destination_cidr_block (str): The CIDR range for the route.
                The value you specify must match the CIDR for the route
                exactly.

        Returns:
            true if the requests succeeds.
        """
        return route_table.delete_route(context, route_table_id,
                                        destination_cidr_block)

    def associate_route_table(self, context, route_table_id, subnet_id):
        """Associates a subnet with a route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            subnet_id (str): The ID of the subnet.

        Returns:
            The route table association ID

        The subnet and route table must be in the same VPC. This association
        causes traffic originating from the subnet to be routed according to
        the routes in the route table. The action returns an association ID,
        which you need in order to disassociate the route table from the subnet
        later. A route table can be associated with multiple subnets.
        """
        return route_table.associate_route_table(context, route_table_id,
                                                 subnet_id)

    def replace_route_table_association(self, context, association_id,
                                        route_table_id):
        """Changes the route table associated with a given subnet in a VPC.

        Args:
            context (RequestContext): The request context.
            association_id (str): The association ID.
            route_table_id (str): The ID of the new route table to associate
                with the subnet.

        Returns:
            The ID of the new association.

        After the operation completes, the subnet uses the routes in the new
        route table it's associated with.
        You can also use this action to change which table is the main route
        table in the VPC.
        """
        return route_table.replace_route_table_association(context,
                                                           association_id,
                                                           route_table_id)

    def disassociate_route_table(self, context, association_id):
        """Disassociates a subnet from a route table.

        Args:
            context (RequestContext): The request context.
            association_id (str): The association ID.

        Returns:
            true if the requests succeeds.

        After you perform this action, the subnet no longer uses the routes in
        the route table. Instead, it uses the routes in the VPC's main route
        table.
        """
        return route_table.disassociate_route_table(context, association_id)

    def delete_route_table(self, context, route_table_id):
        """Deletes the specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.

        You must disassociate the route table from any subnets before you can
        delete it. You can't delete the main route table.

        Returns:
            true if the requests succeeds.
        """
        return route_table.delete_route_table(context, route_table_id)

    def describe_route_tables(self, context, route_table_id=None, filter=None):
        """Describes one or more of your route tables.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): One or more route table IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain tables.

        Returns:
            A list of route tables
        """
        return route_table.describe_route_tables(context, route_table_id=None,
                                                 filter=None)
