#!/usr/bin/python
###########################################################################
# Description:
#
# Copyright (c) 2018 Nokia
###########################################################################
from srlinux.mgmt.cli.cli_plugin import CliPlugin
from srlinux.mgmt.cli.execute_error import ExecuteError
from srlinux.mgmt.cli.plugins.bash_network_command_helper import execute_network_command, add_common_arguments
from srlinux.syntax import Syntax


class Plugin(CliPlugin):
    def load(self, cli, **_kwargs):
        syntax = Syntax('fabric-traceroute', help='Print the route(s) packets trace to network host, following all uplinks and ECMP paths')
        add_tracert_arguments(syntax)
        cli.add_global_command(syntax, only_at_start_of_line=True, update_location=False, callback=send_traceroute)

def send_traceroute(state, output, arguments, **_kwargs):
    if not state.is_interactive:
        raise ExecuteError(f"'{arguments}' is only supported in interactive mode")

    def get_uplinks(netns):
       logging.info( f"fabric-traceroute: Listing all uplinks in '{netns}' network-instance" )
       # XXX hardcoded assumption it is called 'default'
       path = build_path(f'/network-instance[name={netns}]/interface[name=e*]')
       data = state.server_data_store.get_data(path, recursive=True)
       return [ i.name.replace('ethernet-','e').replace('/','-')
                for i in data.network_instance.get().interface.items() ]

    # XXX Hardcoded name for network-instance of type 'default'
    network_instance = arguments.get_or('network-instance', 'default')
    if not arguments.has_node('uplinks'):
        arguments.set( 'uplinks', get_uplinks(network_instance) )

    cmd = '/opt/demo-agents/srl-vxlan-oam/ecmp-traceroute.py'
    return execute_network_command(cmd, output, arguments)

def add_tracert_arguments(syntax):
    ''' Add the arguments shared between 'traceroute' and 'traceroute6' '''
    add_common_arguments(syntax)

    syntax.add_named_argument('-f', default=None, help='Specifies with what TTL to start. Defaults to 1')
    syntax.add_named_argument('-g', default=None, help='gateway : Route packets through the specified gateway')
    syntax.add_named_argument(
        '-p',
        default=None,
        help='port For ICMP tracing, specifies the initial ICMP sequence value (incremented by each probe too).')
    syntax.add_named_argument('-N', default=None, help='Specifies the number of probe packets sent out simultaneously.')
    syntax.add_named_argument(
        '-m',
        default=5,
        help='max_ttl Specifies the maximum number of hops (max time-to-live value) fabric-traceroute will probe.'
             ' The default is 5.')

    # syntax.add_boolean_argument(
    #     '-A',
    #     help='Perform AS path lookups in routing registries and print results directly'
    #          ' after the corresponding addresses.')
    syntax.add_boolean_argument('-F', help='Do not fragment probe packets.')
    syntax.add_boolean_argument('-I', help='Use ICMP ECHO for probes')
    syntax.add_boolean_argument('-T', help='Use TCP SYN for probes')
    # syntax.add_boolean_argument('-n', help='Do not try to map IP addresses to host names when displaying them.')
