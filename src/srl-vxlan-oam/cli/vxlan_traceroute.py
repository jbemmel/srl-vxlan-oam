#!/usr/bin/python
###########################################################################
# Description:
#
# Copyright (c) 2021 Nokia
###########################################################################
from srlinux.mgmt.cli import ExecuteError
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.mgmt.cli.required_plugin import RequiredPlugin
from srlinux.mgmt.cli import KeyCompleter
from srlinux.syntax import Syntax
from srlinux.location import build_path
from srlinux.mgmt.cli.plugins.bash_network_command_helper import execute_network_command
from srlinux import child_process
from srlinux.schema import DataStore

import sys
sys.path.append('/usr/local/lib/python3.6/site-packages') # for netns
import logging, socket, netns

#
# L2 service ping using custom ARP packets
#
class Plugin(ToolsPlugin):

    # Provide list of plugins that must be loaded before this one
    def get_required_plugins(self):
        return [RequiredPlugin("tools_mode")]

    # Define where this command exists in the command hierarchy in sr_cli
    def on_tools_load(self, state):
        # Could also add it under /tools network-instance
        if state.system_features.vxlan:
           root = state.command_tree.tools_mode.root
           root.add_command(self._get_syntax(state), update_location=False, callback=do_traceroute)
        # system = state.command_tree.tools_mode.root.get_command('system')
        # system.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)
        else:
            logging.warning( "VXLAN feature not enabled for this system" )

    # Helper function to get arguments and help strings for this plugin command
    def _get_syntax(self,state):
        syntax = Syntax("vxlan-traceroute", help="Traces paths to other VXLAN VTEPs, globally or for a given L2 overlay service (mac-vrf)")
        syntax.add_named_argument('mac-vrf', default="*", help="target mac-vrf used to lookup the destination VTEPs, default all known VTEPs",
          suggestions=KeyCompleter(path='/network-instance[name=*]')) # Cannot select type=mac-vrf only?

        # Dont allow specific VNI directly, we need to know service context with VTEPs
        # syntax.add_named_argument('vni', default="0", help="specific vni to use (instead of lookup by mac-vrf)",
        #  suggestions=KeyCompleter(path='/tunnel-interface[name=*]/vxlan-interface[index=*]/ingress/vni'))

        # Lookup vxlan interface for given mac-vrf - seems to deadlock
        def _get_vteps_in_vrf(arguments):
          mac_vrf = arguments.get_or('mac-vrf','*')
          # logging.info( f"_get_path args={arguments} mac_vrf={mac_vrf}" )
          if mac_vrf!='*':
             vxlan_intf = get_vxlan_interface(state,mac_vrf)
             tun = vxlan_intf.split('.')
          else:
             tun = ['*','*']
          # Could lookup VNI here too
          return build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/bridge-table/multicast-destinations/destination[vtep=*][vni=*]')

        # Hardcoded
        syntax.add_named_argument('vtep', default='*',
           # suggestions=KeyCompleter(path=_get_vteps_in_vrf,keyname='vtep') )
           # suggestions=KeyCompleter(path='/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/bridge-table/multicast-destinations/destination[vtep=*]') )
           suggestions=KeyCompleter(path='/tunnel-interface[name=*]/vxlan-interface[index=*]/bridge-table/multicast-destinations/destination[vtep=*]') )

        syntax.add_named_argument('timeout', default="auto", help="Timeout and interval between probes, default auto (= minimum to avoid ICMP rate limits)")
        syntax.add_named_argument('ttl', default="1-3", help="TTL range to use, default 1-3 (inclusive)")
        syntax.add_named_argument('entropy', default="0", help="Provide extra input to ECMP hashing, added to UDP source port in traceroute probes")
        syntax.add_boolean_argument('debug', help="Enable additional debug output")

        # TODO add 'count' argument, default 3
        return syntax

# end class VxlanServicePing

def get_vxlan_interface(state,mac_vrf):
   path = build_path(f'/network-instance[name={mac_vrf}]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-interface')
   data = state.server_data_store.get_data(path, recursive=True)
   return data.network_instance.get().protocols.get().bgp_evpn.get().bgp_instance.get().vxlan_interface

    # Callback that runs when the plugin is run in sr_cli
def do_traceroute(state, input, output, arguments, **_kwargs):
    logging.info( f"do_traceroute arguments={arguments}" )

    mac_vrf = arguments.get('mac-vrf')
    vtep = arguments.get('vtep')
    ttl = arguments.get('ttl')
    timeout = arguments.get('timeout')
    entropy = int( arguments.get('entropy') )
    debug = arguments.get('debug')

    def get_uplinks():
       logging.info( f"vxlan-traceroute: Listing all uplinks in 'default' network-instance" )
       # XXX hardcoded assumption it is called 'default'
       path = build_path(f'/network-instance[name=default]/interface[name=e*]')
       data = state.server_data_store.get_data(path, recursive=True)
       return [ i.name.replace('ethernet-','e').replace('/','-')
                for i in data.network_instance.get().interface.items() ]

    def get_system0_vtep_ip():
       path = build_path('/interface[name=system0]/subinterface[index=0]/ipv4/address')
       data = state.server_data_store.get_data(path, recursive=True)
       for a in data.interface.get().subinterface.get().ipv4.get().address.items():
           logging.info( f"system0 IP: {a.ip_prefix}" ) # Only allows 1 IP
       return data.interface.get().subinterface.get().ipv4.get().address.get().ip_prefix # .split('/')[0]

    # Need to access State
    def get_evpn_vteps(vxlan_intf):
       logging.info( f"vxlan-traceroute: Listing VTEPs associated with VXLAN interface {vxlan_intf}" )
       # path = build_path('/vxlan-agent/evpn-vteps')
       tun = vxlan_intf.split('.')
       path = build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/bridge-table/multicast-destinations/destination')
       # logging.info( f"Current store: {state.data_store}")
       data = state.server.get_data_store( DataStore.State ).get_data(path, recursive=True)
       return [ p.vtep for p in data.tunnel_interface.get().vxlan_interface.get().bridge_table.get().multicast_destinations.get().destination.items() ]

    vxlan_intf = get_vxlan_interface(state,mac_vrf)
    local_vtep = get_system0_vtep_ip() # ip/prefix
    uplinks = ",".join( get_uplinks() )
    dest_vteps = vtep if vtep!='*' else ",".join( get_evpn_vteps(vxlan_intf) )

    # Run a separate, simple Python binary in the default namespace
    # Need sudo
    dbg = "debug" if debug else ""
    cmd = f"ip netns exec srbase-default /usr/bin/sudo -E /usr/bin/python3 /opt/demo-agents/srl-vxlan-oam/ecmp-traceroute.py {local_vtep} {ttl} {timeout} {entropy} {uplinks} {dest_vteps} {dbg}"
    logging.info( f"vxlan-traceroute: {cmd}" )
    exit_code = child_process.run( cmd.split(), output=output )
    logging.info( f"vxlan-traceroute: exitcode {exit_code}" )
