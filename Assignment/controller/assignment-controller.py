#!/usr/bin/env python3

import argparse
import os
import sys
from time import sleep
from scapy.all import Ether, Packet, BitField, raw
import threading
import time

import grpc

# Import P4Runtime lib from utils dir
# This approach is used to import P4Runtime library when it's located in a different directory.
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../utils/'))

# Import the necessary P4Runtime libraries
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections #, connections

# Define a custom CPU header that encapsules additional information sent by the data plane
class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingressPort', 0, 16)]

# List of broadcast replicas the clone engine for the multicast group
# with egress port and the number of copies "instance"
broadcastReplicas = [
    {'egress_port': 1, 'instance': 1},
    {'egress_port': 2, 'instance': 1},
    {'egress_port': 3, 'instance': 1},
    {'egress_port': 4, 'instance': 1},
    {'egress_port': 5, 'instance': 1}
]

# List of CPU replicas, clone engine for sending packets to CPU (port 510)
cpuReplicas = [
     {'egress_port': 510, 'instance': 1}
]

# Define session IDs for multicast and CPU sessions (clone engines)
mcSessionId = 1
cpuSessionId = 100

# Custom function to handle gRPC errors and display useful debugging information
def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

# Function to read the current table rules from the switch and print them
def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # you can use the p4info_helper to translate
            # the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()

# Function to install a default action entry into a table
def writeDefaultTableAction(p4info_helper, sw, table, action):
    table_entry = p4info_helper.buildTableEntry(
            table_name = table,
            default_action = True,
            action_name = action)
    sw.WriteTableEntry(table_entry)
    print("Installed default entry on %s" % sw.name)

# Function to write a MAC destination lookup entry to the table
def writeMacDstLookUp(p4info_helper, sw, mac, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.dMacLookup",
        match_fields = {
            "hdr.eth.dstAddr" : mac
        },
        default_action = False,
        action_name = "MyIngress.forward",
        action_params = {
            "egressPort": port
        },
        priority = 0)
    sw.WriteTableEntry(table_entry)
    print("Installed MAC DST rules on %s" % sw.name)

# Function to write a MAC source lookup entry to the table
def writeMacSrcLookUp(p4info_helper, sw, mac):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.sMacLookup",
        match_fields = {
            "hdr.eth.srcAddr" : mac
        },
        default_action = False,
        action_name = "NoAction",
        action_params = None, 
        priority = 0)
    sw.WriteTableEntry(table_entry)
    print("Installed MAC SRC rules on %s" % sw.name)

# Function to write a multicast group entry to the switch
def writeMcGroup(p4info_helper, sw, sessionId):
    mc_group = p4info_helper.buildMulticastGroupEntry(sessionId, broadcastReplicas)
    sw.WritePREEntry(mc_group)
    print("Installed Mc Group on %s" % sw.name)

# Function to write a CPU session entry for packet cloning to the CPU port
def writeCpuSession(p4info_helper, sw, sessionId):
    clone_entry = p4info_helper.buildCloneSessionEntry(sessionId, cpuReplicas)
    sw.WritePREEntry(clone_entry)
    print("Installed clone session on %s" % sw.name)

# Define switch configurations
SWITCH_CONFIGS = {
    's1': {'address': '127.0.0.1:50051', 'device_id': 0, 'log_file': 'logs/s1-p4runtime-request.txt', 'p4_program': 'l2switch'},
    'r1': {'address': '127.0.0.1:50052', 'device_id': 1, 'log_file': 'logs/r1-p4runtime-request.txt', 'p4_program': 'ingress'},
    'r2': {'address': '127.0.0.1:50053', 'device_id': 2, 'log_file': 'logs/r2-p4runtime-request.txt', 'p4_program': 'label_forwarder'},
    'r3': {'address': '127.0.0.1:50054', 'device_id': 3, 'log_file': 'logs/r3-p4runtime-request.txt', 'p4_program': 'label_forwarder'},
    'r4': {'address': '127.0.0.1:50055', 'device_id': 4, 'log_file': 'logs/r4-p4runtime-request.txt', 'p4_program': 'teste_r4'},
    'r5': {'address': '127.0.0.1:50056', 'device_id': 5, 'log_file': 'logs/r5-p4runtime-request.txt', 'p4_program': 'label_forwarder'},
    'r6': {'address': '127.0.0.1:50057', 'device_id': 6, 'log_file': 'logs/r6-p4runtime-request.txt', 'p4_program': 'label_forwarder'},
}

# Flow configurations for each router
ROUTER_FLOWS = {
    'r1': [
        {'table': 'MyIngress.ipv4Lpm', 'action': 'MyIngress.forward', 'match': {'hdr.ipv4.dstAddr': ('10.0.1.1', 32)}, 'params': {'egressPort': 1, 'nextHopMac': 0xaa0000000001}},
        {'table': 'MyIngress.ipv4Lpm', 'action': 'MyIngress.forward', 'match': {'hdr.ipv4.dstAddr': ('10.0.1.2', 32)}, 'params': {'egressPort': 1, 'nextHopMac': 0xaa0000000002}},
        {'table': 'MyIngress.ipv4Lpm', 'action': 'MyIngress.forward', 'match': {'hdr.ipv4.dstAddr': ('10.0.1.3', 32)}, 'params': {'egressPort': 1, 'nextHopMac': 0xaa0000000003}},
        {'table': 'MyIngress.forTunnelMacrewrite', 'action': 'MyIngress.rewriteMacsForTunnel', 'match': {'standard_metadata.egress_spec': 2}, 'params': {'srcAddr': 0xaa0000000102, 'dstAddr': 0xaa0000000201}},
        {'table': 'MyIngress.forTunnelMacrewrite', 'action': 'MyIngress.rewriteMacsForTunnel', 'match': {'standard_metadata.egress_spec': 3}, 'params': {'srcAddr': 0xaa0000000103, 'dstAddr': 0xaa0000000601}},
        {'table': 'MyIngress.internalMacLookup', 'action': 'MyIngress.rewriteMacs', 'match': {'standard_metadata.egress_spec': 1}, 'params': {'srcMac': 0xaa0000000101}},
    ],
    'r2': [
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x2020}, 'params': {'port': 2, 'dst_mac': 0xaa0000000301, 'src_mac': 0xaa0000000202}},
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x2010}, 'params': {'port': 1, 'dst_mac': 0xaa0000000102, 'src_mac': 0xaa0000000201}},
    ],
    'r3': [
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x3020}, 'params': {'port': 2, 'dst_mac': 0xaa0000000403, 'src_mac': 0xaa0000000302}},
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x3010}, 'params': {'port': 1, 'dst_mac': 0xaa0000000202, 'src_mac': 0xaa0000000301}},
    ],
    'r4': [
        {'table': 'MyIngress.ipv4Lpm', 'action': 'MyIngress.forward', 'match': {'hdr.ipv4.dstAddr': ('10.0.2.1', 32)}, 'params': {'egressPort': 1, 'nextHopMac': 0xaa0000000004}},
        {'table': 'MyIngress.forTunnelMacrewrite', 'action': 'MyIngress.rewriteMacsForTunnel', 'match': {'standard_metadata.egress_spec': 3}, 'params': {'srcAddr': 0xaa0000000302, 'dstAddr': 0xaa0000000403}},
        {'table': 'MyIngress.forTunnelMacrewrite', 'action': 'MyIngress.rewriteMacsForTunnel', 'match': {'standard_metadata.egress_spec': 2}, 'params': {'srcAddr': 0xaa0000000503, 'dstAddr': 0xaa0000000402}},
        {'table': 'MyIngress.internalMacLookup', 'action': 'MyIngress.rewriteMacs', 'match': {'standard_metadata.egress_spec': 1}, 'params': {'srcMac': 0xaa0000000401}},
        # Firewall configuration - direction 0 means outgoing traffic (from internal to external)
        {'table': 'MyIngress.check_ports', 'action': 'MyIngress.set_direction', 'match': {'standard_metadata.ingress_port': 1, 'standard_metadata.egress_spec': 2}, 'params': {'dir': 0}},
        {'table': 'MyIngress.check_ports', 'action': 'MyIngress.set_direction', 'match': {'standard_metadata.ingress_port': 1, 'standard_metadata.egress_spec': 3}, 'params': {'dir': 0}},
        # Firewall configuration - direction 1 means incoming traffic (from external to internal)
        {'table': 'MyIngress.check_ports', 'action': 'MyIngress.set_direction', 'match': {'standard_metadata.ingress_port': 2, 'standard_metadata.egress_spec': 1}, 'params': {'dir': 1}},
        {'table': 'MyIngress.check_ports', 'action': 'MyIngress.set_direction', 'match': {'standard_metadata.ingress_port': 3, 'standard_metadata.egress_spec': 1}, 'params': {'dir': 1}},
        # Allow specific UDP ports (common services)
        {'table': 'MyIngress.allowed_udp_ports', 'action': 'MyIngress.allow_predefined_port', 'match': {'hdr.udp.dstPort': 53}, 'params': {}},  # DNS
        {'table': 'MyIngress.allowed_udp_ports', 'action': 'MyIngress.allow_predefined_port', 'match': {'hdr.udp.dstPort': 80}, 'params': {}},  # HTTP
        {'table': 'MyIngress.allowed_udp_ports', 'action': 'MyIngress.allow_predefined_port', 'match': {'hdr.udp.dstPort': 443}, 'params': {}}, # HTTPS
        {'table': 'MyIngress.allowed_udp_ports', 'action': 'MyIngress.allow_predefined_port', 'match': {'hdr.udp.dstPort': 123}, 'params': {}}, # NTP
    ],
    'r5': [
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x5020}, 'params': {'port': 2, 'dst_mac': 0xaa0000000402, 'src_mac': 0xaa0000000502}},
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x5010}, 'params': {'port': 1, 'dst_mac': 0xaa0000000602, 'src_mac': 0xaa0000000501}},
    ],
    'r6': [
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x6020}, 'params': {'port': 2, 'dst_mac': 0xaa0000000501, 'src_mac': 0xaa0000000602}},
        {'table': 'MyIngress.label_forwarding', 'action': 'MyIngress.pop_and_forward', 'match': {'hdr.mslp_labels[0].label': 0x6010}, 'params': {'port': 1, 'dst_mac': 0xaa0000000103, 'src_mac': 0xaa0000000601}},
    ],
}

def writeRouterTableEntry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
    """Write a table entry for router switches"""
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=False,
        action_name=action_name,
        action_params=action_params,
        priority=0)
    sw.WriteTableEntry(table_entry)
    print(f"Installed {table_name} rule on {sw.name}")

def setRouterDefaultActions(p4info_helper, sw, router_name):
    """Set default actions for router tables based on router type"""
    if router_name in ['r1', 'r4']:
        # Ingress and egress routers have multiple tables
        writeDefaultTableAction(p4info_helper, sw, "MyIngress.ipv4Lpm", "MyIngress.drop")
        writeDefaultTableAction(p4info_helper, sw, "MyIngress.forTunnelMacrewrite", "MyIngress.drop")
        writeDefaultTableAction(p4info_helper, sw, "MyIngress.internalMacLookup", "MyIngress.drop")
        writeDefaultTableAction(p4info_helper, sw, "MyIngress.tunnel_label_selector", "MyIngress.set_labels_tunnel1")
        
        # Additional tables for r4 (ns.p4 with firewall)
        if router_name == 'r4':
            writeDefaultTableAction(p4info_helper, sw, "MyIngress.check_ports", "NoAction")
            writeDefaultTableAction(p4info_helper, sw, "MyIngress.allowed_udp_ports", "NoAction")
    else:
        # Label forwarding routers (r2, r3, r5, r6)
        writeDefaultTableAction(p4info_helper, sw, "MyIngress.label_forwarding", "MyIngress.drop")

def connectToSwitches(p4info_files, json_files):
    """Connect to all switches and return switch connections with their helpers"""
    switches = {}
    
    for name, config in SWITCH_CONFIGS.items():
        try:
            p4_program = config['p4_program']
            p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_files[p4_program])
            
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=name,
                address=config['address'],
                device_id=config['device_id'],
                proto_dump_file=config['log_file'])
            
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                         bmv2_json_file_path=json_files[p4_program])
            
            switches[name] = {'switch': sw, 'helper': p4info_helper}
            print(f"Connected to {name} with {p4_program} program")
            
        except Exception as e:
            print(f"Failed to connect to {name}: {e}")
    
    return switches

# Main function that initializes P4Runtime connections and performs setup
def main(p4info_files, json_files):
    try:
        # Connect to all switches
        switches = connectToSwitches(p4info_files, json_files)
        
        if 's1' in switches:
            s1_data = switches['s1']
            s1 = s1_data['switch']
            p4info_helper = s1_data['helper']
            # Write default actions for s1
            writeDefaultTableAction(p4info_helper, s1, "MyIngress.sMacLookup", "MyIngress.learnMac")
            writeDefaultTableAction(p4info_helper, s1, "MyIngress.dMacLookup", "NoAction")
            writeCpuSession(p4info_helper, s1, cpuSessionId)
            writeMcGroup(p4info_helper, s1, mcSessionId)
        
        # Populate router tables
        populateRouterTables(switches)
        
        # Set initial default actions for tunnel selectors
        for switch_name in ['r1', 'r4']:
            if switch_name in switches:
                sw_data = switches[switch_name]
                setTunnelSelectorDefault(sw_data['helper'], sw_data['switch'], "set_labels_tunnel1")
        
        # Start tunnel selector thread
        tunnel_thread = threading.Thread(target=tunnel_selector_thread, 
                                        args=(switches,), 
                                        daemon=True)
        tunnel_thread.start()
        
        # Start l2switch packet handling thread if s1 is connected
        if 's1' in switches:
            packet_thread = threading.Thread(target=l2switch_packet_thread, 
                                            args=(switches['s1']['helper'], switches['s1']['switch']), 
                                            daemon=True)
            packet_thread.start()
        
        print("All threads started. Press Ctrl+C to exit.")
        
        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(" Shutting down.")
        ShutdownAllSwitchConnections()
    except grpc.RpcError as e:
        printGrpcError(e) # Handle any gRPC errors that might occur

def populateRouterTables(switches):
    """Populate all router tables with predefined flows"""
    for router_name, flows in ROUTER_FLOWS.items():
        if router_name in switches:
            sw_data = switches[router_name]
            sw = sw_data['switch']
            p4info_helper = sw_data['helper']
            print(f"Populating tables for {router_name}")
            
            # Set default actions first
            setRouterDefaultActions(p4info_helper, sw, router_name)
            
            # Then add specific flows
            for flow in flows:
                writeRouterTableEntry(
                    p4info_helper, sw, 
                    flow['table'], 
                    flow['match'], 
                    flow['action'], 
                    flow['params']
                )

def setTunnelSelectorDefault(p4info_helper, sw, action_name):
    """Set default action for tunnel_label_selector table"""
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.tunnel_label_selector",
        default_action=True,
        action_name=f"MyIngress.{action_name}")
    sw.WriteTableEntry(table_entry)
    print(f"Set tunnel selector default to {action_name} on {sw.name}")

def tunnel_selector_thread(switches):
    """Thread that toggles tunnel selector every 10 seconds"""
    current_action = "set_labels_tunnel1"
    
    while True:
        try:
            # Toggle between tunnel1 and tunnel2
            if current_action == "set_labels_tunnel1":
                current_action = "set_labels_tunnel2"
            else:
                current_action = "set_labels_tunnel1"
            
            # Update r1 and r4
            for switch_name in ['r1', 'r4']:
                if switch_name in switches:
                    sw_data = switches[switch_name]
                    setTunnelSelectorDefault(sw_data['helper'], sw_data['switch'], current_action)
            
            print(f"Switched to {current_action}")
            time.sleep(10)
            
        except Exception as e:
            print(f"Error in tunnel selector thread: {e}")
            break

def l2switch_packet_thread(p4info_helper, s1):
    """Thread that handles l2switch packet-in messages"""
    macList = []
    
    try:
        for response in s1.stream_msg_resp:
            if response.packet:
                print("Received packet-in message:")
                packet = Ether(raw(response.packet.payload))
                if packet.type == 0x1234:
                    cpu_header = CpuHeader(bytes(packet.load))
                    print("mac: %012X ingress_port: %s " % (cpu_header.macAddr, cpu_header.ingressPort))
                    if cpu_header.macAddr not in macList:
                        writeMacSrcLookUp(p4info_helper, s1, cpu_header.macAddr)
                        writeMacDstLookUp(p4info_helper, s1, cpu_header.macAddr, cpu_header.ingressPort)
                        macList.append(cpu_header.macAddr)
                    else:
                        print("Rules already set")
            else:
                print(f"Received non-packet-in message: {response}")
                
    except Exception as e:
        print(f"Error in l2switch packet thread: {e}")

# Entry point for the script
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--l2switch-p4info', help='l2switch p4info file',
                        type=str, action="store", required=True)
    parser.add_argument('--l2switch-json', help='l2switch JSON file',
                        type=str, action="store", required=True)
    parser.add_argument('--label-forwarder-p4info', help='label_forwarder p4info file',
                        type=str, action="store", required=True)
    parser.add_argument('--label-forwarder-json', help='label_forwarder JSON file',
                        type=str, action="store", required=True)
    parser.add_argument('--ingress-p4info', help='ingress p4info file',
                        type=str, action="store", required=True)
    parser.add_argument('--ingress-json', help='ingress JSON file',
                        type=str, action="store", required=True)
    parser.add_argument('--teste-r4-p4info', help='teste_r4 p4info file',
                        type=str, action="store", required=True)
    parser.add_argument('--teste-r4-json', help='teste_r4 JSON file',
                        type=str, action="store", required=True)
    args = parser.parse_args()

    # Prepare file dictionaries
    p4info_files = {
        'l2switch': args.l2switch_p4info,
        'label_forwarder': args.label_forwarder_p4info,
        'ingress': args.ingress_p4info,
        'teste_r4': args.teste_r4_p4info
    }
    
    json_files = {
        'l2switch': args.l2switch_json,
        'label_forwarder': args.label_forwarder_json,
        'ingress': args.ingress_json,
        'teste_r4': args.teste_r4_json
    }

    # Validate the provided paths
    for program, path in p4info_files.items():
        if not os.path.exists(path):
            print(f"\n{program} p4info file not found: {path}")
            parser.exit(1)
    
    for program, path in json_files.items():
        if not os.path.exists(path):
            print(f"\n{program} JSON file not found: {path}")
            parser.exit(1)
    
    main(p4info_files, json_files)