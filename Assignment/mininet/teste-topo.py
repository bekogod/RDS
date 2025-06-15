from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host
from p4runtime_switch import P4RuntimeSwitch


import argparse
from time import sleep


parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default='simple_switch_grpc')
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--json1', help='Path to l2switch JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--json2', help='Path to ingress JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--json3', help='Path to label_forwarder JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--json4', help='Path to teste_r4 JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--grpc-port', help='gRPC server port for controller comm',
                        type=int, action="store", default=50050)


args = parser.parse_args()

# Mininet assigns MAC addresses automatically, but we need to control this process  
# to ensure that the MAC addresses match our network design.  
# This is crucial because the rules we set in the data plane tables must use  
# the exact MAC addresses of the network.

# In Mininet, IP addresses are assigned only to hosts.  
# Any other IP-related tasks, if required, are handled by the controller.


class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, json_path1, json_path2, json_path3, json_path4, thrift_port, grpc_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        
        # In Mininet, we create switches, hosts, and links.  
        # Every network device — whether it's an L2 switch, L3 switch, firewall, or load balancer — is treated as a switch in Mininet.        
        
        # Adding a P4Switch  
        # Refer to the P4Switch class in p4_mininet.py for more details.  

        s1 = self.addSwitch('s1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path1,
                                thrift_port = thrift_port,
                                grpc_port = grpc_port,
                                device_id = 0,
                                cpu_port = 510
                                )
        r1 = self.addSwitch('r1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path2,
                                thrift_port = thrift_port + 1,
                                grpc_port = grpc_port + 1,
                                device_id = 0 + 1,
                                cpu_port = 510 + 1
                                )
                                
        r2 = self.addSwitch('r2',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path3,
                                thrift_port = thrift_port+2,
                                grpc_port = grpc_port + 2,
                                device_id = 0 + 2,
                                cpu_port = 510 + 2
                                )
        r3 = self.addSwitch('r3',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path3,
                                thrift_port = thrift_port + 3,
                                grpc_port = grpc_port + 3,
                                device_id = 0 + 3,
                                cpu_port = 510 + 3
                                )
        r4 = self.addSwitch('r4',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path4,
                                thrift_port = thrift_port + 4,
                                grpc_port = grpc_port + 4,
                                device_id = 0 + 4,
                                cpu_port = 510 + 4
                                )
        r5 = self.addSwitch('r5',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path3,
                                thrift_port = thrift_port + 5,
                                grpc_port = grpc_port + 5,
                                device_id = 0 + 5,
                                cpu_port = 510 + 5
                                )
        r6 = self.addSwitch('r6',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                json_path = json_path3,
                                thrift_port = thrift_port + 6,
                                grpc_port = grpc_port + 6,
                                device_id = 0 + 6,
                                cpu_port = 510 + 6
                                )
        
        # Adding a host with the correct MAC and IP addresses. 
        h1 = self.addHost('h1',
                          ip = "10.0.1.1/24",
                          mac = "aa:00:00:00:00:01") 
        h2 = self.addHost('h2',
                            ip = "10.0.1.2/24",
                            mac = "aa:00:00:00:00:02")
        h3 = self.addHost('h3',
                            ip = "10.0.1.3/24",
                            mac = "aa:00:00:00:00:03")
        h4 = self.addHost('h4',
                            ip = "10.0.2.1/24",
                            mac = "aa:00:00:00:00:04")
        
        
        # Add hosts and links between hosts and the switch
        # For each host, the MAC and IP addresses are dynamically assigned
        # The host will be connected to the switch with a specific MAC address assigned to the port
        self.addLink(h1, s1, port2=1, addr2="cc:00:00:00:01:01")
        self.addLink(h2, s1, port2=2, addr2="cc:00:00:00:01:02")
        self.addLink(h3, s1, port2=3, addr2="cc:00:00:00:01:03")

        
        self.addLink(s1,r1, port1=4, port2=1, addr1="cc:00:00:00:01:04", addr2="aa:00:00:00:01:01")

        self.addLink(r1,r2, port1=2, port2=1, addr1="aa:00:00:00:01:02", addr2="aa:00:00:00:02:01")
        self.addLink(r1,r6, port1=3, port2=1, addr1="aa:00:00:00:01:03", addr2="aa:00:00:00:06:01")

        self.addLink(r2,r3, port1=2, port2=1, addr1="aa:00:00:00:02:02", addr2="aa:00:00:00:03:01")
        self.addLink(r6,r5, port1=2, port2=1, addr1="aa:00:00:00:06:02", addr2="aa:00:00:00:05:01")


        self.addLink(r3,r4, port1=2, port2=3, addr1="aa:00:00:00:03:02", addr2="aa:00:00:00:04:03")
        self.addLink(r5,r4, port1=2, port2=2, addr1="aa:00:00:00:05:02", addr2="aa:00:00:00:04:02")

        self.addLink(h4,r4, port2=1, addr2="aa:00:00:00:04:01")
        
# Main function to set up and run the network
def main():
    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.json1,
                            args.json2,
                            args.json3,
                            args.json4,
                            args.thrift_port,
                            args.grpc_port)

    net = Mininet(topo = topo,
                  host = P4Host,
                  controller = None
                  )

    net.start()

    # Allow time for the host and switch configurations to take effect.
    sleep(1)

    # In this setup, we're not implementing the ARP protocol. Therefore, we manually configure the ARP entry
    # so that host h1 can correctly resolve the MAC address for the gateway when sending packets.

    h1 = net.get('h1')
    h1.setARP("10.0.1.254", "cc:00:00:00:01:01")
    h1.setDefaultRoute("dev eth0 via 10.0.1.254")
    
    #h2
    h2 = net.get('h2')
    h2.setARP("10.0.1.254", "cc:00:00:00:01:02")
    h2.setDefaultRoute("dev eth0 via 10.0.1.254")
    #h3
    h3 = net.get('h3')
    h3.setARP("10.0.1.254", "cc:00:00:00:01:03")
    h3.setDefaultRoute("dev eth0 via 10.0.1.254")
    #h4
    h4 = net.get('h4')
    h4.setARP("10.0.2.254", "aa:00:00:00:04:01")
    h4.setDefaultRoute("dev eth0 via 10.0.2.254")

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()