#!/bin/bash

# Run Mininet with the specified behavioral model and JSON configs
sudo python3 mininet/teste-topo.py --behavioral-exe simple_switch_grpc --json1 json/l2switch.json --json2 json/ingress.json --json3 json/label_forwarder.json --json4 json/teste_r4.json --grpc-port 50051