#!/bin/bash

python3 controller/assignment-controller.py   --l2switch-p4info json/l2switch.p4info.txt   --l2switch-json json/l2switch.json   --label-forwarder-p4info json/label_forwarder.p4info.txt   --label-forwarder-json json/label_forwarder.json   --ingress-p4info json/ingress.p4info.txt   --ingress-json json/ingress.json   --teste-r4-p4info json/teste_r4.p4info.txt   --teste-r4-json json/teste_r4.json
