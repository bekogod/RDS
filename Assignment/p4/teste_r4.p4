// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MSLP = 0x88B5;
const bit<8>  TYPE_UDP  = 17;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header label_t {
    bit<16> label;
    bit<1>  bos;     // Bottom of Stack bit
    bit<7>  padding; // Padding, we need 8*x bits
}

struct metadata {
    bit<1> tunnel;
    macAddr_t nextHopMac;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    label_t[3]   mslp_labels;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MSLP: parse_mslp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_UDP: udp;
            default: accept;
        }
    }

    state udp {
       packet.extract(hdr.udp);
       transition accept;
    }


    state parse_mslp {
        packet.extract(hdr.mslp_labels.next);
        transition parse_ipv4;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<1> reg_val_one; bit<1> reg_val_two;
    bit<1> direction;
    bit<1> allow_port;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action forward(bit<9>  egressPort, macAddr_t nextHopMac) {
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
        hdr.ethernet.dstAddr = nextHopMac; 
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4Lpm{
        key = {hdr.ipv4.dstAddr : lpm;}
        actions = {
            forward;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    //-----------INGRESS-------------//////

    action rewriteMacsForTunnel(macAddr_t srcAddr, macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = srcAddr;
    }

    table forTunnelMacrewrite {
        key = {standard_metadata.egress_spec: exact;}
        actions = {
            rewriteMacsForTunnel;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    //-----------INGRESS-------------//////



    //-----------EGRESS-------------//////
    action rewriteMacs(macAddr_t srcMac) {
        hdr.ethernet.srcAddr = srcMac;
    }

    table internalMacLookup{
        key = {standard_metadata.egress_spec: exact;}
        actions = { 
            rewriteMacs;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    //-----------EGRESS-------------//////


    //action set_tunnel() {
    //    bit<32> tunnel_hash = hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
    //    meta.tunnel = (bit<1>)(tunnel_hash & 1);
    //}

    action set_labels_tunnel1() {

        hdr.mslp_labels[2] = {0x1010, 1, 0}; 
        hdr.mslp_labels[2].setValid();

        hdr.mslp_labels[1] = {0x2010, 0, 0}; 
        hdr.mslp_labels[1].setValid();

        hdr.mslp_labels[0] = {0x3010, 0, 0};
        hdr.mslp_labels[0].setValid();

        standard_metadata.egress_spec = 3; //porta 2 para sair tunel 1
    }

    action set_labels_tunnel2() {
        
        hdr.mslp_labels[2] = {0x1010, 1, 0}; 
        hdr.mslp_labels[2].setValid();

        hdr.mslp_labels[1] = {0x6010, 0, 0};
        hdr.mslp_labels[1].setValid();

    
        hdr.mslp_labels[0] = {0x5010, 0, 0};
        hdr.mslp_labels[0].setValid();
        
        standard_metadata.egress_spec = 2; //porta 3 para sair tunel 2
    }


    table tunnel_label_selector {
        key = {hdr.ipv4.dstAddr: exact;} //FAKE KEY VAI FALHAR SEMPRE
        actions = {
            set_labels_tunnel1;
            set_labels_tunnel2;
        }
        size = 8;
        default_action = set_labels_tunnel1;
    }
    

    action set_direction(bit<1> dir) {
        direction = dir;
    }

    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action allow_predefined_port() {
        allow_port = 1;
    }

    table allowed_udp_ports {
        key = {
            hdr.udp.dstPort: exact;
        }
        actions = {
            allow_predefined_port;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    apply {
        // Tunnel processing logic first
        if (hdr.ethernet.etherType == TYPE_IPV4) {
            hdr.ethernet.etherType = TYPE_MSLP;
            tunnel_label_selector.apply();
            forTunnelMacrewrite.apply();
        }
        else if (hdr.ethernet.etherType == TYPE_MSLP){
            hdr.mslp_labels.pop_front(1);
            hdr.ethernet.etherType = TYPE_IPV4;                   
            if (ipv4Lpm.apply().hit) {
                internalMacLookup.apply();
            }
        }
        else {
            drop();
            return;
        }

        // Apply firewall logic after tunnel processing
        if (hdr.ipv4.isValid() && hdr.udp.isValid()){
            direction = 0;
            allow_port = 0; 
            if (check_ports.apply().hit) {
                if (direction == 0) {
                    compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort);
                }
                else {
                    compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.udp.dstPort, hdr.udp.srcPort);
                }
                
                if (direction == 0){
                    bloom_filter_1.write(reg_pos_one, 1);
                    bloom_filter_2.write(reg_pos_two, 1);
                }
                else if (direction == 1){
                    allowed_udp_ports.apply();
                    
                    if (allow_port == 0) {
                        bloom_filter_1.read(reg_val_one, reg_pos_one);
                        bloom_filter_2.read(reg_val_two, reg_pos_two);
                        if (reg_val_one != 1 || reg_val_two != 1){
                            drop();
                            return;
                        }
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mslp_labels);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;