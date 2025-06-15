#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MSLP = 0x88B5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
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
    ethernet_t     ethernet;
    ipv4_t         ipv4;
    label_t[3]     mslp_labels;
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

    state parse_mslp {
        packet.extract(hdr.mslp_labels.next);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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


    action drop() {
        mark_to_drop(standard_metadata);
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

    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4) {
            hdr.ethernet.etherType = TYPE_MSLP;
            //set_tunnel();
            //if (meta.tunnel == 0) {
            //    set_labels_tunnel1();
            //}
            //else {
            //    set_labels_tunnel2();
            //}
            tunnel_label_selector.apply();
            forTunnelMacrewrite.apply();
        }

        //} else {
        //    if (hdr.ipv4.ttl == 0) {
        //        drop();
        //    } 

        else if (hdr.ethernet.etherType == TYPE_MSLP){
            //if (hdr.ipv4.isValid()) {
            hdr.mslp_labels.pop_front(1);
            hdr.ethernet.etherType = TYPE_IPV4;                   
            if (ipv4Lpm.apply().hit) {
                internalMacLookup.apply();
            }
            //} 
            //else {
            //    drop();
            //}
        }
        //}
        else {drop();}

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
    /* The IPv4 Header was changed, it needs new checksum*/
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