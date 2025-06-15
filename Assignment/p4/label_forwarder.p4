#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_MSLP = 0x88B5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header label_t {
    bit<16> label;
    bit<1>  bos;     // Bottom of Stack bit
    bit<7>  padding; // Padding to match ingress.p4
}

struct metadata {
    /* empty for now */
}

struct headers {
    ethernet_t       ethernet;
    label_t[3]       mslp_labels;
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
            TYPE_MSLP: parse_mslp;
            default: accept;
        }
    }

   state parse_mslp {
        packet.extract(hdr.mslp_labels.next);
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

    action pop_and_forward(bit<9> port, macAddr_t dst_mac, macAddr_t src_mac) {
        hdr.mslp_labels.pop_front(1);
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;
        standard_metadata.egress_spec = port; // Set egress port
    }


    table label_forwarding {
        key = {
            hdr.mslp_labels[0].label: exact;  // Match top label
        }
        actions = {
            pop_and_forward;  // Remove label and forward
            drop();  // Drop the packet if label doesn't match
        }
        size = 10;
        default_action = drop();  // Default action is to drop
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_MSLP){
            if (hdr.mslp_labels[0].isValid()) { // Check validity of TOP label
                    label_forwarding.apply();  // Apply label forwarding action
            } else {
                    drop(); // Invalid or empty label stack
            }
        }
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
     apply { } 
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mslp_labels); 
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
