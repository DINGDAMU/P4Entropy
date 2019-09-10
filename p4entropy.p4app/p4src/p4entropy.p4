#include <core.p4>
#include <v1model.p4>


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    bit<64> nhop_ipv4;
    bit<64> buc_sum;
    bit<64> buc_sumR1;
    bit<64> buc_sumR2;
    bit<64> log_value;
    bit<64> exp_value;
    bit<8>  powerS;
    bit<64> buc_val;
    bit<64> exponent;
    bit<64> bEXP;
    bit<64> power_sum;
    bit<64> decimal;
    bit<64> pow;
    bit<32> h1;
    bit<32> h2;
    bit<32> h3;
    bit<32> h4;
    bit<64> g1;
    bit<64> g2;
    bit<64> g3;
    bit<64> g4;
    bit<64> c1;
    bit<64> c2;
    bit<64> c3;
    bit<64> c4;
    bit<64> median;
    bit<64> m1;
    bit<64> m2;
    bit<64> m3;
    bit<64> m4;
    bit<64> tot;
    bit<64> sum;
    bit<64> log_sum;
    bit<64> log_S;
    bit<64> entropy;

}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}


/*register<bit<64>>(32w3) register_0;*/

register<bit<64>>(32w30) register1;
register<bit<64>>(32w30) register2;
register<bit<64>>(32w30) register3;
register<bit<64>>(32w30) register4;
register<bit<64>>(32w5)  queryResult;
register<bit<64>>(32w1)  SUM;
register<bit<64>>(32w1)  S;
register<bit<64>>(32w4)  finalResults;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
     action do_expES()  {
        meta.exp_value = (bit<64>)(meta.bEXP >> 10);
        meta.pow = (bit<64>)meta.bEXP - (meta.exp_value << 10);
        meta.decimal = meta.decimal + meta.pow;
        meta.decimal = meta.decimal + 64w1024;
        meta.decimal = meta.decimal - (meta.pow * (64w1024 - meta.pow) >> 11);
        meta.decimal = meta.decimal + (((meta.pow * (64w1024 - meta.pow)>>10) * (64w2048 - meta.pow)>>10) * 64w170 >> 10);
        
     }
    @name(".ipv4_forward") action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    action do_logES() {
        meta.buc_val = meta.buc_sum | (meta.buc_sum >> 1);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 2);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 4);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 8);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 16);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 32);
        meta.buc_val = (meta.buc_val & 64w0x5555555555555555) + ((meta.buc_val >> 1) & 64w0x5555555555555555);
        meta.buc_val = (meta.buc_val & 64w0x3333333333333333) + ((meta.buc_val >> 2) & 64w0x3333333333333333);
        meta.buc_val = (meta.buc_val & 64w0xf0f0f0f0f0f0f0f) + ((meta.buc_val >> 4) & 64w0xf0f0f0f0f0f0f0f);
        meta.buc_val = (meta.buc_val & 64w0xff00ff00ff00ff) + ((meta.buc_val >> 8) & 64w0xff00ff00ff00ff);
        meta.buc_val = (meta.buc_val & 64w0xffff0000ffff) + ((meta.buc_val >> 16) & 64w0xffff0000ffff);
        meta.buc_val = (meta.buc_val & 64w0xffffffff) + ((meta.buc_val >> 32) & 64w0xffffffff);
            }
    action do_logES_dec() {

        meta.log_value = (bit<64>)((meta.buc_val - 64w1) << 10);
        meta.buc_sumR1 = meta.buc_sum ^ (meta.buc_sum >> 8w1);
        meta.buc_sumR2 = meta.buc_sum ^ (meta.buc_sum >> 8w2);
        if (meta.buc_sum < meta.buc_sumR1 ){
            if(meta.buc_sum > meta.buc_sumR2){
                meta.log_value = meta.log_value + 64w330;
        }
        }else {
            if (meta.buc_sum < meta.buc_sumR2) {
                meta.log_value = meta.log_value + 64w599;
            }
            else {
                meta.log_value = meta.log_value + 64w827;
            }
        }

    }

    action do_logES_dec2() {

            meta.log_sum = (bit<64>)((meta.buc_val - 64w1) << 10);
           meta.buc_sumR1 = meta.buc_sum ^ (meta.buc_sum >> 8w1);
           meta.buc_sumR2 = meta.buc_sum ^ (meta.buc_sum >> 8w2);
            if (meta.buc_sum < meta.buc_sumR1 ){
                if(meta.buc_sum > meta.buc_sumR2){
                    meta.log_sum = meta.log_sum + 64w330;
                }
            }else {
                if (meta.buc_sum < meta.buc_sumR2) {
                    meta.log_sum = meta.log_sum + 64w599;
                }
            else {
                meta.log_sum = meta.log_sum + 64w827;
            }
        }
        meta.log_sum = meta.log_sum - 10*1024;

    }

   action do_logES_dec3() {
            meta.log_S = (bit<64>)((meta.buc_val - 64w1) << 10);
           meta.buc_sumR1 = meta.buc_sum ^ (meta.buc_sum >> 8w1);
           meta.buc_sumR2 = meta.buc_sum ^ (meta.buc_sum >> 8w2);
            if (meta.buc_sum < meta.buc_sumR1 ){
                if(meta.buc_sum > meta.buc_sumR2){
                    meta.log_S = meta.log_S + 64w330;
                }
            }else {
                if (meta.buc_sum < meta.buc_sumR2) {
                    meta.log_S = meta.log_S + 64w599;
                }
            else {
                meta.log_S = meta.log_S + 64w827;
            }
        }

  
    }

action do_update() {
        hash(meta.h1, HashAlgorithm.xxhash64_1, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)30);
        hash(meta.h2, HashAlgorithm.xxhash64_2, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)30);
        hash(meta.h3, HashAlgorithm.xxhash64_3, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)30);
        hash(meta.h4, HashAlgorithm.xxhash64_4, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)30);
        hash(meta.g1, HashAlgorithm.xxhash64_1, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)2);
        hash(meta.g2, HashAlgorithm.xxhash64_2, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)2);
        hash(meta.g3, HashAlgorithm.xxhash64_3, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)2);
        hash(meta.g4, HashAlgorithm.xxhash64_4, (bit<16>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)2);

        register1.read(meta.c1, (bit<32>)meta.h1);
        register2.read(meta.c2, (bit<32>)meta.h2);
        register3.read(meta.c3, (bit<32>)meta.h3);
        register4.read(meta.c4, (bit<32>)meta.h4);
        meta.g1 =  ((2 * meta.g1) - 1);
        meta.g2 =  ((2 * meta.g2) - 1);
        meta.g3 =  ((2 * meta.g3) - 1);
        meta.g4 =  ((2 * meta.g4) - 1);
        meta.c1 = meta.c1 + meta.g1;
        meta.c2 = meta.c2 + meta.g2;
        meta.c3 = meta.c3 + meta.g3;
        meta.c4 = meta.c4 + meta.g4;
        register1.write((bit<32>)meta.h1, (bit<64>)meta.c1);
        register2.write((bit<32>)meta.h2, (bit<64>)meta.c2);
        register3.write((bit<32>)meta.h3, (bit<64>)meta.c3);
        register4.write((bit<32>)meta.h4, (bit<64>)meta.c4);
        meta.m1 =  meta.c1 * meta.g1;
        meta.m2 =  meta.c2 * meta.g2;
        meta.m3 =  meta.c3 * meta.g3;
        meta.m4 =  meta.c4 * meta.g4;
        queryResult.write(0, meta.m1);
        queryResult.write(1, meta.m2);
        queryResult.write(2, meta.m3);
        queryResult.write(3, meta.m4);
    }
      
    action do_query(){
        if ((meta.m1 <= meta.m2 && meta.m1 <= meta.m3 && meta.m1 <= meta.m4 && meta.m2 >= meta.m3 && meta.m2 >= meta.m4) || (meta.m2 <= meta.m1 && meta.m2 <= meta.m3 && meta.m2 <= meta.m4 && meta.m1 >= meta.m3 && meta.m1 >= meta.m4)){
            meta.median = (meta.m3 + meta.m4) >> 1;
        }
        else if ((meta.m1 <= meta.m2 && meta.m1 <= meta.m3 && meta.m1 <= meta.m4 && meta.m3 >= meta.m2 && meta.m3 >= meta.m4) || (meta.m3 <= meta.m1 && meta.m3 <= meta.m2 && meta.m3 <= meta.m4 && meta.m1 >= meta.m2 && meta.m1 >= meta.m4)){
            meta.median = (meta.m2 + meta.m4) >> 1;
            }
        else if ((meta.m1 <= meta.m2 && meta.m1 <= meta.m3 && meta.m1 <= meta.m4 && meta.m4 >= meta.m2 && meta.m4 >= meta.m3) || (meta.m4 <= meta.m1 && meta.m4 <= meta.m2 && meta.m4 <= meta.m3 && meta.m1 >= meta.m2 && meta.m1 >= meta.m3)){
            meta.median = (meta.m2 + meta.m3) >> 1;
            }
        else if ((meta.m2 <= meta.m1 && meta.m2 <= meta.m3 && meta.m2 <= meta.m4 && meta.m3 >= meta.m1 && meta.m3 >= meta.m4) || (meta.m3 <= meta.m1 && meta.m3 <= meta.m2 && meta.m3 <= meta.m4 && meta.m2 >= meta.m1 && meta.m2 >= meta.m4)){
            meta.median = (meta.m1 + meta.m4) >> 1;
            }
        else if ((meta.m2 <= meta.m1 && meta.m2 <= meta.m3 && meta.m2 <= meta.m4 && meta.m4 >= meta.m1 && meta.m4 >= meta.m3) || (meta.m4 <= meta.m1 && meta.m4 <= meta.m2 && meta.m4 <= meta.m3 && meta.m2 >= meta.m1 && meta.m2 >= meta.m3)){
            meta.median = (meta.m1 + meta.m3) >> 1;
            }
        else{
            meta.median = (meta.m1 + meta.m2) >> 1;
            }

        queryResult.write(4, meta.median);
    }

    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    table update{
        actions = {
            do_update;
        }
    }
    table query{
        actions = {
            do_query;
        }
    }
    table logES{
        actions = {
            do_logES;
        }
    }
    table logES2{
        actions = {
            do_logES;
        }
    }
    table logES3{
        actions = {
            do_logES;
        }
    }
    table logES_dec{
        actions = {
            do_logES_dec;
        }
    }
    table logES_dec2{
        actions = {
            do_logES_dec2;
        }
    }
    table logES_dec3{
        actions = {
            do_logES_dec3;
        }
    }

    table expES{
        actions = {
            do_expES;
        }
    }



    apply {
        ipv4_lpm.apply();
        S.read(meta.tot, 0);
        meta.tot = meta.tot + 64w1;
        S.write(0, meta.tot);
        update.apply();
        query.apply();
        SUM.read(meta.sum, 0);
        meta.buc_sum = meta.median;
        logES.apply();
        logES_dec.apply();
        if  (meta.buc_sum == 2 ){
            meta.sum = meta.sum + meta.log_value + 1024;
/*        }else if (meta.buc_sum > 2 && meta.buc_sum < 6){*/
            /*meta.sum = meta.sum + meta.log_value + 1198;*/
        }else if (meta.buc_sum > 6){
            meta.sum = meta.sum + meta.log_value + 1475;
        }else{
            meta.sum = meta.sum;
        }
        SUM.write(0, meta.sum);
        if (meta.tot >= 10){
           meta.buc_sum = meta.sum;

           logES2.apply();
            logES_dec2.apply();
            finalResults.write(0, meta.log_sum);

            meta.buc_sum = meta.tot;

           logES3.apply();
            logES_dec3.apply();
           finalResults.write(1, meta.log_S);
        if (meta.log_sum > meta.log_S){ 
           meta.exponent = meta.log_sum - meta.log_S;
           meta.bEXP = meta.exponent;
            expES.apply();
         if (meta.exp_value < 8){
                     meta.powerS = (bit<8>)1<< ((bit<8>)meta.exp_value);
                     meta.power_sum = (bit<64>)meta.powerS;
                 }else if (meta.exp_value < 16 ){
                     meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 8);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<8);
                 }else if (meta.exp_value < 24 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 16);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<16);
                 }else if (meta.exp_value < 32 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 24);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<24);
                 }else if (meta.exp_value < 40 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 32);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<32);
                 }else if (meta.exp_value < 48 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 40);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<40);
                 }else if (meta.exp_value < 56 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 48);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<48);
                 }else{
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 56);
                     meta.power_sum = (bit<64>)meta.powerS * (1<<56);
                 }
         
                meta.power_sum = (meta.power_sum) * meta.decimal;
            finalResults.write(2, meta.power_sum);
            meta.entropy = (meta.log_S - (meta.power_sum));

            finalResults.write(3, meta.entropy);
    
           }else{
                meta.entropy = meta.log_S;
           }

                       
           }
}
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

