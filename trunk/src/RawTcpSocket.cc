/*
 * Copyright 2007-2008 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz
 *
 * You may not use this file except under the terms of the accompanying license.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Project: repache
 * File: RawTcpSocket.cc
 * Purpose: socket for sending raw packets
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#include "RawTcpSocket.h"

RawTcpSocket::RawTcpSocket() {

    timeval realTime;
    gettimeofday(&realTime, 0);
    srandom((unsigned)realTime.tv_sec * 42  + realTime.tv_usec);

    // IP RAW Socket Descriptor
    if( (rawsock = socket(PF_INET, SOCK_RAW, 6) ) == -1 ) {
        perror("could not create socket");
        exit(1);
    }

    // IP_HDRINCL must be enabled, otherwise the Kernel will fill all the
    // interesting fields...
    int one = 1;
    if( setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1 ) {
        perror("could not set socket options");
        exit(1);
    }
}


void RawTcpSocket::init(Request& request) {
    request.srcPort = init(request.srcIP(), request.destIP(), request.srcPort, request.destPort);
}

uint16_t RawTcpSocket::init(string srcIP, string destIP, uint16_t srcPort, uint16_t destPort) {


    localIP = srcIP;
    remoteIP = destIP;
    connected = false;
    packet = 0;
    packetsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    srcSeq = 0;
    ackSeq = 0;
    // start with clean IP and TCP headers
    memset(&ip, 0, sizeof(struct iphdr));
    memset(&tcp, 0, sizeof(struct tcphdr));

    // choose arbitrary port (> 1024 && < 65535) if none set
    if(srcPort == 0) {
        extern u_int16_t MIN_PORT;
        extern u_int16_t MAX_PORT;
        srcPort = (random() % (MAX_PORT-MIN_PORT)) + MIN_PORT;
//        srcPort = (random() % 64510) + 1024;
    }

    // assamble IP Header
    ip.version = 4;
    ip.ihl = 5; // Header Length (in 32-bit words)
    ip.tos = IPTOS_TOS(IPTOS_LOWDELAY | IPTOS_RELIABILITY); //Type Of Service
    ip.tot_len = htons(60); // TOTal LENgth of TCP/IP packet (init without data)
    ip.id = htons(random()); // IP ID
    //ip.frag_off = 0; // FRAGment OFFset
    ip.ttl = random() % 250 + 5; // Time to live
    ip.protocol = IPPROTO_TCP; // Transport Protocol TCP (6)
    //ip.check = 0; // IP Checksum (kernel will do it if we set it to zero!)
    ip.saddr = inet_addr(localIP.c_str()); // Source IP
    ip.daddr = inet_addr(remoteIP.c_str()); // Destination IP

    // assemble TCP Header
    tcp.source = htons(srcPort); // Source Port
    tcp.dest = htons(destPort); // Destination Port
    //tcp.seq = htonl(0); // Sequence number
    //tcp.ack_seq = htonl(0); // Acknowledgement number
    tcp.doff = 5; // data offset <=> header length
    // -- TCP Flags --
    //tcp.urg = 0; // URGent
    tcp.ack = 0; // ACKnowledge
    //tcp.psh = 0; //PuSH
    //tcp.rst = 0; //ReSeT
    tcp.syn = 0; // SYNchronize
    tcp.fin = 0; //FINish
    tcp.window = htons(1024); // Window size
    //tcp.check = htons(0); // init CHECKsum with zero for calculating correctly later

    return srcPort;
}

RawTcpSocket::~RawTcpSocket() {
    //if(connected)
    ::close(rawsock);
    if(packet != 0) delete[] packet;
}

bool RawTcpSocket::sendConnect(Request& request) {

    srcSeq = request.lastSeq;
    tcp.syn = 1;
    tcp.ack = 0;
    send();

    return true;
}


bool RawTcpSocket::sendAck(Request& request) {

    srcSeq = request.lastSeq;
    ackSeq = request.lastAck;
    tcp.ack = 1;
    send();

    return true;
}

bool RawTcpSocket::sendRequest(Request& request) {

    srcSeq = request.lastSeq;
    ackSeq = request.lastAck;
    tcp.ack = 1;
    send((unsigned char*) request.theRequest().c_str(), request.theRequest().length());

    return true;
}

bool RawTcpSocket::sendFin(Request& request) {

    srcSeq = request.lastSeq;
    ackSeq = request.lastAck;
    tcp.ack = 1;
    tcp.fin = 1;
    send();

    return true;
}


bool RawTcpSocket::close() {
    if(!connected) return true;

    tcp.fin = 1;
    tcp.ack = 1;
    send();
    tcp.fin = 0;

    return true;
}

bool RawTcpSocket::send(unsigned char* data, unsigned short length) {

    extern TcpOption tcpOptions[];

    // -- currently tcp options only in syn packets --
    if(!tcp.syn) {
        tcpOptionsIndex = -1;
        ip.tot_len = htons(40);
        tcp.doff = 5;
    } else {
        tcpOptionsIndex = randTcpOptionsIndex(tcpOptions);
        ip.tot_len = htons(40 + tcpOptions[tcpOptionsIndex].length);
        tcp.doff = 5 + (tcpOptions[tcpOptionsIndex].length / 4);
    }

    unsigned short hdrLen = ip.ihl*4 + tcp.doff*4;

    //-- allocate packet to send --
    packetsize = hdrLen;
    // we must not use tcp packets of odd length!
    unsigned short padding = 0;
    if(length > 0 && data != 0) {
        padding = (length%2 == 1) ? 1 : 0;
        packetsize += length + padding;
    }
    if(packet != 0) delete[] packet;
    packet = new unsigned char[packetsize];

    //-- set remaining header fields
    ip.tot_len = htons(packetsize);
    if(srcSeq == 0) srcSeq = random();
    tcp.seq = htonl(srcSeq);
    tcp.ack_seq = htonl(ackSeq);
    // checksum is the last action on a TCP/IP packet!
    tcp.check = tcpChecksum(data, length + padding);

    //-- copy headers and evtl data --
    memcpy(packet, &ip, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &tcp, sizeof(struct tcphdr));

    if(tcpOptionsIndex >= 0) { // only if options were set
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
                tcpOptions[tcpOptionsIndex].options, tcpOptions[tcpOptionsIndex].length);
    }

    if(packetsize > hdrLen) memcpy(packet + hdrLen, data, length+padding);

    //-- actually send the packet --
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = tcp.dest;
    destAddr.sin_addr.s_addr = ip.daddr;
    size_t bytesSent = sendto(rawsock, packet, packetsize, 0, (struct sockaddr*)&destAddr,
         sizeof(struct sockaddr_in));
    if( bytesSent == -1 ) {
        cout << "########################## ERROR ##########################\n";
        perror("could not send");
	printf("%s %d\n", inet_ntoa(destAddr.sin_addr), packetsize);
        return false;
    }

    if(bytesSent < packetsize)
        cout << "########################## ERROR ##########################\n";


    return true;
}

void RawTcpSocket::printSettings() {
    printf("--IP--\n");
    printf("Version: %d\n", ip.version);
    printf("Header: %d\n", ip.ihl);
    printf("TOS: %d\n", ip.tos);
    printf("Total: %d\n", ntohs(ip.tot_len));
    printf("ID: %d\n", ntohs(ip.id));
    printf("TTL: %d\n", ip.ttl);
    printf("Protcol: %d\n", ip.protocol);
    printf("Checksum: 0x%x\n", ip.check);
    struct in_addr iaddr;
    iaddr.s_addr = ip.saddr;
    printf("SourceIP: %s\n", inet_ntoa(iaddr));
    iaddr.s_addr = ip.daddr;
    printf("DestIP: %s\n", inet_ntoa(iaddr));
    printf("--TCP--\n");
    printf("SrcPort: %d\n", ntohs(tcp.source));
    printf("DestPort: %d\n", ntohs(tcp.dest));
    printf("Seq#: %ul\n", ntohl(tcp.seq));
    printf("Ack#: %ul\n", ntohl(tcp.ack_seq));
    printf("DataOffset: %d\n", tcp.doff);
    printf("URG: %d\n", tcp.urg);
    printf("ACK: %d\n", tcp.ack);
    printf("PSH: %d\n", tcp.psh);
    printf("RST: %d\n", tcp.rst);
    printf("SYN: %d\n", tcp.syn);
    printf("FIN: %d\n", tcp.fin);
    printf("Window: %d\n", ntohs(tcp.window));
    printf("Checksum: 0x%x\n", tcp.check);
}

uint16_t RawTcpSocket::checksum(unsigned short *addr, unsigned int count) {
    register long sum = 0;
    while( count > 1 )  {
        sum += * addr++;
        count -= 2;
    }
    /*  Add left-over byte, if any */
    if( count > 0 ) sum += * (unsigned char *) addr;
    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16) sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


uint16_t RawTcpSocket::tcpChecksum(unsigned char* data, unsigned short length) {
    TcpPseudoHeader pseudohead;
    extern TcpOption tcpOptions[];

    uint16_t total_len = ntohs(ip.tot_len);

    //printf("total_len: %d\n", total_len);

    // tcp.check MUST be zero for calculating the checksum!
    tcp.check = 0;

    int tcpopt_len = tcp.doff*4 - sizeof(struct tcphdr);
    int tcpdatalen = total_len - (tcp.doff*4) - (ip.ihl*4);
    //printf("datalen=%d\n",tcpdatalen);
    pseudohead.src_addr = ip.saddr;
    pseudohead.dst_addr = ip.daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr) + tcpopt_len + tcpdatalen);

    unsigned int totaltcp_len = sizeof(struct TcpPseudoHeader) + sizeof(struct tcphdr) + tcpopt_len + tcpdatalen;

    unsigned short * total = new unsigned short[totaltcp_len];

    memcpy((unsigned char *)total, &pseudohead, sizeof(struct TcpPseudoHeader));
    memcpy((unsigned char *)total + sizeof(struct TcpPseudoHeader), (unsigned char *)&tcp, sizeof(struct tcphdr));

//    memcpy((unsigned char *)total + sizeof(struct TcpPseudoHeader) + sizeof(struct tcphdr), (unsigned char *) &tcp + (sizeof(struct tcphdr)), tcpopt_len);
    if(tcpopt_len > 0) {
        memcpy((unsigned char *)total + sizeof(struct TcpPseudoHeader) + sizeof(struct tcphdr),
                tcpOptions[tcpOptionsIndex].options, tcpopt_len);
    }

    if(length > 0 && data != 0) memcpy((unsigned char *)total + sizeof(struct TcpPseudoHeader) + sizeof(struct tcphdr) + tcpopt_len, data, length);
    /*
    printf("pseud length: %d\n",ntohs(pseudohead.length));
    printf("tcp hdr length: %d\n",tcp->doff*4);
    printf("tcp hdr struct length: %d\n",sizeof(struct tcphdr));
    printf("tcp opt length: %d\n",tcpopt_len);
    printf("tcp total+psuedo length: %d\n",totaltcp_len);
    fflush(stdout);
    if (tcpdatalen > 0)
    printf("tcp data len: %d, data start %u\n", tcpdatalen,tcp + (tcp->doff*4));
    */

    uint16_t sum = checksum(total, totaltcp_len);

    delete[] total;
    return sum;
}


