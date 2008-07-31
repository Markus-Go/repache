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
 * File: sniffer.h
 * Purpose: header file for the sniffer
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

/**
 * @brief Sniffs the network for packets.
 * You can specify a host and port as a filter to reduce traffic
 * and then access the respective fields of the TCP/IP header to see
 * if this is the packet you had been waiting for.
 */
class Sniffer {

public:
    /**
     * Ctor creates a sniffer with a filter on a specified interface or
     * on the default interface if none specified.
     */
    Sniffer(string filter, string interface = "");
    ~Sniffer();
    /**
     * indicates whether the Sniffer could be initialized correctly or not
     */
    inline bool isOK() { return ok; }
    /**
     * sniff indefinitely and pass all incoming packets to tcpIpCallback
     */
    void sniff(pcap_handler onReceive);
    /**
     * sniff for the sequence number of an incoming packet that acknowledges
     * a previously sent packet.
     * @param expectedACK the ACK we expect for our currently sent packet
     * @param limit a limit of packets to sniff if no match is found
     *
     * @return the seq of the ACK packet we expect, 0 if no ACK arrived
     */
    uint32_t sniffSeq(uint32_t expectedACK, unsigned short limit);

private:
    bool ok;
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* The compiled filter */
    bpf_u_int32 mask;               /* Our netmask */
    bpf_u_int32 net;                /* Our IP */
};

#endif
