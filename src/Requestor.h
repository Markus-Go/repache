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
 * File: requestor.h
 * Purpose: header file for the requestor
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#ifndef REQUESTOR_H
#define REQUESTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

    // tcp + ip header size: 20 byte each
    // mtu: 1500 byte
    // this leaves 1460 byte for data, in our case a http request 
#define DATA_SIZE 1460

void printStats();

/**
 * the possible state of a TCP connection
 */
enum TcpState { 
    // -- 3 way handshake --
    CLOSED=0,       // no connection
    SYN_SENT,       // initialize 3 way handshake with SYN
    ESTABLISHED,    // rcv: SYN, send: ACK -> 3 way handshake complete
    RST,            // RST received
    // -- passive close --
    CLOSEWAIT,      // after ESTABLISHED, rcv: FIN, send: ACK
    LAST_ACK,       // after CLOSEWAIT, send:FIN, expect ACK
    // -- active close --
    FIN_WAIT_1,     // after ESTABLISHED, s
    CLOSING,        // after FIN_WAIT_1, rcv: FIN, send: ACK (simlt. close)
    FIN_WAIT_2,     // after FIN_WAIT_1, rcv: ACK, expect FIN
    TIME_WAIT       // after FIN_WAIT_2, rcv: FIN, send: ACK
                    // or after CLOSING, rcv: ACK
};

static string stateToString(TcpState state) {
    string out;
    
    switch (state) {
        case CLOSED:
            out = "CLOSED";
            break;
        case SYN_SENT:
            out = "SYN_SENT";
            break;
        case ESTABLISHED:
            out = "ESTABLISHED";
            break;
        case CLOSEWAIT:
            out = "CLOSEWAIT";
            break;
        case LAST_ACK:
            out = "LAST_ACK";
            break;
        case FIN_WAIT_1:
            out = "FIN_WAIT_1";
            break;
        case CLOSING:
            out = "CLOSING";
            break;
        case FIN_WAIT_2:
            out = "FIN_WAIT_2";
            break;
        case TIME_WAIT:
            out = "TIME_WAIT";
            break;
         case RST:
            out = "RST";
            break;   
        default:
            out = "UNDEFINED";
            break;
    }
    
    return out;
}

struct Request;

/**
 * Represents a single request consisting of:
 * - source IP address and
 * - the actual request
 * theRequest may contain more than one line, like for the User-Agent in HTTP.
 */
struct Request {
    uint32_t sIP;
    uint16_t srcPort;
    uint32_t dIP;
    uint16_t destPort;
    uint32_t lastSeq;
    uint32_t lastAck;
    TcpState state;
    time_t timeout;
    int attempts;

    char theReq[DATA_SIZE];

    Request():sIP(0), srcPort(0), dIP(0), destPort(0),
            lastSeq(0), lastAck(0), state(CLOSED), attempts(0) {
        strcpy(theReq, "");
    }
    
    Request(const Request& in) {
        init(in);
    }
    
    Request& operator=(const Request& rhs) {
        init(rhs);
        return *this;
    }
    
    void init(const Request& in) {
        sIP = in.sIP;
        dIP = in.dIP;
        srcPort = in.srcPort;
        destPort = in.destPort;
        strcpy(theReq,in.theReq);
        lastSeq = in.lastSeq;
        lastAck = in.lastAck;
        state = in.state;
        timeout = in.timeout;
        attempts = in.attempts;
    }
    
    void destIP(string ip) {
        dIP = inet_addr(ip.c_str());
    }
    
    string destIP() {
        if (dIP == 0) return "";
        struct in_addr addr;
        addr.s_addr = dIP;
        return inet_ntoa(addr);
    }
    
    void srcIP(string ip) {
        sIP = inet_addr(ip.c_str());
    }
    
    string srcIP() {
        if (sIP == 0) return "";
        struct in_addr addr;
        addr.s_addr = sIP;
        return inet_ntoa(addr);
    }
    
    void theRequest(string req) {
        strcpy(theReq, req.c_str());
    }
    
    string theRequest() {
        string s = theReq; 
        return s;             
    }
    
    Request(const iphdr* ip, const tcphdr* tcp) {
        sIP = ip->saddr;
        dIP= ip->daddr;
        srcPort = ntohs(tcp->source);
        destPort = ntohs(tcp->dest);
        //theRequest = "";
        lastSeq = ntohl(tcp->seq);
        lastAck = ntohl(tcp->ack_seq);
    }

    void print() {
        cout << "\n+-- -- --" << endl;
        cout << "| " << srcIP() << ":" << this->srcPort << " -> ";
        
        cout << destIP() << ":" << this->destPort << endl;
        cout << "| lastSeq: " << this->lastSeq << "  --  lastAck: " << lastAck << endl;
        cout << "| Request: " << this->theReq << endl;
        cout << "| state: " << stateToString(this->state) << endl;
        cout << "+-- -- --\n" << endl;
    }
    
};


/**
 * Creates TCP connections and sends requests to previously defined destination
 */
class Requestor {
public:
    /**
     * Ctor initializes the destination for all future requests. Fields in
     * a Request actually override the fields set inside the Requestor.
     * @param destinationPort default port is www (80)
     * @param sourcePort zero means: a random port > 1024 will be used (default)
     */
    Requestor(string destinationIP="", uint16_t destinationPort=80,
              string sourceIP="", uint16_t sourcePort=0);
    /**
     * cleanup
     */
    ~Requestor();
    /**
     * initialize Sender, Sniffer and Watchdog thread and all datastructures
     * to handle Requests.
     * @return true if successfully initialized, false otherwise
     */
    bool initialize(string statFilename, unsigned short statAvgCount, unsigned short statPeriod, char* device);
    /**
     * sends multiple Requests to the previously defined destination
     */
    bool request(vector<Request>& requests);
    /**
     * issue a single request to the previously define destination
     */
    bool request(Request& request);
    /**
     * Returns the number of successfully sent requests. Multiple from the same
     * IP address count as one!
     * The counter is reset to zero everytime it is read!!!
     */
    unsigned int latelySent();
    /**
     * Returns the number of failed requests. Multiple from the same IP
     * address count as one!
     * The counter is reset to zero everytime it is read!!!
     */
    unsigned int latelyFailed();
    
     /**
     * Returns the number of reset requests. Multiple from the same IP
     * address count as one!
     * The counter is reset to zero everytime it is read!!!
     */
    unsigned int latelyReset();
    
    bool writeStats();
private:
    string srcIP;
    uint16_t srcPort;
    string destIP;
    uint16_t destPort;

    pthread_t sendThreadID;
    pthread_t sniffThreadID;
    pthread_t watchdogThreadID;
    
    string statFilename;
    unsigned short statAvgCount;
    unsigned short statPeriod;
    vector<unsigned int> sentBuffer;
    vector<unsigned int> failedBuffer;
    unsigned short buffersize;
    vector<string> statistics;
};

#endif
