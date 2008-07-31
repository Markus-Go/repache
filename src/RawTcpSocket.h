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
 * File: RawTcpSocket.h
 * Purpose: header file for the raw socket class
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#ifndef RAW_TCP_SOCKET_H
#define RAW_TCP_SOCKET_H

#include <string>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> // inet_addr()
#include <arpa/inet.h>

#include "Sniffer.h"
#include "tcpoptions.h"
#include "Requestor.h"

using namespace std;

/**
 * TCP pseudo header for calculating checksum.
 */
struct TcpPseudoHeader {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t proto;
    uint16_t length;
};

/**
 * Encapsulates a TCP socket, in which all fields can be set manually.
 * This also includes the enclosing IP packet, so the source IP address can be
 * manipulated.
 * IMPORTANT: You MUST hav root privileges to use this class!
 */
class RawTcpSocket {

public:
    /**
     * std Ctor initializes empty RawTcpSocket
     */
    RawTcpSocket();
    /**
     * initialize a RawTcpSocket with srcIP/Port and destIP/Port
     * @param srcPort zero means: a random port > 1024 will be used (default)
     */
    RawTcpSocket(string srcIP, string destIP, uint16_t srcPort=0, uint16_t destPort=80);
    /**
     * initialize a RawTcpSocket with the values of a Request
     */
    RawTcpSocket(Request& request);
    /**
     * close eventually established connection and cleanup
     */
    ~RawTcpSocket();

    bool sendConnect(Request& request);
    bool sendRequest(Request& request);
    bool sendAck(Request& request);
    bool sendFin(Request& request);


    /**
     * @return true if there is currently a connection, fals otherwise
     */
    bool isConnected();

    bool close();

    /**
     * print out all settings (ip and tcp struct etc).
     * mainly for debugging purpose.
     */
    void printSettings();

    /**
     * initialize fields of ip and tcp struct properly
     * @return the port number of this socket
     */
    void init(Request& request);
    uint16_t init(string srcIP="", string destIP="", uint16_t srcPort=0, uint16_t destPort=80);

    int rawsock;
private:

    bool connected;
    struct sockaddr_in destAddr;
    unsigned int packetsize;
    unsigned char* packet;
    struct iphdr ip;
    string localIP;
    string remoteIP;
    struct tcphdr tcp;
    uint32_t srcSeq;
    uint32_t ackSeq;

    int tcpOptionsIndex;

    /**
     * just send out a packet (with or without data) without waiting for
     * an ACK
     * @return true if successfully sent, false otherwise
     */
    bool send(unsigned char* data=0, unsigned short length=0);
    /**
     * Compute TCP checksum (from the fields of "this")
     */
    uint16_t tcpChecksum(unsigned char* data=0, unsigned short length=0);
    /**
     * Compute Internet Checksum for "count" bytes beginning at "addr".
     */
    uint16_t checksum(unsigned short *addr, unsigned int count);
};


#endif
