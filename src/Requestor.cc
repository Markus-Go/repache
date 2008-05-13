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
 * File: requestor.cc 
 * Purpose: the requestor 
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#include "Requestor.h"

#include <pthread.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <cstdio>
#include <set>
#include <map>
#include <queue>
#include <sys/time.h>
#include <unistd.h>

#include "RawTcpSocket.h"
#include "Sniffer.h"

using namespace std;

/** value type for the reveiveQ map */
typedef map<uint32_t, Request>::value_type rcvQValType;
/** iterator type for the receiveQ map */
typedef map<uint32_t, Request>::iterator rcvQIterator;

/** mutex to protect the set of successfully sent requests */
pthread_mutex_t sentLock = PTHREAD_MUTEX_INITIALIZER;
/** mutex to protect the set of failed requests */
pthread_mutex_t failedLock = PTHREAD_MUTEX_INITIALIZER;
/** a set of successfully sent requests, protected by sentLock */
set<unsigned long int> sentRequests;
/** a set of failed requests, protected by failedLock */
set<unsigned long int> failedRequests;

/** mutex to protect the queue of Requests to send */
pthread_mutex_t sendQLock = PTHREAD_MUTEX_INITIALIZER;
/** mutex to protect the queue/set of Requests to receive/handle */
pthread_mutex_t rcvQLock = PTHREAD_MUTEX_INITIALIZER;
/** a queue with all Requests for which there is something to send */
vector<Request> sendQ;
/** a Set with all Requests for which there is something to receive */
map<uint32_t, Request> receiveQ;


/** the destination IP for all Requests */
string DESTINATION_IP = "";
/** wait this time for an answer (in seconds) */
static const int TIMEOUT = 3;
/** max number of attempts to send*/ 
static const int ATTEMPTS = 3;


char* eth_device = NULL;
unsigned long int okCnt = 0;
unsigned long int failedCnt = 0;
unsigned long int rstCnt = 0;

void printStats()
{
    cout << "\x1b[32mok: " << okCnt << "\t\x1b[31mfailed: " << failedCnt << "\x1b[0m" << endl;
}

/**
 * runs a command on the shell without catching any output.
 * only the exit code of the command is of interest.
 *
 * @param command the command to execute
 * @param silent if true (default) all output of the command is piped
 *               to /dev/null, otherwise it will show up on the shell
 * @return false if command failed, true otherwise
 */
bool run(string command, bool silent=true) {
    int retval = -1;
    string commandString = command;
    if (silent) commandString += " &> /dev/null";
    retval = system(commandString.c_str());
    if (retval != 0) {
        cerr << "FAILED: " << command << endl;
        return false;
    }
    return true;
}


void receiveQInsert(rcvQValType val) {
//    cout << "[RCVQ] Expecting: " << val.first << endl;
//    val.second.print();
    val.second.timeout = time(NULL) + TIMEOUT;
    pthread_mutex_lock(&rcvQLock);
    if(receiveQ.find(val.first) == receiveQ.end()) {
        receiveQ.insert(val);
    } else {
        cerr << "[RCVQ] a packet with same Seq already exists!!!" << endl;
        val.second.print();
    }
    pthread_mutex_unlock(&rcvQLock);
}

void success(Request& request)
{
    okCnt++;
/*    pthread_mutex_lock(&sentLock);
    sentRequests.insert(inet_addr(request.srcIP.c_str()));

    //fprintf(stderr,"%s\n",request->srcIP.c_str());

    pthread_mutex_unlock(&sentLock);*/
}

void resetC(Request& request){
    rstCnt++;
}    

void failed(Request& request) {
//    cout << "[DBG] Request failed:" << endl;
//    request.print();
    failedCnt++;
/*    pthread_mutex_lock(&failedLock);
    if(failedRequests.insert(inet_addr(request.srcIP.c_str())).second) {
	//printf("%s\n",request->srcIP.c_str());
    }
    pthread_mutex_unlock(&failedLock);*/
}

/**
 * this thread is responsible for reading all requests from the sendQ
 * and sending them.
 */
void* sendThread(void* arg) {
    // the Requests currently to be sent
    vector<Request> reqs;
    RawTcpSocket* socket = new RawTcpSocket();
       
    while(true) {
        pthread_mutex_lock(&sendQLock);
        // take over all Requests if there are some
        if(sendQ.size() > 0) {
            reqs = vector<Request>(sendQ);
            sendQ.clear();
        }
        pthread_mutex_unlock(&sendQLock);

        timespec delay;
        delay.tv_sec = 0;
        delay.tv_nsec = 1;
        // only go on if there is something to send
        if(reqs.size() == 0)
        {
            //nanosleep(&delay, NULL);
            continue;
        }


        // -- for each request --
        for(vector<Request>::iterator i = reqs.begin(); i != reqs.end(); i++) {
//            cout << "[SEND] sending packet: " << endl;
//            i->print();
//            socket->printSettings();
            socket->init(*i);
            //i->print();
            // length needed for actual request data
            unsigned short length = 0;
            switch (i->state) {
                case RST:
                    //start 3 way handshake again...
                    //same as CLOSED
                    i->state = SYN_SENT;
                    i->lastSeq = random();
                    i->srcPort = 0;
                    receiveQInsert(rcvQValType(i->lastSeq + 1, *i));
                    socket->sendConnect(*i);
                    break;
                case CLOSED:
                    i->state = SYN_SENT;
                    // -- create new random sequence number --
                    i->lastSeq = random();
                    // -- add current Request to receiveQ --
//                    cout << "[SEND] Expecting ACK for: " << endl;
//                    i->print();
                    receiveQInsert(rcvQValType(i->lastSeq + 1, *i));
                    // -- actually send the connect (SYN) packet --
                    socket->sendConnect(*i);
                    // cout << "sending connect" << endl;
                    break;
                case SYN_SENT:
                    // -- complete handshake and send actual (HTTP) request --
                    socket->sendAck(*i);
                    i->state = ESTABLISHED;
                    
                    //check length; if length > DATA_SIZE split the request into 2 packets
                    length = i->theRequest().length();                   
                    if(length > DATA_SIZE){
                        Request r;
                        uint16_t new_length = 0;
                        uint16_t n = length/DATA_SIZE;
                        uint32_t read = 0;
                        uint32_t seq = i->lastSeq;
                        //cout << "SEQ: " << seq << endl; 
                        for(int j=0; j<=n; j++){
                            string s("");
                            if(DATA_SIZE*j > length){
                                read = length%DATA_SIZE;
                            }else {
                                read = DATA_SIZE;
                            } 
                            seq += read;    
                            s = i->theRequest().substr(DATA_SIZE*j,read);
                            r.sIP = i->sIP;
                            r.srcPort = i->srcPort;
                            r.dIP = i->dIP;
                            r.lastAck = i->lastAck;
                            r.destPort = i->destPort;
                            r.theRequest(s);
                            r.state = i->state; 
                            r.lastSeq = seq;
                            
                            r.print();
                              
                            // no odd length of data allowed
                            new_length = r.theRequest().length();
                            new_length += (new_length%2 == 1) ? 1 : 0;
                            receiveQInsert(rcvQValType(seq, r));
                            socket->sendRequest(r);                          
                        }             
                    } else {
                    // no odd length of data allowed!
//                        cout << i->theRequest() << endl;                    
                        length += (length%2 == 1) ? 1 : 0;
                        receiveQInsert(rcvQValType(i->lastSeq + length, *i));
                        //usleep(1);
                        socket->sendRequest(*i);
                    }
                    break;
                case ESTABLISHED:
                    // -- send dummy ACKS for incoming data --
                    //i->rcvd = 0; // reset count for sliding window
                    socket->sendAck(*i);
                    break;
                case CLOSEWAIT:
                    i->state = LAST_ACK;
                    receiveQInsert(rcvQValType(i->lastSeq + 1, *i));
                    // -- send FIN and ACK in one packet --
                    // --> we actually skip the official CLOSEWAIT
                    socket->sendFin(*i);
                    break;
                case FIN_WAIT_1:
                    receiveQInsert(rcvQValType(i->lastSeq + 1, *i));
                    socket->sendFin(*i);
                    break;
                case FIN_WAIT_2:
                    socket->sendAck(*i);
                    success(*i);
                    break;
                default:
                    cerr << "[SEND] request in undefined state: " << i->state << endl;
                    break;
            } 
        }
        // don't forget to clean up!
        reqs.clear();
    }
    delete socket;
    pthread_exit(NULL);
}


/**
 * this method is called for every incoming packet
 */
void onReceive(u_char* args, const struct pcap_pkthdr* hdr, const u_char* packet) {
    const iphdr* ip;
    const tcphdr* tcp;
    Request request; 

    // cast the sniffed packet to TCP/IP
    ip = (const iphdr*) (packet + sizeof(struct ether_header));
    tcp = (const tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    
    // -- check if we are responsible for this packet --
    extern u_int16_t MIN_PORT;
    extern u_int16_t MAX_PORT;
    u_int16_t origSrcPort = ntohs(tcp->dest);
    if(origSrcPort < MIN_PORT || origSrcPort > MAX_PORT) {
        return;
    }
    
//    char* data = (char*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
      
    if(tcp->rst)
        cerr << "got reset. HELP!!!\n";
        
//    if(tcp->fin)
//        cout << "got fin\n";

      
    // -- see if we sent a Seq matching this Ack --
    uint32_t incomingAck = ntohl(tcp->ack_seq);
    //cout << "incomingAck: " << incomingAck << endl;
    uint32_t originalSeq = incomingAck;
    pthread_mutex_lock(&rcvQLock);
    rcvQIterator match = receiveQ.find(originalSeq);
    if(match != receiveQ.end()) {
        // -- copy the match and erase it from the receiveQ --
        request = match->second;
        receiveQ.erase(match);
//        cout << "\t\t\t\t\tmatch!" << endl;
//        request.print();
    }
    pthread_mutex_unlock(&rcvQLock);

    // -- break if no match was found --
    if(request.lastSeq == 0) {
//        cout << "\t!!! received unexpected packet:" << endl;
//        Request unexpected(ip, tcp);
//        unexpected.print();
        return;
    }

    // -- verify that packet is really for the right IP --
    if (ip->daddr != request.sIP) {
        struct in_addr iaddr;
        iaddr.s_addr = ip->daddr;
        cout << "[SNIFF] received packet for wrong IP: " << inet_ntoa(iaddr) << endl;
        cout << "[SNIFF] expected:" << endl;
        request.print();
        return;
    }

    
/*    if(request.attempts > 0) {
//        cout << "attempts "  << request.attempts << endl;
        request.attempts = 0;
    }*/
    
    // -- handle the incoming packet according to the status of the Request --
    
    
    
    
    //cout << "[SNIFF] rcv in state " << stateToString(request.state) << endl; 
//    cout << "[SNIFF] received packet:" << endl;
//    Request rcvd(ip, tcp);
//    rcvd.print();
//    if(tcp->fin != 0 && request.state != ESTABLISHED)
//        cout << "[SNIFF] FIN in state: " << stateToString(request.state) << endl;
    switch (request.state) {
        case RST: //second RST in a row. we will break the connection and not try again. ever.
            if (tcp->rst){
                cerr << "[SNIFF] RST received! Second in a row. We will not try to establish the connection again." << endl;
                request.print();
                return;
            } else if ((tcp->ack != 1) || (tcp->syn != 1)) {
                cerr << "[SNIFF] handshake failed!" << endl;
                request.print();
                return; 
            } else //we got an ack, so we can change to SYN_SENT an continue from there 
                request.state = SYN_SENT;   
            break;
        case CLOSED:
            cerr << "[SNIFF] received packet in wrong state: CLOSED" << endl;
            request.print();
            return;
            break;
        case SYN_SENT:
            if ((tcp->ack != 1) || (tcp->syn != 1)) {
                cerr << "[SNIFF] handshake failed!" << endl;
                request.print();
                return; 
            }
            // -- stay in SYN_SENT, switch to ESTABLISHED after sending ACK --
            break;
        case ESTABLISHED: 
            // can reset occur in this state? 
            // either way we set state to RST and have to start 3 way handshake again
            if (tcp->rst){ 
                cerr << "[SNIFF] RST received!" << endl;
                request.print();
                resetC(request);
                request.state = RST;
            } else if (tcp->fin != 0) {
                // -- go already to CLOSEWAIT on FIN, send ACK as next packet -- 
//                cout << "[SNIFF] received FIN for: " << endl;
//                request.print();
                request.state = CLOSEWAIT;
            } else {
                // go and read more
                //request.rcvd = 0; // reset count for sliding window
                receiveQInsert(rcvQValType(ntohl(tcp->ack_seq), request));
            }
            break;
        case LAST_ACK:
            // -- now this is what I call a complete request ! --
            success(request);
            return;
        case FIN_WAIT_1:
//            cout << "[SNIFF] in FIN_WAIT_1: " << endl;
//            cout << "FIN: " << tcp->fin << endl;
            
            // can reset occur in this state? 
            // either way we set state to RST and have to start 3 way handshake again
            if (tcp->rst){ 
                cerr << "[SNIFF] RST received!" << endl;
                request.print();
                resetC(request);
                request.state = RST;
            } else if(tcp->fin != 0) {
                request.state = FIN_WAIT_2;
            } else {
                receiveQInsert(rcvQValType(ntohl(tcp->ack_seq), request));
                return;
            }
            break;
        case CLOSING:
    
            break;
        case FIN_WAIT_2:
    
            break;
        case TIME_WAIT:
    
            break;
        default:
            cerr << "[SNIFF] request in undefined state: " << request.state << endl;
            break;
    } 
    
    // -- set lastAck of this Request to what the next expected ACK is --
    int acked = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
    if(tcp->fin || tcp->syn)
        acked++;
    
    request.lastAck = ntohl(tcp->seq) + acked;
    
    
    // -- set lastSeq of this Request to what the target expects next --
    if (tcp->ack != 0) request.lastSeq = ntohl(tcp->ack_seq);
    else cout << "[SNIFF] no ACK" << endl;

    if(acked > 0) {
        // -- add Request to SendQ --
        pthread_mutex_lock(&sendQLock);
            sendQ.push_back(request);
        pthread_mutex_unlock(&sendQLock);
    }
}


/**
 * this thread is responsible for sniffing all relevant incoming packets
 * and handle them according to the "open" Requests in the receiveQ
 */
void* sniffThread(void* arg) {
    string filter = "tcp and src host ";
    filter += DESTINATION_IP;
    //printf("-------> %s\n",eth_device);
    //Sniffer sniffer(filter, "eth1");
    
    Sniffer sniffer(filter, eth_device);

    if(sniffer.isOK()) {
        cout << "starting to sniff" << endl;
        sniffer.sniff(onReceive);
    } else {
        cerr << "could not initialize Sniffer!" << endl;
        exit(-1);
    }

    cout << "sniffing stopped" << endl;

    pthread_exit(NULL);
}

/**
 * this thread is responsible for finding Requests that are timed out
 */
void* watchdogThread(void* arg) {
     
    queue<uint32_t> deleteQ;
    queue<uint32_t> retryQ;
    while(true) {
        sleep(1);
        time_t now = time(NULL);
        
        pthread_mutex_lock(&rcvQLock);
        
        for(rcvQIterator i = receiveQ.begin(); i != receiveQ.end(); i++) {
            if( now > i->second.timeout ) {
                i->second.attempts++;
//                cout << "\x1b[31mprobably packet lost...";
                if(i->second.attempts < ATTEMPTS) {
//                    cout << "retry packet: " << endl;
//                    i->second.print();
                    switch(i->second.state) {
                        case (SYN_SENT):
                            if(i->second.attempts < (ATTEMPTS / 2)) {
                                // -- guess our ACK and request was lost --
                                i->second.timeout += 1;
                                pthread_mutex_lock(&sendQLock);
                                sendQ.push_back(Request(i->second));
                                pthread_mutex_unlock(&sendQLock);
                            } else {
                                // -- guess our SYN was lost --
                                i->second.state = CLOSED;
                                retryQ.push(i->first);
                            }
                            break;
                        case (ESTABLISHED):
                            if(i->second.attempts < (ATTEMPTS / 2)) {
                                // -- guess a simple ACK of us was lost --
        //                        cout << "retry ACK" << endl;
                                i->second.timeout += 1;
                                pthread_mutex_lock(&sendQLock);
                                sendQ.push_back(Request(i->second));
                                pthread_mutex_unlock(&sendQLock);
                            } else {
                                // -- guess we missed the FIN -> active close --
        //                        cout << "guess FIN" << endl;
                                i->second.state = FIN_WAIT_1;
                                retryQ.push(i->first);
                            }
                            break;
                    }
                        
/*                    if(i->second.attempts == ATTEMPTS - 1) {
                        // -- guess we missed the FIN --
                        deleteQ.push(i->first);
                        i->second.state = CLOSEWAIT;
                        //i->second.lastSeq++;
                    } else {
                        // -- add request to retry queue
                        retryQ.push(i->first);
                    }*/
                } else {
//                    cout << "give up\x1b[0m\n";
//                    cout << i->second.theRequest << endl;
                    failed(i->second);
                    deleteQ.push(i->first);
                }
            }
        }
        

        while(!retryQ.empty()) {
            // -- send  --
//            cout << "[WATCHD] try again" << endl;
            Request retry = receiveQ[retryQ.front()];
            receiveQ.erase(retryQ.front());
            pthread_mutex_lock(&sendQLock);
            sendQ.push_back(retry);
            pthread_mutex_unlock(&sendQLock);
            retryQ.pop();
        }

        while(!deleteQ.empty()) {
            receiveQ.erase(deleteQ.front());
            deleteQ.pop();
        }
        
        pthread_mutex_unlock(&rcvQLock);
    }

    pthread_exit(NULL);
}


Requestor::Requestor(string destinationIP, uint16_t destinationPort,
                     string sourceIP, uint16_t sourcePort) {
    srcIP = sourceIP;
    srcPort = sourcePort;
    destIP = destinationIP;
    destPort = destinationPort;
    DESTINATION_IP = destinationIP;
}

Requestor::~Requestor() {
    pthread_cancel(sendThreadID);
    pthread_cancel(sniffThreadID);
    pthread_cancel(watchdogThreadID);
}

bool Requestor::initialize(string statFilename, unsigned short statAvgCount, unsigned short statPeriod, char* device) {
    
    this->statFilename = statFilename;
    this->statAvgCount = statAvgCount;
    this->statPeriod = statPeriod;
    eth_device = device;

    char entry[50];
    sprintf(entry, " 0.00 0.00 0.00");

    string tmpStatFilename = statFilename + "tmp";
    ofstream statFile(tmpStatFilename.c_str());
    if(statFile.good())
    {
        for(unsigned short j = 1; j <= statPeriod; ++j) {
            statistics.push_back(entry);
            statFile << (-statPeriod+j) << entry << endl;
        }
        statFile.close();
        string runMe = "mv " + tmpStatFilename + " " + statFilename;
        run(runMe);
    }

    
    int retval = 0;
    pthread_attr_t attr;
    

    retval = pthread_attr_init(&attr);
    if (retval != 0) printf("pthread_attr_init failed: %d", retval);
    retval = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (retval != 0) printf("pthread_attr_setdetachstate failed: %d", retval);
    // -- 1. start sniff thread --
    retval = pthread_create(&sniffThreadID, &attr, sniffThread, (void *)NULL);
    if (retval != 0) {
        cout << "failed creating sniffThread: " << retval << endl;
        return false;
    }
    // -- wait to make give Sniffer enough time to initialize! --
    //usleep(10000);
    sleep(1);
    // -- 2. start send thread --
    retval = pthread_create(&sendThreadID, &attr, sendThread, (void *)NULL);
    if (retval != 0) {
        cout << "failed creating sendThread: " << retval << endl;
        return false;
    }
    // -- 3. start watchdog thread --
    retval = pthread_create(&watchdogThreadID, &attr, watchdogThread, (void *)NULL);
    if (retval != 0) {
        cout << "failed creating watchdogThread: " << retval << endl;
        return false;
    }
    pthread_attr_destroy(&attr);

    return true;
}

bool Requestor::request(vector<Request>& requests) {
    unsigned short reqCount = requests.size();

    for(unsigned short i = 0; i < reqCount; i++) {
        if(!request(requests[i])) return false;
    }

    return true;
}

bool Requestor::request(Request& request) {

    // -- check Request fields and evtl enter defaults --
    if(request.srcIP().empty()) {
        // cannot send without srcIP!
        if(srcIP.empty()) return false;
        request.srcIP(srcIP);
    }
    if(request.destIP().empty()) {
        // cannot send without destIP!
        if(destIP.empty()) return false;
        request.destIP(destIP);
    }
    if(request.srcPort == 0) request.srcPort = srcPort;
    if(request.destPort == 0) request.destPort = destPort;

    // override the request!
    //request.theRequest("GET / HTTP/1.0\r\n");

    // -- add Request to SendQ --
    pthread_mutex_lock(&sendQLock);
    sendQ.push_back(request);
    pthread_mutex_unlock(&sendQLock);
    
    return true;
}

unsigned int Requestor::latelySent() {
/*    pthread_mutex_lock(&sentLock);
    unsigned long int sent = sentRequests.size();
    sentRequests.clear();
    pthread_mutex_unlock(&sentLock);*/
    unsigned long int sent = okCnt;
    okCnt = 0;
    return sent;
}

unsigned int Requestor::latelyFailed() {
    /*pthread_mutex_lock(&failedLock);
    unsigned long int failed = failedRequests.size();
    failedRequests.clear();
    pthread_mutex_unlock(&failedLock);*/
    unsigned long int failed = failedCnt;
    failedCnt = 0;
    return failed;
}

unsigned int Requestor::latelyReset() {
    unsigned long int reset = rstCnt;
    rstCnt = 0;
    return reset;
}

bool Requestor::writeStats() {
    //static unsigned long int counter = statPeriod;

    if(statAvgCount < 1) return false;

    // -- add recent Requests to the respective buffer --
    unsigned short sent = latelySent();
    unsigned short failed = latelyFailed();
    unsigned short reset = latelyReset();
    cout << "sent: " << sent;
    cout << "  ---  failed: ";
    if(failed > 0)
    {
        cout << "\x1b[31m";
    }
    cout << failed << "\x1b[0m";
    cout << " --- reset: " << reset << endl;
    sentBuffer.push_back(sent);
    failedBuffer.push_back(failed);

    // -- prune buffers to the correct length --
    if(sentBuffer.size() > (statAvgCount))
        sentBuffer.erase(sentBuffer.begin());
    else if(sentBuffer.size() < statAvgCount)
        return true;
    if(failedBuffer.size() > (statAvgCount))
        failedBuffer.erase(failedBuffer.begin());


    int sentSum = 0;
    int failedSum = 0;
    for(unsigned short bufferIndex = 0; bufferIndex < sentBuffer.size(); ++bufferIndex) {
        sentSum += sentBuffer[bufferIndex];
        failedSum += failedBuffer[bufferIndex];
    }
    
    float rate;
    if((sentSum == 0 && failedSum == 0))
    {
        rate = 1.0f;
    }
    else
    {
        rate = (float)sentSum / (float)(sentSum + failedSum);
    }
        
    
    char entry[50];
    sprintf(entry, " %.2f %.2f %.2f", (float) (sentSum / (float) statAvgCount), (float) (failedSum  / (float) statAvgCount), rate * 100.0f);
    //cout << "adding entry: " << entry << endl;
    statistics.push_back(entry);


    // -- prune statistics to period --
    if(statistics.size() > statPeriod)
        statistics.erase(statistics.begin());

    string tmpStatFilename = statFilename + "tmp";
    ofstream statFile(tmpStatFilename.c_str());
    if(!statFile.good())
    {
        return false;
    }
    for(unsigned short j = 0; j < statistics.size(); ++j) {
        statFile << (-statPeriod+j+1) << statistics[j] << endl;
    }
    statFile.close();

    string runMe = "mv " + tmpStatFilename + " " + statFilename;
    run(runMe);

    return true;
}
