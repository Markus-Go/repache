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
 * File: main.cc
 * Purpose: main file of repache 
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#include "Requestor.h"
#include "apacheLog.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <ctime>
#include <sys/time.h>
#include <getopt.h>

#include "tcpoptions.h"

using namespace std;

void printUsage(int argc, char *argv[]);
void parseArgs(int argc, char *argv[]);

bool binaryLog = false;
char* logFileName = NULL;
char* destinationIP = NULL;
char* device = NULL;

u_int16_t MIN_PORT = 1025;
u_int16_t MAX_PORT = 9999;
TcpOption tcpOptions[NUM_TCP_OPTIONS];

/**
 * parses the arguments
 */
void parseArgs(int argc, char *argv[]){
    static struct option long_options[] = {
        {"binary", no_argument, 0, 'b'},
        {"device", required_argument, 0, 'd'},
        {"file", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    char c;
    logFileName = NULL;
    destinationIP = NULL;
    device = NULL;
    int option_index = 0;
    if(argc < 2){
        printUsage(argc, argv);
        exit(EXIT_SUCCESS);
    } else {
        while ((c = getopt_long(argc,argv,"bd:f:h", long_options, &option_index)) != EOF){
            switch(c){
                case 'b':
                    binaryLog = true;
                    break;
                case 'd':
                    device = optarg;
                    break;    
                case 'f': 
                    logFileName = optarg;
                    break;   
                case 'h':
                    printUsage(argc,argv);
                    exit(EXIT_SUCCESS);
                    break;
            }
        }
        if(binaryLog & !logFileName){
            printf("\n\nYou have to supply a logfile with binary format!!\n");
            exit(EXIT_FAILURE);
        } 
        if(!logFileName){
            printf("\n\nYou have to supply an Apache logfile!!\n");
            exit(EXIT_FAILURE);
        } 
        if(!device){
            device = "eth1";
        }          
        if(option_index < argc-1){
            destinationIP = argv[argc-1];
        }else {
            destinationIP = "10.0.0.1";
        }     
        printf("Destination IP: %s\n", destinationIP);
        printf("Device: %s\n", device);
    }
    
}

void printUsage(int argc, char *argv[]){
    printf("Usage: %s [OPTION...] [<targetHostIP >](default: 10.0.0.1)\n\n", argv[0]);
    printf("Options:\n\n");
    printf("-b, --binary              optional flag for loading binary log file\n");
    printf("-d, --device=DEVICE       network listening device for tcp\n");
    printf("-f, --file=FILENAME       apache log file (binary if b is set)\n");
    printf("-h, --help                Print this message and exit\n");
    printf("\n");
}

/**
 * @return microseconds since the specified timeval
 */
unsigned long usecSince(timeval& since) {
    timeval realTime;
    unsigned long usec = 0;
    gettimeofday(&realTime, 0);
    usec += (realTime.tv_sec - since.tv_sec) * 1000000;
    usec += (realTime.tv_usec - since.tv_usec);
    return usec;
}

/**
 * @return current timestamp in usec
 */
unsigned long timestamp() {
    timeval realTime;
    gettimeofday(&realTime, 0);
    return (realTime.tv_sec * 1000000 + realTime.tv_usec);
}

/**
 * @return nanoseconds sinc the specified timeval (uSec accuracy!)
 */
unsigned long nsecSince(timeval& since) {
    return usecSince(since) * 1000;
}

/**
 * @return milliseconds sinc the specified timeval
 */
unsigned long msSince(timeval& since) {
    return usecSince(since) / 1000;
}

/**
 * read simulation data from binary log file
 */
void readBinaryLog(string logFileName) {
    ifstream inStream;
    // -- open file and set pointer "at the end" (ate) --
    inStream.open(logFileName.c_str(), ios::in|ios::binary|ios::ate);
    
    if(!inStream.is_open()) {
        cerr << "Could not open file: "<< logFileName << endl;
        exit(-1);
    }

    unsigned long fileSize = inStream.tellg();
    
    if(fileSize < sizeof(valType)) {
        cerr << logFileName << " is empty or contains no useful data" << endl;
        exit(-1);
    }
    
    // -- verify that the size fits exactly in our requests multimap --
    if((fileSize % sizeof(valType)) != 0) {
        cerr << logFileName << " seems not proper formatted!" << endl;
        exit(-1);
    }
    
    unsigned int entries = fileSize / sizeof(valType);

    // -- reset pointer to the begin of the file --    
    inStream.seekg(0, ios::beg);
    unsigned int cnt = 0;
    // -- read all entries and add them to the internal storage --
    while(cnt < entries) {
        valType val;
        inStream.read((char*) &val, sizeof(valType));
        requests.insert(val);
        ++cnt;
    }
    inStream.close();
    
    if(requests.size() != entries) {
        cerr << "size of entries in file(" << entries << ") and actually read(";
        cerr << requests.size() << ") does not match!" << endl;
    }
}



/**
 * read an Apache log file and "replay" the requests by sending them
 * in the respective timing to a defined target web server
 */
int main(int argc, char* argv[]) {
    // -- check parameters and display usage if not enough --
    parseArgs(argc,argv);
    
    unsigned int minSleep = 0;

    initTcpOptions(tcpOptions);
/*
 * test code for sleep-time
 */
    timeval lastTime;
    double avgSleepMeas = 0.f;
    double sleptMeas = 0.f;
    unsigned int runs = 100;
    for(int j = 0; j < runs; ++j) {
        gettimeofday(&lastTime, 0);
        usleep(1);
        sleptMeas += usecSince(lastTime);
    }
    minSleep = (unsigned int)(sleptMeas / runs);
    // -- be a bit pessimistic about the estimation! --
    minSleep *= 2;
    cout << "average sleep measured (ms): " << minSleep / 1000 << endl;
    
    srandom(time(NULL)*getpid());

    printf("logname: %s\n\n\n", logFileName);
    
    Requestor requestor(destinationIP);
    requestor.initialize("stats", 3, 60, device);

    // -- read Apache logfile into global multimap 'requests' --
    if(binaryLog) {
        readBinaryLog(logFileName);
    } else {
        readApacheLog(logFileName);
    }
    cout << "read " << requests.size() << " log entries." << endl;

    // start with timestamp of the begin() of the requests
    time_t currentTimestamp = (requests.begin())->first;
    // set the end to one after the timestamp of the last of the requests
    time_t endTimestamp = (--requests.end())->first;

    //cout << "First Timestamp: " << asctime(gmtime(&currentTimestamp)) << endl;
    //cout << "Last Timestamp: " << asctime(gmtime(&endTimestamp)) << endl;

    // the total amount of microseconds for sending within one timestamp
    long int totalUsec = 0;
    unsigned long now = 0;
    unsigned long last = 0;
    unsigned long wakeup = 0;
    unsigned long sleep = 0;


    // a factor to simulate a higher load by compressing requests
    unsigned short compressor = 0;

    // -- issue all requests within the respective timestamps --
    // -- the total time is distributed randomly to the requests --
    while(currentTimestamp <= endTimestamp)
    {
        unsigned int reqCount = requests.count(currentTimestamp);
        // compress requests to simulate higher load
        for (int i = 1; i <= compressor; ++i) {
            reqCount += requests.count(currentTimestamp + i);
        }
        cout << endl << reqCount << ": " << asctime(gmtime(&currentTimestamp));
        totalUsec = 1000000;
        //srand(currentTimestamp * 42);
        if(reqCount > 0) {
            // get all requests in the range from currentTimestamp + eventual 
            // compress factor and go through them
            // pos.first = firstResult, pos.second = firstNotResult
            iterType pos = requests.lower_bound(currentTimestamp);
            iterType stop = requests.upper_bound(currentTimestamp + compressor);
            for(; pos != stop; pos++) {
                //gettimeofday(&lastRequest, 0);
                sleep = (compressor > 0) ? totalUsec/reqCount/compressor : totalUsec/reqCount;
                last = timestamp();
                requestor.request(pos->second);
                wakeup = last + sleep; 
                // issue the current request
                now = timestamp();
                while(now < wakeup) {
                    if((wakeup - now) > minSleep) {
                        usleep((wakeup - now) / 4);
                    }
                    now = timestamp();
                }
                totalUsec -= now - last;
                
                // decrease amount of remaining requests
                --reqCount;
            }
        }
        // sleep the rest of the second of this timestamp
//        cout << "[MAIN] remaining usec: " << totalUsec << endl;
        if (totalUsec > minSleep && totalUsec > 0) {
            usleep(totalUsec);
        }
//        cout << "sent: " << requestor.latelySent();
//        cout << "  ---  failed: " << requestor.latelyFailed() << endl;
        
        if(!requestor.writeStats()) {
            cout << "stat file error\n";
        }
        ++currentTimestamp;
        currentTimestamp += compressor;
    }

    // TODO solve abort a bit nicer!
    // e.g. catch abort signal: stop new requests, wait for old ones
    // to finish, wait for timeouts, clean exit
    // catch another interrupt for a brutal quit of the app (dev feature!) 

    // provide all threads enough time to finish their work
    short cnt = 0;
    while (cnt < 10) {
        usleep(1000000);
        requestor.writeStats();
        cnt++;
    }

    return 0;
}

