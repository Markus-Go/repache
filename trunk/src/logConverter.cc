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
 * File: logConverter.cc 
 * Purpose: converts and scrambles an apache logfile into a binry format 
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

using namespace std;

/**
 * sdbm hash algorithm of Sleepycat's databse BDB (Berkeley DataBase)
 */
unsigned long sdbm(unsigned char *str) {
    unsigned long hash = 0;
    int q = 0;
    
    while (q = *str++)
        hash = q + (hash << 6) + (hash << 16) - hash;
    
    return hash;
}

/**
 * read an Apache log file and "replay" the requests by sending them
 * in the respective timing to a defined target web server
 */
int main(int argc, char* argv[]) {
    
    bool anonymizeIP = true;
    bool randomURLs= true;
    string logFileName;
    string outFileName;
    map<uint32_t, uint32_t> anonymizedIPs;
    map<unsigned long, string> anonymizedURLs;
    
    srandom(time(NULL)*getpid());
    
    // -- check parameters and display usage if not enough --
    if(argc < 3) {
        cout << "\nRead an apache logfile, anonymize it and convert it to binary." << endl;
        cout << "Usage: " << argv[0] << " <apacheLogFile> <outputFile>" << endl;
        cout << "  - apacheLogFile: apache log in the format" << endl;
        cout << "    host identity user time \"request\" status size \"Referer\" \"User-agent\"" << endl;
        cout << "  - outputFile: wher to store the anonymized binary" << endl;
        exit(-1);
    } else {
        logFileName = argv[1];
        outFileName = argv[2];
    }

    // -- read Apache logfile into global multimap 'requests' --
    readApacheLog(logFileName);
    unsigned int entries = requests.size(); 
    
    ofstream outStream;
    outStream.open(outFileName.c_str(), ios::out | ios::binary);

    // -- write out all entries --    
    for(iterType i = requests.begin(); i != requests.end(); i++) {
        if (anonymizeIP) {
//            cout << "original IP: " << i->second.srcIP();
//            cout << " (" << i->second.sIP << ")" << endl;
            uint32_t ip = i->second.sIP;
            // -- check if we already anonymized this IP --
            map<uint32_t,uint32_t>::iterator match = anonymizedIPs.find(ip);
            if(match != anonymizedIPs.end()) {
                // -- IP already anonymized --
                ip = match->second;
            } else {
                // -- anonymize IP and store it --
                uint32_t origIP = ip;
                unsigned char* bytes = (unsigned char *) &ip;
                // -- anonymoze it, but do not use 0 and not 255 -- 
                bytes[3] = ((bytes[3] + random()) % 253) + 1;
                anonymizedIPs.insert(map<uint32_t,uint32_t>::value_type(origIP,ip));
            }
            i->second.sIP = ip;
//            cout << "anonymized IP: " << i->second.srcIP();
//            cout << " (" << i->second.sIP << ")" << endl;
        }
        
        if (randomURLs) {
//            cout << "original Request: " << i->second.theRequest() << endl;
            istringstream request(i->second.theRequest());
            string method;
            string url;
            string remainder;
            request >> method;
            request >> url;
            remainder = request.str().substr((request.tellg()));

            // -- calculate hash code of URL as unique identifier --           
            unsigned long hash = sdbm((unsigned char*) url.c_str());
            
            map<unsigned long, string>::iterator match = anonymizedURLs.find(hash);
            if(match != anonymizedURLs.end()) {
                // -- URL already anonymized --
                url = match->second;
            } else {
                // -- anonymize URL keeping its type (foo.html, bar.gif etc.) --
                string::size_type afterfile = url.find_first_of("?");
                string::size_type dot = url.find_last_of(".", afterfile);
                string suffix = "";
                if(dot != string::npos) {
                    if(afterfile == string::npos)
                        afterfile = url.length();
                    suffix = url.substr(dot, afterfile - dot);
                }
                unsigned long tmp = hash;
                url = "";
                while(tmp > 0) {
                    url += (char) ((tmp % 26) + 97);
                    tmp /= 12;
                }
                url += suffix;
                    
                anonymizedURLs.insert(map<unsigned long, string>::value_type(hash,url));
            }
            
            i->second.theRequest(method + " /" + url + remainder);
//            cout << "anonymized Request: " << i->second.theRequest() << endl;
        }
            
            
        valType val(i->first, i->second);
        outStream.write((char*) &val, sizeof(valType));
    }
    outStream.close();

    cout << "converted " << entries << " log entries." << endl;
}

