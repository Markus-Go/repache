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
 * File: apacheLog.h
 * Purpose: reads a apache log file
 * Responsible: Christian Kofler 
 * Primary Repository: http://repache.googlecode.com/svn/trunk/ 
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#ifndef APACHELOG_H_
#define APACHELOG_H_

// GLOBALS
/**
 * all requests from an apache logFile in a multimap with their respective
 * timestamps as keys (multiple requests with same timestamp)
 */
multimap<time_t, Request> requests;
/** value type for the requests multimap */
typedef multimap<time_t, Request>::value_type valType;
/** iterator type for the requests multimap */
typedef multimap<time_t, Request>::iterator iterType;

/**
 * Represents a single line in an Apache logfile
 */
struct ApacheLogEntry {
    string IP;
    time_t timestamp;
    string request;
    string referer;
    string agent;

    /** initialize all members empty */
    ApacheLogEntry():IP(""), timestamp(0), request(""),referer(""), agent("") {}

    void print() {
        cout << "IP: " << IP << " - Timestamp: " << asctime(gmtime(&timestamp)) << endl;
        cout << "Request: " << request << endl;
        cout << "Referer: " << referer << endl;
        cout << "Agent:   " << agent << endl << endl;
    }
};

/**
 * parse Apache logfile and return a vector of all recorded requests
 */
void readApacheLog(string filename) {
    ifstream logFile;
    
    cerr << "readApacheLog" << endl;

    logFile.open(filename.c_str());
    if (!logFile.is_open()) {
        cerr << "Could not open file: " << filename << endl;
        exit(-1);
    }

    string textline;
    while( !getline(logFile, textline).eof() ) {
            // skip line if it starts with whitespace or is a comment
        if (textline.empty() || isspace(textline[0]) || textline[0] == '#')
            continue;

        istringstream line(textline);
        string tmp;
        string tmp_request; //used to put the actual request, the referer and the user agent together
        
        // apache logfile format:
        //IP identity user dateTime "request" status size "Referer" "User-agent"

        ApacheLogEntry entry;

        // read IP address
        // TODO check that it's an IP address!
        line >> entry.IP;

        // ignore identity and userID
        // cut until opening bracket '['
        getline(line, tmp, '[');
        // read timestamp (until closing bracket ']')
        getline(line, tmp, ']');
        struct tm tmpStamp;
        // initialize tmpStamp ???
        if(strptime(tmp.c_str(), "%d/%b/%Y:%T ", &tmpStamp) == 0) {
            cerr << "could not parse timestamp!" << endl;
            continue;
        }
        /***********************/
        //tmpStamp.tm_hour %= 2;
        //tmpStamp.tm_min %= 1;
        //tmpStamp.tm_sec %= 10;
        /***********************/
        entry.timestamp = mktime(&tmpStamp);

        // cut opening quotation marks "
        getline(line, tmp, '"');
        // ingore actual HTTP method (GET/POST)
        getline(line, tmp, ' ');
        // read request (until space which divides it from HTTP version ")
        getline(line, tmp, ' ');
        // default all requests to use HTTP GET method
        entry.request +=  "GET ";
        // use actually requested URL
        entry.request += tmp;
        //entry.request += "/";
        // default all requests to use HTTP 1.0
        entry.request +=  " HTTP/1.0";
        // ignore actual http version
        getline(line, tmp, '"');
        // ignore status and size
        // cut until opening quotation marks of User-agent
        getline(line, tmp, '"'); 
        getline(line, entry.referer, '"');
        getline(line, tmp, '"');
        getline(line, entry.agent, '"');

        // don't care about the rest of the line
        //entry.print();
        // assemble Request from log entry
        
        tmp_request += entry.request;
        if(! entry.referer.empty() && !(entry.referer == "-")) {
            tmp_request += "\r\nReferer: ";
            tmp_request += entry.referer;
        
        }
        if( !entry.agent.empty() && !(entry.agent == "-")) {
            tmp_request += "\r\nUser-Agent: ";
            tmp_request += entry.agent;
        }
        tmp_request += "\r\n\r\n";
        //cout << tmp_request;
        size_t s = strlen(tmp_request.c_str());
        if(int(s)> DATA_SIZE) {
            cerr << "Just Info: Request too long\n";
        }
        Request req;
        req.srcIP(entry.IP);
        //req.theRequest = "GET / HTTP/1.0";
        //entry.request += "\r\n\r\n";
        req.theRequest(tmp_request); 
        
        /*    
        if( !entry.agent.empty() && !(entry.agent == "-")) {
            req.theReq += "\nUser-agent: ";
            req.theReq += entry.agent;
        }
        */
               
        // add request to global multimap
        requests.insert( valType(entry.timestamp, req));
    }
}

#endif /*APACHELOG_H_*/
