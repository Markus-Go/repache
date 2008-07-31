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
 * File: sniffer.cc
 * Purpose: captures packets from thwe device in promiscuous mode
 * Responsible: Christian Kofler
 * Primary Repository: http://repache.googlecode.com/svn/trunk/
 * Web Sites: www.iupr.org, www.dfki.de, http://code.google.com/p/repache/
 */

#include "Sniffer.h"

Sniffer::Sniffer(string filter, string interface) {
    handle = 0;
    char* dev = 0;
    ok = false;

    if(interface.empty()) {
        dev = pcap_lookupdev(errbuf);
        if(dev == 0) {
            printf("%s\n",errbuf);
            return;
        }
    } else {
        dev = (char*) interface.c_str();
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
        return;
    }
    /* Open the session in promiscuous mode with no timeout */
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == 0) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, (char*) filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return;
    }
    // cleanup
    pcap_freecode(&fp);

    ok = (handle != 0);
}

Sniffer::~Sniffer() {
    /* close the session */
    if(handle != 0) {
        pcap_close(handle);
    }
}

void Sniffer::sniff(pcap_handler onReceive) {
    if(!ok) {
        printf("sniff error\n");
        return;
    }
    // get all packets from the sniffed device and pass them to "callback"
    pcap_loop(handle, -1, onReceive, 0);
}
