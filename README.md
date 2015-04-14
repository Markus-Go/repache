repache
=======

**repache** replays apache log files by creating actual TCP connections with
original timing and source IP addresses. Therefore a simple TCP-stack was included that
handles the TCP connections in promiscuous mode. For correct operation, one has to
ensure that the response packets are routed to the host at which **repache** is
running. Therefore **repache** cannot used in arbitrary network infrastructures.

Purpose
-------

* **repache** replays previously recorded Apache webserver logfiles.
* The big advantage of **repache** is it's realistic treatment of source IP addresses. It spoofs the IP addresses of the logfile in order to have a very realistic simulation.
* The purpose of this tool is to test webserver with country/IP specific behavior and intrusion detection/prevention systems under realistic conditions.

Usage Information
-----------------

In order to spoof TCP connections, **repache**'s TCP stack needs to listen on the network interface for reply packets - that's why all packets must be routed to the host running **repache**. This usually means, that a dedicated test environment has to be used.

<b>A demo video of repache in action can be found <a target="_blank" href='http://madm.dfki.de/projects/netcentricsecurity'>here</a>.</b>

Installation
------------

    :~$ ./configure
    :~$ make
    :~$ make install

Usage
-----

    repache [OPTION...] [<targetHostIP >]
    
    Options:
    
    -b              optional flag for loading binary log file
    -d DEVICE       network listening device for tcp
    -f FILENAME     apache log file (binary if b is set)
    -h              print thw help message and exit

Default target host ip is  10.0.0.1


Copyright/ License/ Credits
---------------------------

Copyright 2006-2008 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz  
Copyright 2009-2015 Markus Goldstein

This is free software. Licensed under the [Apache License, Version 2.0](LICENSE).  
There is NO WARRANTY, to the extent permitted by law.

![http://madm.dfki.de/lib/tpl/dfki/images/logo.jpg](http://madm.dfki.de/lib/tpl/dfki/images/logo.jpg)
