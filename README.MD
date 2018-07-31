#Iperf3 Dissector for Wireshark

Wireshark already contains an iperf2 dissector, but in iperf3 some fields have changed order, plus the UDP port.
<BR>So i made this small LUA file to recognize & dissect iperf3 UDP packets.

Work is based on https://github.com/dragonxtek/iperf_dissector

To install, just copy the LUA file to .\App\Wireshark\plugins directory.

NOTE: the dissector does NOT support the --udp-counters-64bit option yet.
<BR>NOTE: the dissector only decodes timestamp and sequence number. No other fields.
  
Using the iperf3 dissector, you can verify out-of-order UDP packets in iperf3 yourself.

I used it to troubleshoot a network situation where i got LOTS of duplicate frames. iperf3 dumped so many error messages that i thought it was a bug in iperf3 itself. Using the dissector, i could see iperf3 was right, there really was an awkward network situation.
  
Example:
  
  
  ![alt text](https://github.com/geertn444/iperf3_dissector/blob/master/example.png)
