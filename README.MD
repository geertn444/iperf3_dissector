#Iperf3 Dissector for Wireshark

Wireshark already contains an iperf2 dissector, but in iperf3 some fields have changed order, plus the UDP port.
<BR>So i made this small LUA file to recognize & dissect iperf3 UDP packets.

Work is based on https://github.com/dragonxtek/iperf_dissector

To install, just copy the LUA file to .\App\Wireshark\plugins directory.

NOTE: the dissector does NOT support the --udp-counters-64bit option yet.
<BR>NOTE: the dissector only decodes timestamp and sequence number. No other fields.
