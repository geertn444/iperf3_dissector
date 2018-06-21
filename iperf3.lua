-- REFERENCE
-- http://www.ainoniwa.net/ssp/wp-content/uploads/2013/06/wireshark_dissector_with_lua.pdf
-- http://ufpr.dl.sourceforge.net/project/iperf/iperf-2.0.5.tar.gz
-- https://github.com/dragonxtek/iperf_dissector

iperf_proto = Proto("iperf3","Iperf3 UDP packet")
iperf_seq_F = ProtoField.uint32("iperf.id", "Iperf3 sequence")
iperf_time_F = ProtoField.string("iperf.ts", "Iperf3 TimeStamp")
iperf_sec_F = ProtoField.uint32("iperf.sec", "Iperf3 sec")
iperf_usec_F = ProtoField.uint32("iperf.usec", "Iperf3 usec")
iperf_flags_F = ProtoField.uint32("iperf.flags", "Iperf3 flags")
iperf_numthreads_F = ProtoField.uint32("iperf.numThreads", "Iperf3 numThreads")
iperf_mport_F = ProtoField.uint32("iperf.mPort", "Iperf3 mPort")
iperf_bufferlen_F = ProtoField.uint32("iperf.bufferlen", "Iperf3 bufferlen")
iperf_mwinband_F = ProtoField.uint32("iperf.mWinBand", "Iperf3 mWinBand",base.HEX)
iperf_mamount_F = ProtoField.uint32("iperf.mAmount", "Iperf3 mAmount",base.HEX)
iperf_proto.fields = {iperf_seq_F, iperf_time_F, iperf_sec_F, iperf_usec_F, iperf_flags_F, iperf_numthreads_F, iperf_mport_F, iperf_bufferlen_F, iperf_mwinband_F, iperf_mamount_F }

function iperf_proto.dissector(buffer,pinfo,tree)

 local iperf_seq_range = buffer(8,4)
 
 local iperf_time_range = buffer(0,8)
 
 local iperf_sec_range = buffer(0,4)
 local iperf_usec_range = buffer(4,4)
 
 local iperf_flags_range = buffer(12,4)
 local iperf_numthreads_range = buffer(16,4)
 local iperf_mport_range = buffer(20,4)
 local iperf_bufferlen_range = buffer(24,4)
 local iperf_mwinband_range = buffer(28,4)
 local iperf_mamount_range = buffer(32,4)

 local iperf_seq = iperf_seq_range:uint()
 local iperf_sec = iperf_sec_range:uint()
 local iperf_usec = iperf_usec_range:uint()
 local iperf_flags = iperf_flags_range:uint()
 local iperf_numthreads = iperf_numthreads_range:uint()
 local iperf_mport = iperf_mport_range:uint()
 local iperf_bufferlen = iperf_bufferlen_range:uint()
 local iperf_mwinband = iperf_mwinband_range:uint()
 local iperf_mamount = iperf_mamount_range:uint()

 -- Work out the timestamp from the sec and usec
 local timestamp = (iperf_sec * 1.0) + (iperf_usec / 1000000.0)
 local iperf_time = format_date(timestamp)

 local subtree = tree:add(iperf_proto, buffer(0,36), "Iperf3 packet data")
 
 timetree = subtree:add(iperf_time_F, iperf_time_range, iperf_time)
 timetree:add(iperf_sec_F, iperf_sec_range, iperf_sec)
 timetree:add(iperf_usec_F, iperf_usec_range, iperf_usec)
 
 subtree:add(iperf_seq_F, iperf_seq_range, iperf_seq)
 
 -- subtree:add(iperf_flags_F, iperf_flags_range, iperf_flags)
 -- subtree:add(iperf_numthreads_F, iperf_numthreads_range, iperf_numthreads)
 -- subtree:add(iperf_mport_F, iperf_mport_range, iperf_mport)
 -- subtree:add(iperf_bufferlen_F, iperf_bufferlen_range, iperf_bufferlen)
 -- subtree:add(iperf_mwinband_F, iperf_mwinband_range, iperf_mwinband)
 -- subtree:add(iperf_mamount_F, iperf_mamount_range, iperf_mamount)

Dissector.get("data"):call(buffer(36,buffer:len()-36):tvb(), pinfo, tree)
end
DissectorTable.get("udp.port"):add(5201, iperf_proto)



