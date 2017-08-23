# tshark-tcp-stream-splitter

Lua script for split big PCAP file in few little PCAP's by tcp stream id with **one** tshark run. It's **much** faster than:

``` shell
pcap="very-big-file.pcap"
mkdir -p "$pcap.parts/"
for tcp_stream in $(tshark -n -r "$pcap" -T fields -e tcp.stream | sort -un | tail -1); do
    tshark -Y "tcp.stream eq ${tcp_stream}" -r "$pcap" -w "$pcap.parts/$tcp_stream.pcap"
done
```

because you don't need to reread entire PCAP for each tcp stream.

# Usage

``` shell
tshark -X lua_script:tcp-stream-splitter.lua -X lua_script1:very-big-file.pcap -n -r very-big-file.pcap
```

Output files will be stored by pattern `$PWD/very-big-file.pcap.parts/$TCP_STREAM_ID.pcap`.
