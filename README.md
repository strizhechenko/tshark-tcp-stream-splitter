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

# Hints

If there's a lot concurrent tcp streams in one big PCAP you may avoid [fail with to many opened file descriptor](https://github.com/strizhechenko/tshark-tcp-stream-splitter/issues/1) by set ulimit to maximal available value:

```
ulimit -n 2048
```

If there's a really lot of streams probably nothing will help you. You can use shell-script above (and add some "parallelism) with python/coproc) and have nice cup of coffee. If you can suggest an better solution of this problem feel free to open an issue or send pull request.

# "Benchmarks"

- tcp stream count doesn't include corrupted (not full) tcp streams.

| Size of PCAP, Mbytes | tcp packet count | tcp stream count | time | hardware | ulimit -n | remarks |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.004 | 23 | 1 | 00:00:00.342 | Macbook Pro 2015 | 256 | -- |
| 0.224 | 1000 | 18 | 00:00:00.332 | Macbook Pro 2015 | 256 | -- |
| 21 | 96682 | 13832 | 00:00:09.000 | Macbook Pro 2015 | 2048 | -- |
| 41 | 302868 | 14465 | 00:00:19.000 | Macbook Pro 2015 | 2048 | -- |
| 283 | 967707 | 49239 | 00:01:10.303 | Macbook Pro 2015 | 8192 | failed after 967707 packet. exit by ^C |
