do
    local args = { ... }
    local pcap_file = args[1]
    assert(pcap_file, "You should pass -X lua_script1:$PATH_TO_SOURCE_PCAP_FILE")
    local streams_table = {}
    local tcp_stream_f = Field.new("tcp.stream")
    local tcp_syn_f = Field.new("tcp.flags.syn")
    local tcp_fin_f = Field.new("tcp.flags.fin")
    local tcp_rst_f = Field.new("tcp.flags.reset")
    local src_addr_f = Field.new("ip.src")
    local src_port_f = Field.new("tcp.srcport")
    local dst_addr_f = Field.new("ip.dst")
    local dst_port_f = Field.new("tcp.dstport")

    local function init_listener()
        local SYN = 2
        local tap = Listener.new("frame", "tcp")
        os.execute(string.format("mkdir -p %s.parts/", pcap_file))

        function tap.reset()
            for _, value in pairs(streams_table) do
                value.dumper:flush()
                value.dumper:close()
            end
        end

        function tap.packet()
            local tcp_stream = assert(tonumber(tostring(tcp_stream_f())))
            local src_addr = assert(tostring(src_addr_f()))
            local src_port = assert(tostring(src_port_f()))
            local dst_addr = assert(tostring(dst_addr_f()))
            local dst_port = assert(tostring(dst_port_f()))
            local syn = tonumber(tostring(tcp_syn_f()))
            local index = tcp_stream + 1
            local part_pcap
            if streams_table[index] == nil then
                part_pcap = string.format("%s.parts/%s-%s_%s-%s_%d.pcap", pcap_file, src_addr, src_port, dst_addr, dst_port, index)
                streams_table[index] = {
                    dumper = nil,
                    corrupted = not (syn == 1),
                    finished = false,
                    client = src_addr,
                }
                if streams_table[index].corrupted then
                    streams_table[index].finished = true
                else
                    streams_table[index].dumper = Dumper.new_for_current(part_pcap)
                end
            end
            if streams_table[index].finished then
                return
            end
            streams_table[index].dumper:dump_current()
            if src_addr == streams_table[index].client then
                local fin = tonumber(tostring(tcp_fin_f()))
                local rst = tonumber(tostring(tcp_rst_f()))
                if fin == 1 or rst == 1 then
                    streams_table[index].dumper:flush()
                    streams_table[index].dumper:close()
                    streams_table[index].finished = true
                end
            end
        end
    end

    init_listener()
end
