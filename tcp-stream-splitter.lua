do
    local args = { ... }
    local pcap_file = args[1]
    assert(pcap_file, "You should pass -X lua_script1:$PATH_TO_SOURCE_PCAP_FILE")
    local streams_table = {}
    local tcp_stream_f = Field.new("tcp.stream")

    local function init_listener()
        local tap = Listener.new("frame", "")
        os.execute(string.format("mkdir -p %s.parts/", pcap_file))
        function tap.reset()
            for _, value in pairs(streams_table) do
                value.dumper:flush()
                value.dumper:close()
            end
        end

        function tap.packet()
            local tcp_stream = assert(tonumber(tostring(tcp_stream_f())))
            local index = tcp_stream + 1 -- in Lua arrays starts with 1 (and not with 0)
            local part_pcap
            if streams_table[index] == nil then
                part_pcap = string.format("%s.parts/%d.pcap", pcap_file, index)
                streams_table[index] = Dumper.new_for_current(part_pcap)
            end
            streams_table[index]:dump_current()
        end
    end

    init_listener()
end
