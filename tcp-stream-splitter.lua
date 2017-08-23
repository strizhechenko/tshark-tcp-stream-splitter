do
    local args = { ... }
    assert(args[1], "You should pass -X lua_script1:$PATH_TO_SOURCE_PCAP_FILE")
    local streams_table = {}
    local tcp_stream_f = Field.new("tcp.stream")

    local function init_listener()
        filter = ""
        local tap = Listener.new("frame", filter)

        function tap.reset()
            for _, value in pairs(streams_table) do
                value.dumper:flush()
                value.dumper:close()
            end
        end

        function tap.packet(pinfo)
            local tcp_stream = assert(tonumber(tostring(tcp_stream_f())))
            local index = tcp_stream + 1 -- in Lua arrays starts with 1 (and not with 0)

            if streams_table[index] == nil then
                streams_table[index] = {
                    tcp_stream = tcp_stream,
                    dumper = Dumper.new_for_current(string.format("%s.parts/%d.pcap", args[1], index))
                }
            end
            streams_table[index].dumper:dump_current()
        end
    end

    init_listener()
end
