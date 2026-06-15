local reflect_proto = Proto("icmpv6_reflect", "ICMPv6 Reflection")

local ICMPV6_EXT_ECHO_REQUEST = 160
local ICMPV6_EXT_ECHO_REPLY = 161
local REFLECT_ALL_CLASS = 6

local icmp_type_names = {
    [ICMPV6_EXT_ECHO_REQUEST] = "Extended Echo Request",
    [ICMPV6_EXT_ECHO_REPLY] = "Extended Echo Reply"
}

local icmp_reply_code_names = {
    [0] = "No Error",
    [1] = "Malformed Query",
    [2] = "No Such Interface",
    [3] = "No Such Table Entry",
    [4] = "Multiple Interfaces Satisfy Query"
}

local reflect_class_names = {
    [REFLECT_ALL_CLASS] = "Reflect All"
}

local reflect_ctype_names = {
    [0] = "Request",
    [1] = "Reply - No Error",
    [2] = "Reply - Unsupported Object"
}

local reply_state_names = {
    [0] = "Reserved / Not Used",
    [1] = "Incomplete",
    [2] = "Reachable",
    [3] = "Stale",
    [4] = "Delay",
    [5] = "Probe",
    [6] = "Failed"
}

local f_base_type = ProtoField.uint8(
    "icmpv6_reflect.type",
    "Type",
    base.DEC,
    icmp_type_names
)

local f_base_code = ProtoField.uint8(
    "icmpv6_reflect.code",
    "Code",
    base.DEC,
    icmp_reply_code_names
)

local f_base_chk = ProtoField.uint16(
    "icmpv6_reflect.checksum",
    "Checksum",
    base.HEX
)

local f_base_id = ProtoField.uint16(
    "icmpv6_reflect.identifier",
    "Identifier",
    base.HEX
)

local f_base_seq_flags_word = ProtoField.uint16(
    "icmpv6_reflect.seq_flags_word",
    "Sequence/Flags Word",
    base.HEX
)

local f_base_seq = ProtoField.uint8(
    "icmpv6_reflect.sequence",
    "Sequence Number",
    base.DEC
)

local f_req_flags = ProtoField.uint8(
    "icmpv6_reflect.request.flags",
    "Request Reserved/L Flags",
    base.HEX
)

local f_req_reserved = ProtoField.uint8(
    "icmpv6_reflect.request.reserved",
    "Request Reserved",
    base.HEX,
    nil,
    0xfe
)

local f_req_l = ProtoField.bool(
    "icmpv6_reflect.request.l",
    "L-bit",
    8,
    nil,
    0x01
)

local f_reply_flags = ProtoField.uint8(
    "icmpv6_reflect.reply.flags",
    "Reply State/Flags",
    base.HEX
)

local f_reply_state = ProtoField.uint8(
    "icmpv6_reflect.reply.state",
    "State",
    base.DEC,
    reply_state_names,
    0xf0
)

local f_reply_reserved = ProtoField.uint8(
    "icmpv6_reflect.reply.reserved",
    "Reply Reserved",
    base.HEX,
    nil,
    0x08
)

local f_reply_active = ProtoField.bool(
    "icmpv6_reflect.reply.active",
    "Active Flag",
    8,
    nil,
    0x04
)

local f_reply_ipv4 = ProtoField.bool(
    "icmpv6_reflect.reply.ipv4",
    "IPv4 Flag",
    8,
    nil,
    0x02
)

local f_reply_ipv6 = ProtoField.bool(
    "icmpv6_reflect.reply.ipv6",
    "IPv6 Flag",
    8,
    nil,
    0x01
)

local f_ext_ver_raw = ProtoField.uint16(
    "icmpv6_reflect.ext.version_reserved",
    "Version & Reserved",
    base.HEX
)

local f_ext_version = ProtoField.uint16(
    "icmpv6_reflect.ext.version",
    "Extension Version",
    base.DEC,
    nil,
    0xf000
)

local f_ext_reserved = ProtoField.uint16(
    "icmpv6_reflect.ext.reserved",
    "Extension Reserved",
    base.HEX,
    nil,
    0x0fff
)

local f_ext_chk = ProtoField.uint16(
    "icmpv6_reflect.ext.checksum",
    "Extension Checksum",
    base.HEX
)

local f_obj_len = ProtoField.uint16(
    "icmpv6_reflect.obj.length",
    "Object Length",
    base.DEC
)

local f_obj_cls = ProtoField.uint8(
    "icmpv6_reflect.obj.class",
    "Object Class",
    base.DEC,
    reflect_class_names
)

local f_obj_typ = ProtoField.uint8(
    "icmpv6_reflect.obj.ctype",
    "Object C-Type",
    base.DEC,
    reflect_ctype_names
)

local f_payload = ProtoField.bytes(
    "icmpv6_reflect.payload",
    "Reflected Payload"
)

local f_trailing = ProtoField.bytes(
    "icmpv6_reflect.trailing",
    "Trailing Data After Reflect All Object"
)

reflect_proto.fields = {
    f_base_type,
    f_base_code,
    f_base_chk,
    f_base_id,
    f_base_seq_flags_word,
    f_base_seq,
    f_req_flags,
    f_req_reserved,
    f_req_l,
    f_reply_flags,
    f_reply_state,
    f_reply_reserved,
    f_reply_active,
    f_reply_ipv4,
    f_reply_ipv6,
    f_ext_ver_raw,
    f_ext_version,
    f_ext_reserved,
    f_ext_chk,
    f_obj_len,
    f_obj_cls,
    f_obj_typ,
    f_payload,
    f_trailing
}

local original_icmpv6 = DissectorTable.get("ip.proto"):get_dissector(58)

function reflect_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 1 then
        return
    end

    local icmp_type = tvb(0, 1):uint()

    if icmp_type ~= ICMPV6_EXT_ECHO_REQUEST and icmp_type ~= ICMPV6_EXT_ECHO_REPLY then
        if original_icmpv6 then
            original_icmpv6:call(tvb, pinfo, tree)
        end
        return
    end

    pinfo.cols.protocol = "ICMPv6-REFLECT"

    if icmp_type == ICMPV6_EXT_ECHO_REQUEST then
        pinfo.cols.info = "ICMPv6 Extended Echo Request with Reflection"
    else
        pinfo.cols.info = "ICMPv6 Extended Echo Reply with Reflection"
    end

    local main_tree = tree:add(reflect_proto, tvb(), "ICMPv6 Reflection")

    if tvb:len() < 8 then
        main_tree:append_text(" [Truncated ICMPv6 Extended Echo header]")
        return
    end

    main_tree:add(f_base_type, tvb(0, 1))
    main_tree:add(f_base_code, tvb(1, 1))
    main_tree:add(f_base_chk, tvb(2, 2))
    main_tree:add(f_base_id, tvb(4, 2))
    main_tree:add(f_base_seq_flags_word, tvb(6, 2))
    main_tree:add(f_base_seq, tvb(6, 1))

    if icmp_type == ICMPV6_EXT_ECHO_REQUEST then
        local req_flags_tree = main_tree:add(f_req_flags, tvb(7, 1))
        req_flags_tree:add(f_req_reserved, tvb(7, 1))
        req_flags_tree:add(f_req_l, tvb(7, 1))
    else
        local reply_flags_tree = main_tree:add(f_reply_flags, tvb(7, 1))
        reply_flags_tree:add(f_reply_state, tvb(7, 1))
        reply_flags_tree:add(f_reply_reserved, tvb(7, 1))
        reply_flags_tree:add(f_reply_active, tvb(7, 1))
        reply_flags_tree:add(f_reply_ipv4, tvb(7, 1))
        reply_flags_tree:add(f_reply_ipv6, tvb(7, 1))
    end

    if tvb:len() < 16 then
        main_tree:append_text(" [No complete ICMP Extension Structure]")
        return
    end

    local ext_main_tree = main_tree:add(tvb(8), "ICMP Extension Structure")

    local ext_tree = ext_main_tree:add(tvb(8, 4), "Extension Header")
    ext_tree:add(f_ext_ver_raw, tvb(8, 2))
    ext_tree:add(f_ext_version, tvb(8, 2))
    ext_tree:add(f_ext_reserved, tvb(8, 2))
    ext_tree:add(f_ext_chk, tvb(10, 2))

    local obj_len = tvb(12, 2):uint()
    local obj_tree = ext_main_tree:add(tvb(12), "Reflect All Object Header")
    obj_tree:add(f_obj_len, tvb(12, 2))
    obj_tree:add(f_obj_cls, tvb(14, 1))
    obj_tree:add(f_obj_typ, tvb(15, 1))

    if obj_len < 4 then
        obj_tree:append_text(" [Invalid object length: less than object header]")
        return
    end

    local declared_payload_len = obj_len - 4
    local available_after_obj_header = tvb:len() - 16
    local payload_len = math.min(declared_payload_len, available_after_obj_header)

    if payload_len > 0 then
        local payload_item = ext_main_tree:add(f_payload, tvb(16, payload_len))

        if payload_len < declared_payload_len then
            payload_item:append_text(
                string.format(" [Truncated: captured %d of %d declared bytes]",
                              payload_len, declared_payload_len)
            )
        end
    end

    local object_total_len = 4 + declared_payload_len
    local next_offset = 12 + object_total_len

    if tvb:len() > next_offset then
        ext_main_tree:add(f_trailing, tvb(next_offset, tvb:len() - next_offset))
    end
end

DissectorTable.get("ip.proto"):add(58, reflect_proto)
