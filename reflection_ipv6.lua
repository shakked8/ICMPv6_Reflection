-- 1. הגדרת הפרוטוקול החדש שלנו
local reflect_proto = Proto("icmpv6_reflect", "RFC 4884 Reflection Protocol")

-- 2. הגדרת השדות 
-- שדות של כותרת הבסיס (הוספנו עכשיו כדי לפרסר הכל בעצמנו)
local f_base_type = ProtoField.uint8("icmpv6_reflect.type", "Type", base.DEC)
local f_base_code = ProtoField.uint8("icmpv6_reflect.code", "Code", base.DEC)
local f_base_chk  = ProtoField.uint16("icmpv6_reflect.checksum", "Checksum", base.HEX)
local f_base_id   = ProtoField.uint16("icmpv6_reflect.id", "Identifier", base.HEX)
local f_base_seq  = ProtoField.uint16("icmpv6_reflect.seq", "Sequence", base.DEC)

-- שדות ההרחבה והאובייקט (כמו קודם)
local f_ext_ver = ProtoField.uint16("icmpv6_reflect.ext.version_reserved", "Version & Reserved", base.HEX)
local f_ext_chk = ProtoField.uint16("icmpv6_reflect.ext.checksum", "Extension Checksum", base.HEX)
local f_obj_len = ProtoField.uint16("icmpv6_reflect.obj.length", "Object Length", base.DEC)
local f_obj_cls = ProtoField.uint8("icmpv6_reflect.obj.class", "Class Num", base.HEX)
local f_obj_typ = ProtoField.uint8("icmpv6_reflect.obj.ctype", "C-Type (Active Flag)", base.DEC)
local f_payload = ProtoField.bytes("icmpv6_reflect.payload", "Reflected Payload")

reflect_proto.fields = { f_base_type, f_base_code, f_base_chk, f_base_id, f_base_seq, 
                         f_ext_ver, f_ext_chk, f_obj_len, f_obj_cls, f_obj_typ, f_payload }

-- 3. שמירת המפענח המקורי של ICMPv6
local original_icmpv6 = DissectorTable.get("ip.proto"):get_dissector(58)

-- 4. פונקציית הפענוח
function reflect_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 1 then return end

    -- קריאת הבית הראשון כדי לדעת אם זה שלנו
    local icmp_type = tvb(0, 1):uint()

    -- אם זה הפרוטוקול שלנו: אנחנו מפרסרים הכל לבד!
    if icmp_type == 160 or icmp_type == 161 then
        
        pinfo.cols.protocol = "REFLECTION"
        if icmp_type == 160 then
            pinfo.cols.info = "RFC 4884 Extended Echo Request"
        else
            pinfo.cols.info = "RFC 4884 Extended Echo Reply"
        end

        -- יצירת העץ הראשי שמתחיל מבית 0
        local main_tree = tree:add(reflect_proto, tvb(), "Internet Control Message Protocol v6 (Reflection)")

        -- [++] הוספת כותרת הבסיס של ICMPv6 (0 עד 8)
        main_tree:add(f_base_type, tvb(0, 1))
        main_tree:add(f_base_code, tvb(1, 1))
        main_tree:add(f_base_chk,  tvb(2, 2))
        main_tree:add(f_base_id,   tvb(4, 2))
        main_tree:add(f_base_seq,  tvb(6, 2))

        -- אם יש מספיק מקום להרחבות, נוסיף גם אותן תחת תת-עץ
        if tvb:len() >= 16 then
            local ext_main_tree = main_tree:add("RFC 4884 Reflection Data")

            -- Extension Header
            local ext_tree = ext_main_tree:add("Extension Header")
            ext_tree:add(f_ext_ver, tvb(8, 2))
            ext_tree:add(f_ext_chk, tvb(10, 2))

            -- Object Header
            local obj_tree = ext_main_tree:add("Reflect Object Header")
            obj_tree:add(f_obj_len, tvb(12, 2))
            obj_tree:add(f_obj_cls, tvb(14, 1))
            
            local ctype_val = tvb(15, 1):uint()
            if ctype_val == 1 then
                obj_tree:add(f_obj_typ, tvb(15, 1)):append_text(" [ACTIVE]")
            else
                obj_tree:add(f_obj_typ, tvb(15, 1)):append_text(" [INACTIVE]")
            end

            -- Payload
            local payload_len = tvb:len() - 16
            if payload_len > 0 then
                ext_main_tree:add(f_payload, tvb(16, payload_len))
            end
        end

    -- אם זה לא שלנו (פינג רגיל, שגיאות, וכו'), ניתן ל-Wireshark לעשות את העבודה
    else
        if original_icmpv6 then
            original_icmpv6:call(tvb, pinfo, tree)
        end
    end
end

-- 5. הרישום
DissectorTable.get("ip.proto"):add(58, reflect_proto)