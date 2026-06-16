# ICMPv6 Reflection Prototype

This repository contains a prototype implementation of ICMPv6 Reflection using
ICMPv6 Extended Echo Request/Reply and a Reflect All object.

The implementation includes:

- a Linux kernel patch that adds Reflect All handling to the ICMPv6 Extended Echo reply path;
- an iputils `ping` patch that can generate ICMPv6 Extended Echo Requests with Reflect All;
- checksum validation for the ICMP Extension Header on receive;
- evidence pcaps and tcpdump outputs for both positive and negative tests.

## Files

- `icmpv6-add-reflect-all-support.patch`

  Linux kernel patch. Adds Reflect All object constants and handling in the
  ICMPv6 Extended Echo reply path.

  It also verifies the ICMP Extension Header checksum when receiving an
  ICMPv6 Extended Echo Request with a Reflect All object. Requests with an
  invalid ICMP Extension checksum are dropped.

- `ping-add-icmpv6-reflection-options.patch`

  iputils patch. Adds:

  - `-z`: send an ICMPv6 Extended Echo Request with a Reflect All object;
  - `-x`: print the reflected payload as a hex dump;
  - `-Z <bytes>`: set the Reflect All object payload length explicitly.

  The patch also verifies the ICMP Extension Header checksum when receiving an
  ICMPv6 Extended Echo Reply before printing the reflected payload.

- `successful-run.txt`

  Summary of the final tests, including the positive Reflect All test,
  the negative bad-extension-checksum test, and CLI validation.

- `reflection-success.pcap`

  Packet capture of the positive test.

  This test uses:

      sudo ./build/ping/ping -6 -z -x -Z 100 ::1 -c 1

  The expected Reflect All object length is `0x0068`, meaning:

      104 bytes = 4-byte object header + 100-byte reflected payload

- `reflection-success-tcpdump.txt`

  Textual tcpdump decoding of the positive test.

  It shows:

  - ICMPv6 type 160 Extended Echo Request;
  - ICMPv6 type 161 Extended Echo Reply;
  - request object header `0068 0600`;
  - reply object header `0068 0601`;
  - valid outer ICMPv6 checksums.

- `bad-ext-checksum.pcap`

  Packet capture of the negative checksum test.

  A malformed ICMPv6 Extended Echo Request is sent with:

  - valid outer ICMPv6 checksum;
  - invalid ICMP Extension Header checksum `0x1234`;
  - Reflect All object header `0068 0600`.

  The expected result is no ICMPv6 Extended Echo Reply.

- `bad-ext-checksum-tcpdump.txt`

  Textual tcpdump decoding of the negative checksum test.

  It shows only the malformed ICMPv6 type 160 request. No ICMPv6 type 161 reply
  is captured, confirming that the kernel drops requests with an invalid
  ICMP Extension Header checksum.

- `kernel-version.txt`

  Kernel version used for the final tests.

- `reflection_ipv6.lua`

  Wireshark Lua dissector/helper for inspecting the ICMPv6 Reflection packets.

- `environment.txt`

  Environment information from the earlier prototype run.

## How to run the positive test

Enable ICMP Echo Probe support:

    sudo sysctl -w net.ipv4.icmp_echo_enable_probe=1

Run the patched ping:

    cd ~/reflection-work/iputils
    sudo ./build/ping/ping -6 -z -x -Z 100 ::1 -c 1

Expected result:

- 1 packet transmitted;
- 1 packet received;
- 0 percent packet loss;
- `icmp_seq=1` is printed;
- Reflect All Object hex dump is printed;
- reflected payload length is 100 bytes.

The corresponding tcpdump output should contain:

    0068 0600

for the request, meaning Object Length 104, Class 6, C-Type Request.

It should also contain:

    0068 0601

for the reply, meaning Object Length 104, Class 6, C-Type Reply - No Error.

## How to run the negative checksum test

Start tcpdump:

    cd ~/reflection-final
    sudo timeout 20 tcpdump -i lo -nn -vv -XX -w bad-ext-checksum.pcap icmp6

In another terminal, send a malformed Extended Echo Request:

    sudo python3 - <<'PY'
    from scapy.all import IPv6, ICMPv6Unknown, send

    payload_len = 100
    obj_len = 4 + payload_len

    body = bytes.fromhex(
        "00070101"      # Identifier=7, Sequence=1, L-bit=1
        "20001234"      # Version=2, deliberately bad extension checksum
    ) + obj_len.to_bytes(2, "big") + bytes([6, 0]) + bytes(payload_len)

    pkt = IPv6(src="::1", dst="::1") / ICMPv6Unknown(type=160, code=0, msgbody=body)

    send(pkt, verbose=False)
    print("Sent malformed Extended Echo Request with bad ICMP Extension checksum")
    PY

Decode the capture:

    tcpdump -nn -vv -XX -r bad-ext-checksum.pcap

Expected result:

- one ICMPv6 type 160 request is captured;
- the request contains `2000 1234`;
- the request contains `0068 0600`;
- no ICMPv6 type 161 reply is captured.

This confirms that the kernel verifies the ICMP Extension Header checksum and
drops Extended Echo Requests with an invalid extension checksum.

## CLI validation

Running `-Z` without `-z` should fail:

    ./build/ping/ping -6 -Z 100 ::1 -c 1

Expected error:

    -Z requires -z

Running with an oversized Reflect All payload length should fail:

    ./build/ping/ping -6 -z -Z 2000 ::1 -c 1

Expected error:

    out of range: 0 <= value <= 1224

## Wireshark Lua dissector

The `reflection_ipv6.lua` file contains a Wireshark Lua dissector/helper for
inspecting the ICMPv6 Reflection packets used in this prototype.

It helps inspect:

- ICMPv6 Extended Echo Request, type 160;
- ICMPv6 Extended Echo Reply, type 161;
- ICMP Extension Header;
- Reflect All object header;
- Active flag and IPv4/IPv6 flags in Extended Echo Reply;
- reflected IPv6 packet payload.

## Notes

IPv6 does not use the term TTL. The equivalent field is Hop Limit.

The reflected payload starts from the IPv6 header, so the Hop Limit of the
received request is reflected automatically as part of the copied IPv6 header.

The sysctl `net.ipv4.icmp_echo_enable_probe` must be enabled. Without it, Linux
does not process ICMPv6 Extended Echo Requests through the reply path.
