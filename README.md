# ICMPv6 Reflection Prototype

This directory contains a prototype implementation of ICMPv6 Reflection using
ICMPv6 Extended Echo Request/Reply and a Reflect All object.

## Files

- 0001-icmpv6-add-reflect-all-support.patch
  Linux kernel patch. Adds Reflect All object constants and handling in the
  ICMPv6 Extended Echo reply path.

- 0001-ping-add-icmpv6-reflection-options.patch
  iputils patch. Adds ping -z to send an ICMPv6 Extended Echo Request with a
  Reflect All object, and ping -x to print the reflected payload as a hex dump.

- successful-run.txt
  Output of a successful run using the patched kernel and patched ping.

- reflection-success.pcap
  Packet capture of the successful test.

- reflection-success-tcpdump.txt
  Textual tcpdump decoding of the successful test. It shows an ICMPv6 type 160
  Extended Echo Request and an ICMPv6 type 161 Extended Echo Reply.

- environment.txt
  Kernel version, sysctl state, and ping version used for the test.

## How to run the test

Enable ICMP Echo Probe support:

    sudo sysctl -w net.ipv4.icmp_echo_enable_probe=1

Run the patched ping:

    cd ~/reflection-work/iputils
    sudo ./build/ping/ping -6 -z -x ::1 -c 1

Expected result:

- 1 packet transmitted
- 1 packet received
- 0 percent packet loss
- RTT is printed
- Reflect All Object hex dump is printed

## Wireshark Lua dissector

The `wireshark/icmpv6_reflection.lua` file contains a Wireshark Lua dissector/helper for inspecting the ICMPv6 Reflection packets used in this prototype.

It helps inspect:

- ICMPv6 Extended Echo Request, type 160
- ICMPv6 Extended Echo Reply, type 161
- ICMP Extension Header
- Reflect All object header
- Reflected IPv6 packet payload


## Notes

IPv6 does not use the term TTL. The equivalent field is Hop Limit.

The reflected payload starts from the IPv6 header, so the Hop Limit of the
received request is reflected automatically as part of the copied IPv6 header.

The sysctl net.ipv4.icmp_echo_enable_probe must be enabled. Without it, Linux
does not process ICMPv6 Extended Echo Requests through the reply path.
