#
# Copyright (c) 2020 Raul Caro.
#
# This file is part of ICMPack
# (see https://github.com/rcaroncd/ICMPack).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
from ICMPack.icmp import Packet
import time
import socket


def start_icmp_server(iface, data=None):

    # If data is passed, it is added to the data section of the ICMP package,
    # but if it is not passed, the default values used by PING in the data field are used

    continue_server = True

    while continue_server:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_SOCKET, 25, str(iface+'\0').encode('utf-8'))
        rec_packet, addr = s.recvfrom(65535)

# Transforming the received bytes into an ICMP packet structure
        request_packet = None

        if data:
            request_packet = Packet(ping=False)
        else:
            request_packet = Packet(ping=True)

        request_packet.unpack(rec_packet)

        print("Request Packet:")
        print(request_packet)

        # stop duplicate reponse packets

        print("[*] DATA Sent: ", request_packet.data)


# Generating the icmp response based on the icmp request received
        response_packet = None

        if data:
            response_packet = Packet(ping=False)
            response_packet.pack_response(request_packet, data)
        else:
            response_packet = Packet(ping=True)
            response_packet.pack_response(request_packet)

        response_raw_packet = response_packet.toBytes()

        print("Response Packet:")
        print(response_packet)
        print("[*] DATA Recv: ", response_packet.data)

        s.sendto(response_raw_packet, (addr[0], 1))

        s.close()

        time.sleep(1)


if __name__ == "__main__":
    CURRENT_LOOPBACK_INTERFACE = "lo"
    start_icmp_server(iface=CURRENT_LOOPBACK_INTERFACE)
