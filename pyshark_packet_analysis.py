#############################################################################################
# The Python module PyShark is a wrapper for the Wireshark CLI (TShark).
#
# reference: https://kiminewt.github.io/pyshark
# reference: https://www.wireshark.org
# reference: https://www.wireshark.org/docs/man-pages/tshark.html
#############################################################################################
import pyshark


#############################################################################################
# This section is used to parse various types of protocols and their associated port numbers
# from a standard Packet Capture (PCAP) file using PyShark.
#############################################################################################
def filter_all_tcp_traffic_file(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP)
    packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_all_udp_traffic_file(packet):
    """
    This function is designed to parse all the User Datagram Protocol (UDP)
    packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'udp'):
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_dns_traffic_file(packet):
    """
    This function is designed to parse all the Domain Name System (DNS) packets
    from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'udp') and packet[packet.transport_layer].dstport == '53':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_ftp_traffic_file(packet):
    """
    This function is designed to parse all the File Transfer Protocol (FTP) packets
    from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '21':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_http_traffic_file(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol (HTTP)
    packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '80':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_https_traffic_file(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol Secure (HTTPS)
    packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '443':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_netbios_traffic_file(packet):
    """
    This function is designed to parse all the Server Message Block (SMB) packets
    from a Packet Capture (PCAP) file.

    Port 139: SMB originally ran on top of NetBIOS using port 139. NetBIOS is an older
    transport layer that allows Windows computers to talk to each other on the same
    network.

    Port 445: Later versions of SMB (after Windows 2000) began to use port 445 on top of
    a TCP stack.

    :param packet: raw packet from a pcap file
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
        if packet[packet.transport_layer].dstport == '139' \
                or packet[packet.transport_layer].dstport == '445':
            protocol = packet.transport_layer
            source_address = packet.ip.src
            source_port = packet[packet.transport_layer].srcport
            destination_address = packet.ip.dst
            destination_port = packet[packet.transport_layer].dstport
            packet_time = packet.sniff_time
            return f'Packet Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'


def filter_all_web_traffic_file(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol (HTTP) and
    Hypertext Transfer Protocol Secure (HTTPS) packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file.
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
        if packet[packet.transport_layer].dstport == '80' or packet[packet.transport_layer].dstport == '443':
            protocol = packet.transport_layer
            source_address = packet.ip.src
            source_port = packet[packet.transport_layer].srcport
            destination_address = packet.ip.dst
            destination_port = packet[packet.transport_layer].dstport
            packet_time = packet.sniff_time
            return f'Packet Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'


def get_file_captures(parse_type, pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    for raw_packet in capture:
        if parse_type is 'dns':
            results = filter_dns_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'ftp':
            results = filter_ftp_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'https':
            results = filter_https_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'http':
            results = filter_https_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'netbios':
            results = filter_netbios_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'tcp':
            results = filter_all_tcp_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'udp':
            results = filter_all_udp_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'web':
            results = filter_all_web_traffic_file(raw_packet)
            if results is not None:
                print(results)


#############################################################################################
# This section is used to parse various types of protocols and their associated port numbers
# from a live capture using TShark.
#############################################################################################
def filter_dns_live_capture(packet):
    """
    This function is designed to parse all the Domain Name System (DNS) packets
    from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'udp') and packet[packet.transport_layer].dstport == '53':
        try:
            if packet.dns.qry_name:
                source_address = packet.ip.src
                dns_location = packet.dns.qry_name
                return f'DNS Request from IP: {source_address}' \
                       f'\nTo DNS Name: {dns_location}'
        except AttributeError as e:
            pass

        try:
            if packet.dns.resp_name:
                source_address = packet.ip.src
                dns_location = packet.dns.resp_name
                return f'DNS Response from IP: {source_address}' \
                       f'\nTo DNS Name: {dns_location}'
        except AttributeError as e:
            pass


def filter_all_web_traffic_file(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol (HTTP) and
    Hypertext Transfer Protocol Secure (HTTPS) packets from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
        if packet[packet.transport_layer].dstport == '80' or packet[packet.transport_layer].dstport == '443':
            protocol = packet.transport_layer
            source_address = packet.ip.src
            source_port = packet[packet.transport_layer].srcport
            destination_address = packet.ip.dst
            destination_port = packet[packet.transport_layer].dstport
            packet_time = packet.sniff_time
            return f'Packet Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'


def filter_https_live_packet_capture(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol Secure (HTTPS)
    packets from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '443':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_http_live_packet_capture(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol (HTTP)
    packets from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '80':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_ssh_live_packet_capture(packet):
    """
    This function is designed to parse all the Secure Shell (SSH) packets
    from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '22':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def filter_ftp_live_packet_capture(packet):
    """
    This function is designed to parse all the File Transfer Protocol (FTP) packets
    from a live capture using TShark.

    :param packet: raw packet from a live capture using TShark
    :return: specific packet details
    """
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '21':
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        return f'Packet Timestamp: {packet_time}' \
               f'\nProtocol type: {protocol}' \
               f'\nSource address: {source_address}' \
               f'\nSource port: {source_port}' \
               f'\nDestination address: {destination_address}' \
               f'\nDestination port: {destination_port}\n'


def get_live_captures(parse_type, network_interface):
    capture = pyshark.LiveCapture(interface=network_interface)
    capture.sniff(timeout=50)
    for raw_packet in capture.sniff_continuously():
        if parse_type is 'dns':
            results = filter_dns_live_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'ftp':
            results = filter_ftp_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'https':
            results = filter_https_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'http':
            results = filter_http_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'ssh':
            results = filter_ssh_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'web':
            results = filter_all_web_traffic_file(raw_packet)
            if results is not None:
                print(results)


#############################################################################################
# This section is used to parse various types of protocols and their associated port numbers
# from a standard Packet Capture (PCAP) file using PyShark and a live capture using TShark.
#
# display_filter='tcp.analysis.retransmission'
# TCP Analysis Flags
# Expert Info (Note/Sequence): This frame is a (suspected) retransmission
# This frame is a (suspected) retransmission
#
# # display_filter='tcp.analysis.fast_retransmission'
# TCP Analysis Flags
# This frame is a (suspected) fast retransmission
# This frame is a (suspected) retransmission
# Expert Info (Note/Sequence): This frame is a (suspected) fast retransmission
# Expert Info (Note/Sequence): This frame is a (suspected) retransmission
#############################################################################################
def filter_retransmission_packet_file(packet, show_packets=''):
    counter = 0
    if not show_packets:
        counter += 1
        return '*' * 10, f'Retransmission packet {counter}:', '*' * 10
    elif show_packets:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
               
        if "(suspected) retransmission" in str(packet.tcp) \
                and "(suspected) spurious retransmission" in str(packet.tcp):
            return f'Suspected spurious retransmission' \
                   f'\nPacket Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'

        elif "(suspected) retransmission" in str(packet.tcp) \
                and "suspected retransmission" not in str(packet.tcp):
            return f'Suspected retransmission' \
                   f'\nPacket Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'


def filter_retransmission_live_capture(packet, show_packets=''):
    counter = 0
    if not show_packets:
        counter += 1
        return '*' * 10, f'Retransmission packet {counter}:', '*' * 10
    elif show_packets:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        
        if "(suspected) retransmission" in str(packet.tcp) \
                and "(suspected) spurious retransmission" in str(packet.tcp):

            return f'Suspected spurious retransmission' \
                   f'\nPacket Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'

        elif "(suspected) retransmission" in str(packet.tcp) \
                and "suspected retransmission" not in str(packet.tcp):
            return f'Suspected retransmission' \
                   f'\nPacket Timestamp: {packet_time}' \
                   f'\nProtocol type: {protocol}' \
                   f'\nSource address: {source_address}' \
                   f'\nSource port: {source_port}' \
                   f'\nDestination address: {destination_address}' \
                   f'\nDestination port: {destination_port}\n'


def get_retransmissions(parse_type, pcap_file, network_interface):

    if parse_type is 'file':
        capture = pyshark.FileCapture(pcap_file, display_filter='tcp.analysis.retransmission')
        for raw_packet in capture:
            results = filter_retransmission_packet_file(raw_packet, 'True')
            if results is not None:
                print(results)

    elif parse_type is 'live':
        capture = pyshark.LiveCapture(interface=network_interface, display_filter='tcp.analysis.retransmission')
        capture.sniff(timeout=50)
        for raw_packet in capture.sniff_continuously():
            results = filter_retransmission_packet_file(raw_packet, 'True')
            if results is not None:
                print(results)


def main():

    # PCAP file to parse
    pcap_file = 'smallFlows.pcap'
    
    # Network interface used by TShark for live capture
    network_interface = 'en0'

    # Parse types include: tcp, udp, dns, ftp, http, https, 
    # netbios, ssh, web (which includes http & https)
    get_file_captures('netbios', pcap_file)

    # Parse types include: dns, ftp, http, https, 
    # ssh, web (which includes http & https)
    # get_live_captures('ftp', network_interface)

    # Parse types include: file and live.
    # get_retransmissions('file', pcap_file, network_interface)


if __name__ == "__main__":
    main()

