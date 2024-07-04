#!/usr/local/bin/python3

##################################################################################
# “AS-IS” Clause
#
# Except as represented in this agreement, all work produced by Developer is
# provided “AS IS”. Other than as provided in this agreement, Developer makes no
# other warranties, express or implied, and hereby disclaims all implied warranties,
# including any warranty of merchantability and warranty of fitness for a particular
# purpose.
##################################################################################

##################################################################################
# Date Completed: July 04, 2024
# Author: John Bumgarner
#
# Date Revised:
# Revised by:
#
# This Python script is designed to process, filter and analyze .pcap files using
# the Python module PyShark.
##################################################################################

#############################################################################################
# The Python module PyShark is a wrapper for the Wireshark CLI (TShark).
#
# reference: https://kiminewt.github.io/pyshark
# reference: https://www.wireshark.org
# reference: https://www.wireshark.org/docs/man-pages/tshark.html
#############################################################################################

##################################################################################
# Python imports required for basic operations
##################################################################################
# Standard library imports
import logging
# Third-party imports
import pyshark

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses DNS information from the given packet.

    NOTE: this code is focused on DNS and can be changed to fit any use case.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: Formatted DNS request or response information.
    :rtype: iter of str
    """
    try:

        if hasattr(packet.dns, 'qry_name'):
            source_address = packet.ip.src
            destination_address = packet.ip.dst
            dns_location = packet.dns.qry_name
            query_type = packet.dns.qry_type
            query_class = packet.dns.qry_class
            yield (f'DNS Request from IP: {source_address}\n'
                   f'Destination IP: {destination_address}\n'
                   f'To DNS Name: {dns_location}\n'
                   f'Query Type: {query_type}\n'
                   f'Query Class: {query_class}')
    except AttributeError:
        pass
    try:
        if hasattr(packet.dns, 'resp_name'):
            source_address = packet.ip.src
            destination_address = packet.ip.dst
            dns_location = packet.dns.resp_name
            transaction_id = packet.dns.id
            response_code = packet.dns.flags_rcode
            answers = packet.dns.resp_addr
            yield (f'DNS Response from IP: {source_address}\n'
                   f'Destination IP: {destination_address}\n'
                   f'To DNS Name: {dns_location}\n'
                   f'Transaction ID: {transaction_id}\n'
                   f'Response Code: {response_code}\n'
                   f'Answers: {answers}')
    except AttributeError:
        pass


def filter_ips(network_interface: str, filter_type: str, source_ip_address: str, destination_ip_address: str) -> iter:
    """
    Captures and filters DNS packet information based on either source or destination IP addresses or both.

    NOTE: this code is focused on DNS and can be changed to fit any use case.

    :param network_interface: The network interface to capture packets from.
    :type network_interface: str

    :param filter_type: The type of filter to apply ('src', 'dst', or 'both').
    :type filter_type: str

    :param source_ip_address: The source IP address to filter on.
    :type source_ip_address: str

    :param destination_ip_address: The destination IP address to filter on.
    :type filter_type: str

    :yields: Formatted IP information.
    :rtype: iter of str
    """
    if filter_type == 'src':
        capture = pyshark.LiveCapture(interface=network_interface,
                                      bpf_filter=f'ip and src host {source_ip_address}',
                                      display_filter='dns')
    elif filter_type == 'dst':
        capture = pyshark.LiveCapture(interface=network_interface,
                                      bpf_filter=f'ip and dst host {destination_ip_address}',
                                      display_filter='dns')
    elif filter_type == 'both':
        capture = pyshark.LiveCapture(interface=network_interface,
                                      bpf_filter=f'ip and src host {source_ip_address} '
                                                 f'and dst host {destination_ip_address}',
                                      display_filter='dns')
    else:
        raise ValueError("Invalid filter_type. Choose 'src', 'dst', or 'both'.")

    for packet in capture:
        yield from parse_info(packet)

def main():
    """
    Main function to capture and print packet information based on either
    source or destination IP addresses or both.
    """
    network_interface = 'en0'  # Change to the appropriate interface name
    source_ip_address = '192.168.86.1' # Change to the appropriate IP Address
    destination_ip_address = '192.168.86.100' # Change to the appropriate IP Address
    filter_type = 'both'  # Choose 'src', 'dst', or 'both'

    try:
        for info in filter_ips(network_interface, filter_type, source_ip_address, destination_ip_address):
            if info is not None:
                print(info)
                print('\n')
    except Exception as error:
        logging.error(f"An error occurred: {error}")

if __name__ == "__main__":
    main()





