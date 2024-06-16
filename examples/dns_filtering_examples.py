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
#
# Date Completed: February 15, 2020
# Author: John Bumgarner
#
# Date Revised: June 15, 2024
# Revised by: John Bumgarner
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

###############################################################################################
# DNS Query Type
#
# The "Query Type" field in a DNS query specifies the type of DNS record that is being requested.
# Each type has a specific numerical value associated with it. Here are some common DNS query types
# and their corresponding numerical values:
#
# A (1): IPv4 address record. This type of query is used to get the IP address associated with a domain name.
# AAAA (28): IPv6 address record. This type of query is used to get the IPv6 address associated with a domain name.
# MX (15): Mail exchange record. This type of query is used to get the mail servers associated with a domain.
# CNAME (5): Canonical name record. This type of query is used to alias one domain name to another.
# NS (2): Name server record. This type of query is used to get the authoritative name servers for a domain.
# PTR (12): Pointer record. This type of query is used for reverse DNS lookups, where an IP address is mapped to a domain name.
# TXT (16): Text record. This type of query is used to retrieve arbitrary text data associated with a domain.
#
# DNS Query Class
#
# The "Query Class" field in a DNS query specifies the class of the query.
# The most common class is "IN" (Internet), which is used for queries related to the Internet.
# Here are some common DNS query classes and their corresponding numerical values:
#
# IN (1): Internet. This is the most commonly used class.
# CH (3): Chaos. This class is used for querying Chaosnet.
# HS (4): Hesiod. This class is used for querying Hesiod systems.

import pyshark
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_dns_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses DNS information from the given packet.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: Formatted DNS request or response information.
    :rtype: iter of str
    """
    try:
        if hasattr(packet.dns, 'qry_name'):
            source_address = packet.ip.src
            dns_location = packet.dns.qry_name
            query_type = packet.dns.qry_type
            query_class = packet.dns.qry_class
            yield f'DNS Request from IP: {source_address}\nTo DNS Name: {dns_location}\nQuery Type: {query_type}\nQuery Class: {query_class}'
    except AttributeError:
        pass

    try:
        if hasattr(packet.dns, 'resp_name'):
            source_address = packet.ip.src
            dns_location = packet.dns.resp_name
            transaction_id = packet.dns.id
            response_code = packet.dns.flags_rcode
            answers = packet.dns.resp_addr
            yield f'DNS Response from IP: {source_address}\nTo DNS Name: {dns_location}\nTransaction ID: {transaction_id}\nResponse Code: {response_code}\nAnswers: {answers}'
    except AttributeError:
        pass


def filter_dns(network_interface: str, filter_type: str = 'transport_layer') -> iter:
    """
    Captures and filters DNS packets from the specified network interface.

    :param network_interface: The network interface to capture packets from.
    :type network_interface: str

    :param filter_type: The type of filter to apply ('transport_layer', 'bpf', or 'display').
    :type filter_type: str

    :yields: Formatted DNS request or response information.
    :rtype: iter of str
    """
    if filter_type == 'transport_layer':
        capture = pyshark.LiveCapture(interface=network_interface)
    elif filter_type == 'bpf':
        capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='udp port 53')
    elif filter_type == 'display':
        capture = pyshark.LiveCapture(interface=network_interface, display_filter='dns')
    else:
        raise ValueError("Invalid filter_type. Choose 'transport_layer', 'bpf', or 'display'.")

    for packet in capture:
        if filter_type == 'transport_layer' and not (hasattr(packet, 'udp') and packet.udp.dstport == '53'):
            continue
        yield from parse_dns_info(packet)

def main():
    """
    Main function to capture and print DNS packet information.
    """
    network_interface = 'en0'  # Change to the appropriate interface name
    filter_type = 'transport_layer'  # Choose 'transport_layer', 'bpf', or 'display'

    try:
        for dns_info in filter_dns(network_interface, filter_type):
            if dns_info is not None:
                print(dns_info)
    except Exception as error:
        logging.error(f"An error occurred: {error}")

if __name__ == "__main__":
    main()





