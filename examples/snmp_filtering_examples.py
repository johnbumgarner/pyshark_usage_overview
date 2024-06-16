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
import pyshark
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def parse_snmp_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses SNMP information from the given packet.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: SNMP packet information.
    :rtype: iter of str
    """
    try:
        snmp_info = {}
        if hasattr(packet, 'snmp'):
            snmp_data = packet.snmp._all_fields
            snmp_info['message_version'] = snmp_data.get('snmp.msgVersion')
            snmp_info['message_id'] = snmp_data.get('snmp.msgID')
            snmp_info['message_max_size'] = snmp_data.get('snmp.msgMaxSize')
            snmp_info['message_flags'] = snmp_data.get('snmp.msgFlags')
            snmp_info['security_model'] = snmp_data.get('snmp.msgSecurityModel')
            snmp_info['authoritative_engine_id'] = snmp_data.get('snmp.msgAuthoritativeEngineID')
            snmp_info['authoritative_engine_boots'] = snmp_data.get('snmp.msgAuthoritativeEngineBoots')
            snmp_info['authoritative_engine_time'] = snmp_data.get('snmp.msgAuthoritativeEngineTime')
            snmp_info['user_name'] = snmp_data.get('snmp.msgUserName')
            snmp_info['authentication_parameters'] = snmp_data.get('snmp.msgAuthenticationParameters')
            snmp_info['privacy_parameters'] = snmp_data.get('snmp.msgPrivacyParameters')
            snmp_info['message_data'] = snmp_data.get('snmp.msgData')
            snmp_info['encrypted_pdu'] = snmp_data.get('snmp.encryptedPDU')
        if not snmp_info:
            yield 'No SNMP information in this packet'
        else:
            yield snmp_info
    except AttributeError as e:
        pass

def filter_snmp(network_interface: str, filter_type: str = 'transport_layer') -> iter:
    """
    Captures and filters SNMP packets from the specified network interface.

    :param network_interface: The network interface to capture packets from.
    :type network_interface: str

    :param filter_type: The type of filter to apply ('transport_layer', 'bpf', or 'display').
    :type filter_type: str

    :yields: SNMP packet information.
    :rtype: iter of str
    """
    if filter_type == 'transport_layer':
        capture = pyshark.LiveCapture(interface=network_interface)
    elif filter_type == 'bpf':
        capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='udp port 161')
    elif filter_type == 'display':
        capture = pyshark.LiveCapture(interface=network_interface, display_filter='snmp')
    else:
        raise ValueError("Invalid filter_type. Choose 'transport_layer', 'bpf', or 'display'.")

    for packet in capture:
        if filter_type == 'transport_layer' and not (hasattr(packet, 'udp') and packet.udp.dstport == '161'):
            continue
        yield from parse_snmp_info(packet)

def main():
    """
    Main function to capture and print SNMP packet information.
    """
    network_interface = 'en0'  # Change to the appropriate interface name
    filter_type = 'display'  # Choose 'transport_layer', 'bpf', or 'display'

    try:
        for snmp_info in filter_snmp(network_interface, filter_type):
            if 'No SNMP information in this packet' not in snmp_info:
                print(snmp_info)
    except Exception as error:
        logging.error(f"An error occurred: {error}")

if __name__ == "__main__":
    main()
