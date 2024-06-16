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


def parse_tls_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses TLS (HTTPS) information from the given packet.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: Formatted TLS (HTTPS) request or response information.
    :rtype: iter of str
    """
    try:
        tls_info = {}
        if hasattr(packet, 'tls'):
            tls_data = packet.tls._all_fields
            if hasattr(packet.tls, 'segment.data'):
                tls_info['segment_data'] = tls_data.get('tls.segment.data')
            elif hasattr(packet.tls, 'handshake'):
                tls_info['tls_record'] = tls_data.get('tls.record')
                tls_info['record_content_type'] = tls_data.get('tls.record.content_type')
                tls_info['record version'] = tls_data.get('tls.record.version')
                tls_info['record_length'] = tls_data.get('tls.record.length')
                tls_info['handshake_version'] = tls_data.get('tls.handshake.version')
                tls_info['random_value'] = tls_data.get('tls.handshake.random')
                tls_info['cipher_suite'] = tls_data.get('tls.handshake.ciphersuite')
                tls_info['session_id'] = tls_data.get('tls.handshake.session_id')
                tls_info['extensions_length'] = tls_data.get('tls.handshake.extensions_length')
                tls_info['handshake_type'] = tls_data.get('tls.handshake.type')
                tls_info['cipher_suites'] = tls_data.get('tls.handshake.ciphersuites')
                tls_info['compression_methods'] = tls_data.get('tls.handshake.comp_methods')
                tls_info['extensions'] = tls_data.get('tls.handshake.extensions')
                tls_info['key_exchange'] = tls_data.get('tls.handshake.key_exchange')
                tls_info['certificate'] = tls_data.get('tls.handshake.certificate')
            elif not hasattr(packet.tls, 'handshake') and hasattr(packet.tls, 'app_data'):
                tls_info['tls_record'] = tls_data.get('tls.record')
                tls_info['record_content_type'] = tls_data.get('tls.record.content_type')
                tls_info['record_version'] = tls_data.get('tls.record.version')
                tls_info['record_length'] = tls_data.get('tls.record.length')
                tls_info['app_data'] = tls_data.get('tls.app_data')
        if not tls_info:
            yield 'No TLS (HTTPS) information in this packet'
        else:
            yield tls_info
    except AttributeError as e:
        pass

def filter_tls(network_interface: str, filter_type: str = 'transport_layer') -> iter:
    """
    Captures and filters HTTPS packets from the specified network interface.

    :param network_interface: The network interface to capture packets from.
    :type network_interface: str

    :param filter_type: The type of filter to apply ('transport_layer', 'bpf', or 'display').
    :type filter_type: str

    :yields: Formatted FTP request or response information.
    :rtype: iter of str
    """
    if filter_type == 'transport_layer':
        capture = pyshark.LiveCapture(interface=network_interface)
    elif filter_type == 'bpf':
        capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='tcp port 443')
    elif filter_type == 'display':
        capture = pyshark.LiveCapture(interface=network_interface, display_filter='tls')
    else:
        raise ValueError("Invalid filter_type. Choose 'transport_layer', 'bpf', or 'display'.")

    for packet in capture:
        if filter_type == 'transport_layer' and not (hasattr(packet, 'tcp') and packet.tcp.dstport == '443'):
            continue
        yield from parse_tls_info(packet)

def main():
    """
    Main function to capture and print HTTPS packet information.
    """
    network_interface = 'en0'  # Change to the appropriate interface name
    filter_type = 'display'  # Choose 'transport_layer', 'bpf', or 'display'

    try:
        for https_info in filter_tls(network_interface, filter_type):
            if 'No TLS (HTTPS) information in this packet' not in https_info:
                print(https_info)
    except Exception as error:
        logging.error(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
