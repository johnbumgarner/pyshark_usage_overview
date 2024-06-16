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

def parse_ftp_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses FTP information from the given packet.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: Formatted FTP request or response information.
    :rtype: iter of str
    """
    try:
        if packet.ftp.command:
            source_address = packet.ip.src
            destination_address = packet.ip.dst
            ftp_command = packet.ftp.command
            yield f'FTP Command from {source_address} to {destination_address}: {ftp_command}'
    except AttributeError:
        pass

    try:
        if packet.ftp.response:
            source_address = packet.ip.src
            destination_address = packet.ip.dst
            ftp_response = packet.ftp.response
            yield f'FTP Response from {source_address} to {destination_address}: {ftp_response}'
    except AttributeError:
        pass

def filter_ftp(network_interface: str, filter_type: str = 'transport_layer') -> iter:
    """
    Captures and filters FTP packets from the specified network interface.

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
        capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='tcp port 21')
    elif filter_type == 'display':
        capture = pyshark.LiveCapture(interface=network_interface, display_filter='ftp')
    else:
        raise ValueError("Invalid filter_type. Choose 'transport_layer', 'bpf', or 'display'.")

    for packet in capture:
        if filter_type == 'transport_layer' and not (hasattr(packet, 'tcp') and packet.tcp.dstport == '21'):
            continue
        yield from parse_ftp_info(packet)

def main():
    """
    Main function to capture and print FTP packet information.
    """
    network_interface = 'en0'  # Change to the appropriate interface name
    filter_type = 'transport_layer'  # Choose 'transport_layer', 'bpf', or 'display'

    try:
        for ftp_info in filter_ftp(network_interface, filter_type):
            if ftp_info is not None:
                print(ftp_info)
    except Exception as error:
        logging.error(f"An error occurred: {error}")

if __name__ == "__main__":
    main()





