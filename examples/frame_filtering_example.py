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
# Date Completed: June 29, 2024
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

###############################################################################################
# Frame Data Elements
#
# frame.section_number: The section number in a multi-section capture file.
#
# frame.interface_id: The identifier for the network interface on which the packet was captured.
#
# frame.interface_name: The name of the network interface on which the packet was captured.
#
# frame.interface_description: A description of the network interface on which the packet was captured.
#
# frame.encap_type: The encapsulation type of the packet (link-layer header type).
#
# frame.time: The timestamp of the packet capture in local time.
#
# frame.time_utc: The timestamp of the packet capture in Coordinated Universal Time (UTC).
#
# frame.time_epoch The timestamp of the packet capture in epoch time (seconds since January 1, 1970).
#
# frame.offset_shift: The time offset shift applied to the packet timestamp.
#
# frame.time_delta: The time difference between this packet and the previous packet.
#
# frame.time_delta_displayed: The time difference displayed between this packet and the previous packet (may be
# affected by display filters).
#
# frame.time_relative: The time relative to the beginning of the capture.
#
# frame.number: The frame number in the capture file.
#
# frame.len: The length of the packet on the wire (including all headers).
#
# frame.cap_len: The actual length of the captured packet in the capture file.
#
# frame.marked: Indicates whether the packet is marked for special attention by the user.
#
# frame.ignored: Indicates whether the packet is ignored in the analysis.
#
# frame.protocols: A list of protocols encapsulated in the packet.

##################################################################################
# Python imports required for basic operations
##################################################################################
# Standard library imports
import logging
# Third-party imports
import pyshark

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_frame_info(packet: pyshark.packet.packet.Packet) -> iter:
    """
    Parses Frame information from the given packet.

    :param packet: A pyshark packet object.
    :type packet: pyshark.packet.packet.Packet

    :yields: Formatted Frame information.
    :rtype: iter of str
    """
    try:
        if packet.frame_info:
            frame_interface_name = packet.frame_info.interface_name
            frame_interface_description = packet.frame_info.interface_description
            frame_time = packet.frame_info.time
            protocols = packet.frame_info.protocols
            yield {'frame_information: ' 
                   f'interface_name: {frame_interface_name}, '
                   f'interface_description: {frame_interface_description}, '
                   f'frame_time: {frame_time}, '
                   f'protocols: { protocols}'}
    except AttributeError:
        pass

def filter_frame(network_interface: str) -> iter:
    """
    Captures and filters packets from the specified network interface.

    :param network_interface: The network interface to capture packets from.
    :type network_interface: str

    :yields: Formatted Frame information.
    :rtype: iter of str
    """
    capture = pyshark.LiveCapture(interface=network_interface)

    for packet in capture:
        yield from parse_frame_info(packet)

def main():
    """
    Main function to capture and parse FRAME packet information.
    """
    network_interface = 'en0'  # Change to the appropriate interface name

    try:
        for frame_info in filter_frame(network_interface):
            if frame_info is not None:
                print(frame_info)
    except Exception as error:
        logging.error(f"An error occurred: {error}")

if __name__ == "__main__":
    main()





