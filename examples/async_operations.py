# This example shows how to use asyncio programming with PyShark.
# In the example below PyShark is executed in LiveCapture mode.
# During this operation another function is also called.
# Asyncio allows these two operations to run in concurrent with each other.

##################################################################################
# Python imports required for basic operations
##################################################################################
# Standard library imports
import asyncio
import threading
from typing import Any
import queue
# Third-party imports
import pyshark
# Import Packet class from pyshark.packet.packet
from pyshark.packet.packet import Packet

# Thread-safe queue to hold captured packets
packet_queue: queue.Queue = queue.Queue()

def capture_packets(interface: str) -> None:
    """
    Captures packets on the specified network interface using pyshark.LiveCapture
    and puts each packet into the packet_queue.

    :param interface: The network interface to capture packets on.
    :param type interface: str
    """
    capture = pyshark.LiveCapture(interface=interface)

    def packet_handler(packet: Any) -> None:
        packet_queue.put(packet)

    capture.apply_on_packets(packet_handler, timeout=100)

async def process_packets() -> None:
    """
    Asynchronously processes packets from the packet_queue.
    """
    while True:
        try:
            packet = packet_queue.get_nowait()
            await process_packet(packet)
        except queue.Empty:
            await asyncio.sleep(0.1)

async def process_packet(packet: Packet) -> None:
    """
    Processes an individual packet, extracting and printing IP and TCP information.

    :param packet: The packet to process.
    :param type packet: pyshark.packet.packet.Packet
    """
    try:
        if 'IP' in packet:
            print(f'IP Packet: {packet.ip.src} -> {packet.ip.dst}')
        if 'TCP' in packet:
            print(f'TCP Packet: {packet.tcp.srcport} -> {packet.tcp.dstport}')
    except AttributeError:
        # Handle packets that don't have the expected attributes
        pass

async def do_other_tasks() -> None:
    """
    Simulates performing other asynchronous tasks.
    """
    while True:
        print("Performing other tasks...")
        await asyncio.sleep(2)  # Simulate doing other work

async def main() -> None:
    """
    Main coroutine that starts the packet capture in a separate thread and
    runs the packet processing and other tasks concurrently.
    """
    interface = 'en0'

    # Start the packet capture in a separate thread
    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
    capture_thread.start()

    await asyncio.gather(
        process_packets(),
        do_other_tasks()
    )

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down...")
