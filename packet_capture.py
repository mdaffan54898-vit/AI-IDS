import pyshark

def list_available_interfaces():
    """
    Lists available network interfaces.
    Note: This may require administrative privileges and Wireshark/tshark installed.
    """
    try:
        interfaces = pyshark.get_if_list()
        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        return []

def capture_packets(interface, num_packets):
    """
    Stream packets from the given network interface.

    If num_packets is a positive integer, capture that many packets then return.
    If num_packets is None or <= 0, treat it as "run forever" and stream packets
    until the process is terminated (useful for a long-running IDS process).

    This function is a generator that yields captured packets as they arrive.
    """
    try:
        # Create a live capture object
        capture = pyshark.LiveCapture(interface=interface)

        run_forever = (num_packets is None) or (int(num_packets) <= 0)
        print(f"Starting packet capture on interface '{interface}' for {'infinite' if run_forever else num_packets} packets...")

        packet_count = 0
        for packet in capture.sniff_continuously():
            packet_count += 1
            try:
                src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            except Exception:
                src = 'N/A'
            try:
                dst = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            except Exception:
                dst = 'N/A'
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A'
            print(f"Captured packet {packet_count}: Source IP: {src}, Destination IP: {dst}, Protocol: {proto}")

            yield packet

            if not run_forever and packet_count >= int(num_packets):
                break

        try:
            capture.close()
        except Exception:
            pass

        print(f"\nTotal packets captured: {packet_count}")

    except Exception as e:
        print(f"Error during packet capture: {e}")
        return

def main():
    """
    Main function to run the packet capture script.
    """
    print("Network Packet Capture Script using Pyshark")
    print("=" * 50)

    # List available interfaces
    interfaces = list_available_interfaces()
    if interfaces:
        print("Available interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
    else:
        print("Could not list interfaces. Please ensure Wireshark/tshark is installed and you have admin privileges.")

    # Get user input for interface
    interface = input("\nEnter the network interface name (e.g., 'Wi-Fi', 'Ethernet'): ").strip()

    # Get user input for number of packets
    try:
        num_packets = int(input("Enter the number of packets to capture: ").strip())
        if num_packets <= 0:
            raise ValueError("Number must be positive.")
    except ValueError as e:
        print(f"Invalid input for number of packets: {e}")
        return

    # Capture packets
    packets = capture_packets(interface, num_packets)

    # Optionally, you can process the packets further here
    print(f"\nCaptured {len(packets)} packets successfully.")

if __name__ == "__main__":
    main()