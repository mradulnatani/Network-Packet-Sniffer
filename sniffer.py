import socket
import sys
import os
from data_link_layer.mac import ethernet_frame
from transport_layer.icmp import icmp_packet
from transport_layer.tcp import tcp_segment
from transport_layer.udp import udp_segment
from transport_layer.ipv4 import ipv4_packet
from formatting.formatting import format_multi_line,format_bytes
from report_generation.pdf_report_generation import generate_pdf_report
from preview.preview_logic import hexdump_preview
from datetime import datetime
from pathlib import Path

# ANSI Escape Sequences for Professional Terminal UI Styling
CLR      = "\033[0m"           # Reset all styling
BOLD     = "\033[1m"           # Bold Text
DIM      = "\033[2m"           # Dark Slate Grey
CYAN     = "\033[36m"          # Bright Cyan
GREEN    = "\033[32m"          # Vibrant Green
YELLOW   = "\033[33m"          # Warning Yellow
WHITE    = "\033[37m"          # Crisp White
BG_NAVY  = "\033[48;5;17m"     # Deep Navy Blue Row Background
BG_STRIP = "\033[48;5;234m"    # Charcoal Zebra Stripe Background
TEXT_HDR = "\033[38;5;214m"    # Amber Header Text


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    connections = {}
    total_packets = 0
    total_bytes_captured = 0
    start_time = datetime.now()
    latest_packet_info = {
        'proto': 'None', 'src': '-', 'dst': '-', 'details': 'Waiting for packets...', 'payload': b''
    }

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            packet_len = len(raw_data)
            total_packets += 1
            total_bytes_captured += packet_len

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            proto_str = f"Eth:{eth_proto}"
            src_display = src_mac
            dst_display = dest_mac
            dst_port = "-"
            payload_data = data
            details_str = f"Eth Proto: {eth_proto}"

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                src_display = src
                dst_display = target
                payload_data = data
                details_str = f"IPv4 (TTL: {ttl}, Ver: {version})"

                if proto == 1:
                    proto_str = "ICMP"
                    icmp_type, code, checksum, data = icmp_packet(data)
                    payload_data = data
                    details_str = f"ICMP Type: {icmp_type}, Code: {code}"
                elif proto == 6:
                    proto_str = "TCP"
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                    dst_port = str(dest_port)
                    payload_data = data
                    
                    flags = []
                    if flag_urg: flags.append("URG")
                    if flag_ack: flags.append("ACK")
                    if flag_psh: flags.append("PSH")
                    if flag_rst: flags.append("RST")
                    if flag_syn: flags.append("SYN")
                    if flag_fin: flags.append("FIN")
                    flags_joined = ', '.join(flags) if flags else "NONE"
                    details_str = f"Seq: {sequence}, Ack: {acknowledgement} | Flags: [{flags_joined}]"
                    
                elif proto == 17:
                    proto_str = "UDP"
                    (src_port, dest_port, size, data) = udp_segment(data)
                    dst_port = str(dest_port)
                    payload_data = data
                    details_str = f"UDP Length Size: {size} bytes"
                else:
                    proto_str = f"IP:{proto}"

            # Update Metrics Matrix using accurate array indexing selectors
            conn_key = (proto_str, src_display, dst_display, dst_port)
            if conn_key not in connections:
                connections[conn_key] = [0, 0]
            
            connections[conn_key][0] += 1          
            connections[conn_key][1] += packet_len  
            
            latest_packet_info = {'proto': proto_str,'src': src_display,'dst': dst_display,'details': details_str,'payload': payload_data}

            if len(connections) > 500:
                oldest_key = next(iter(connections))
                del connections[oldest_key]

            # --- DYNAMIC TERMINAL SIZE CALCULATION ---
            try:
                term_cols, term_rows = os.get_terminal_size()
            except OSError:
                term_cols, term_rows = 80, 24  # Standard default fallback

            # Allocate vertical spacing dynamically (htop style calculation layout)
            # Static rows: Header(4), Labels(2), Inspector Header(4), Footer(2) -> ~12 rows fixed overhead
            overhead_rows = 12
            available_rows = max(6, term_rows - overhead_rows)
            
            # Split the available panel space 60% Matrix Grid, 40% Hex Inspector
            top_view_rows = max(3, int(available_rows * 0.6))
            bottom_view_rows = max(3, available_rows - top_view_rows)

            # --- LIVE RENDER PANEL ---
            sys.stdout.write("\033[H\033[J")
            
            # 1. Main Full-width Banner Title Block
            header_title = " FULL-SCREEN NETWORK TRAFFIC METRIC SNIFFER DASHBOARD "
            print(f"{BOLD}{BG_NAVY}{WHITE}{header_title:<{term_cols}}{CLR}")
            
            box_width = term_cols - 2
            print(f"{DIM}┌{'─' * box_width}┐{CLR}")
            stat_line = f" Total Streams Tracked: {len(connections)}  │  Total Packets Logged: {total_packets}"
            print(f"{DIM}│{CLR} {BOLD}{stat_line:<{box_width - 2}}{CLR} {DIM}│{CLR}")
            print(f"{DIM}└{'─' * box_width}┘{CLR}")
            
            # 2. TOP VIEW GRID: Connection Stream Matrix Rows
            print(f"{BOLD}{TEXT_HDR}{' PROTO':<9}{'SOURCE ADDRESS':<22}{'DESTINATION ADDRESS':<22}{'PORT':<9}{'PACKETS':<12}{'DATA VOLUME':<15}{CLR}")
            print(f"{DIM}┠{'─' * box_width}┨{CLR}")

            # Correct entry value index targeting for packet volume sorting
            sorted_streams = sorted(connections.items(), key=lambda x: x[1][0], reverse=True)

            for idx, (conn_info, metrics) in enumerate(sorted_streams[:top_view_rows]):
                prt, src, dst, port = conn_info
                pkt_cnt, byte_cnt = metrics
                row_bg = BG_STRIP if idx % 2 == 0 else ""
                
                c_prt  = f"{row_bg} {BOLD}{CYAN}{prt:<8}{CLR}"
                c_src  = f"{row_bg}{src:<22}{CLR}"
                c_dst  = f"{row_bg}{dst:<22}{CLR}"
                c_port = f"{row_bg}{YELLOW}{port:<9}{CLR}"
                c_pkt  = f"{row_bg}{GREEN}{pkt_cnt:<12}{CLR}"
                c_byte = f"{row_bg}{WHITE}{format_bytes(byte_cnt):<15}{CLR}"
                
                # Fill trailing gaps dynamically to avoid color bleeding past borders
                row_str = f"{c_prt}{c_src}{c_dst}{c_port}{c_pkt}{c_byte}"
                print(row_str)

            # 3. BOTTOM VIEW PANEL: Wireshark Dynamic Hex Inspection Window
            print(f"\n{BOLD}{TEXT_HDR}🔍 FULL-SIZE LIVE PACKET INSPECTOR (WIRESHARK-STYLE DEEP DATA DUMP){CLR}")
            print(f"{DIM}┠{'─' * box_width}┨{CLR}")
            print(f" {BOLD}Stream Link:{CLR}  {CYAN}{latest_packet_info['proto']}{CLR} :: {latest_packet_info['src']} -> {latest_packet_info['dst']}")
            print(f" {BOLD}Meta Info:{CLR}    {YELLOW}{latest_packet_info['details']}{CLR}")
            print(f" {BOLD}Hex Dump Breakdown:{CLR}")
            
            # Render lines dynamically matching calculated remaining console blocks
            hex_lines = hexdump_preview(latest_packet_info['payload'], max_bytes=bottom_view_rows * 16)
            for line in hex_lines[:bottom_view_rows]:
                print(line)
                
            print(f"{DIM}┠{'─' * box_width}┨{CLR}")
            print(f" {DIM}[Full Window Size Active | Maximize your window for more rows | Ctrl+C to Exit Safely]{CLR}")
            sys.stdout.flush()

    except KeyboardInterrupt:
        end_time = datetime.now()

    print(
        f"\n\n{BOLD}{YELLOW}"
        "Monitoring dashboard halted successfully."
        f"{CLR}"
    )

    try:
        generate_pdf_report(connections=connections,total_packets=total_packets,total_bytes_captured=total_bytes_captured,start_time=start_time,end_time=end_time,latest_packet_info=latest_packet_info)

    except Exception as error:
        print(
            f"{YELLOW}Failed to generate PDF report: "
            f"{error}{CLR}"
        )

    finally:
        conn.close()
        print("Network socket closed.")
if __name__ == '__main__':
    main()
