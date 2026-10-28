from formatting.formatting import format_bytes

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


CLR      = "\033[0m"           
BOLD     = "\033[1m"           
DIM      = "\033[2m"           
CYAN     = "\033[36m"         
GREEN    = "\033[32m"         
YELLOW   = "\033[33m"         
WHITE    = "\033[37m"         
BG_NAVY  = "\033[48;5;17m"    
BG_STRIP = "\033[48;5;234m"    
TEXT_HDR = "\033[38;5;214m"   

def generate_pdf_report(
    connections,
    total_packets,
    total_bytes_captured,
    start_time,
    end_time,
    latest_packet_info
):
    """Generate a professionally formatted PDF network traffic report."""

    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = end_time.strftime("%Y%m%d_%H%M%S")
    pdf_path = report_dir / f"network_report_{timestamp}.pdf"

    duration = (end_time - start_time).total_seconds()


    protocol_stats = {}

    stream_records = []

    for (proto, src, dst, port), metrics in connections.items():
        packet_count, byte_count = metrics

        if proto not in protocol_stats:
            protocol_stats[proto] = {
                "packets": 0,
                "bytes": 0
            }

        protocol_stats[proto]["packets"] += packet_count
        protocol_stats[proto]["bytes"] += byte_count

        stream_records.append({
            "protocol": proto,
            "source": src,
            "destination": dst,
            "port": port,
            "packets": packet_count,
            "bytes": byte_count
        })

    top_by_packets = sorted(
        stream_records,
        key=lambda item: item["packets"],
        reverse=True
    )[:10]

    top_by_bytes = sorted(
        stream_records,
        key=lambda item: item["bytes"],
        reverse=True
    )[:10]



    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title="Network Traffic Analysis Report",
        author="Network Traffic Metric Sniffer"
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=28,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#526579"),
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    ))

    styles.add(ParagraphStyle(
        name="SmallCell",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    ))

    styles.add(ParagraphStyle(
        name="HexDump",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        wordWrap="CJK"
    ))

    story = []


    story.append(Paragraph(
        "NETWORK TRAFFIC ANALYSIS REPORT",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "Network Traffic Metric Sniffer | Session Summary",
        styles["ReportSubtitle"]
    ))

    story.append(Paragraph(
        "1. SESSION OVERVIEW",
        styles["SectionHeading"]
    ))

    overview_data = [
        ["Metric", "Value", "Metric", "Value"],
        [
            "Session Start",
            start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Session End",
            end_time.strftime("%Y-%m-%d %H:%M:%S")
        ],
        [
            "Duration",
            f"{duration:.2f} seconds",
            "Total Packets Captured",
            f"{total_packets:,}"
        ],
        [
            "Total Bytes Captured",
            f"{total_bytes_captured:,} bytes",
            "Total Data Captured",
            format_bytes(total_bytes_captured)
        ],
        [
            "Tracked Streams",
            f"{len(connections):,}",
            "Average Capture Rate",
            (
                f"{total_packets / duration:.2f} packets/sec"
                if duration > 0 else "N/A"
            )
        ]
    ]

    overview_table = Table(
        overview_data,
        colWidths=[42 * mm, 70 * mm, 42 * mm, 70 * mm]
    )

    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#EAF0F6")),
        ("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#EAF0F6")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C7D9")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(overview_table)


    story.append(Paragraph(
        "2. PROTOCOL DISTRIBUTION",
        styles["SectionHeading"]
    ))

    protocol_data = [[
        "Protocol",
        "Packets",
        "Captured Bytes",
        "Data Volume",
        "Packet Share"
    ]]

    for proto, stats in sorted(
        protocol_stats.items(),
        key=lambda item: item[1]["packets"],
        reverse=True
    ):
        packet_share = (
            stats["packets"] / total_packets * 100
            if total_packets else 0
        )

        protocol_data.append([
            proto,
            f"{stats['packets']:,}",
            f"{stats['bytes']:,}",
            format_bytes(stats["bytes"]),
            f"{packet_share:.2f}%"
        ])

    protocol_table = Table(
        protocol_data,
        colWidths=[45 * mm, 35 * mm, 45 * mm, 45 * mm, 40 * mm],
        repeatRows=1
    )

    protocol_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#217346")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2DF")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9")
        ]),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(protocol_table)


    def create_stream_table(records, title):
        story.append(Paragraph(title, styles["SectionHeading"]))

        data = [[
            "Protocol",
            "Source Address",
            "Destination Address",
            "Destination Port",
            "Packets",
            "Data Volume"
        ]]

        for item in records:
            data.append([
                item["protocol"],
                Paragraph(str(item["source"]), styles["SmallCell"]),
                Paragraph(str(item["destination"]), styles["SmallCell"]),
                str(item["port"]),
                f"{item['packets']:,}",
                format_bytes(item["bytes"])
            ])

        table = Table(
            data,
            colWidths=[
                27 * mm,
                55 * mm,
                55 * mm,
                30 * mm,
                27 * mm,
                30 * mm
            ],
            repeatRows=1
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2DF")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#F1F5F9")
            ]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))

        story.append(table)

    create_stream_table(
        top_by_packets,
        "3. TOP 10 STREAMS BY PACKET COUNT"
    )

    create_stream_table(
        top_by_bytes,
        "4. TOP 10 STREAMS BY DATA VOLUME"
    )


    story.append(PageBreak())

    story.append(Paragraph(
        "5. COMPLETE STREAM INVENTORY",
        styles["SectionHeading"]
    ))

    all_stream_data = [[
        "Protocol",
        "Source Address",
        "Destination Address",
        "Port",
        "Packets",
        "Bytes"
    ]]

    for item in sorted(
        stream_records,
        key=lambda stream: stream["packets"],
        reverse=True
    ):
        all_stream_data.append([
            item["protocol"],
            Paragraph(str(item["source"]), styles["SmallCell"]),
            Paragraph(str(item["destination"]), styles["SmallCell"]),
            str(item["port"]),
            f"{item['packets']:,}",
            f"{item['bytes']:,}"
        ])

    all_stream_table = Table(
        all_stream_data,
        colWidths=[
            25 * mm,
            57 * mm,
            57 * mm,
            23 * mm,
            25 * mm,
            30 * mm
        ],
        repeatRows=1
    )

    all_stream_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2DF")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9")
        ]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
    ]))

    story.append(all_stream_table)

    story.append(Paragraph(
        "6. LAST PACKET INSPECTION",
        styles["SectionHeading"]
    ))

    packet_details = [
        ["Field", "Value"],
        ["Protocol", str(latest_packet_info["proto"])],
        ["Source", str(latest_packet_info["src"])],
        ["Destination", str(latest_packet_info["dst"])],
        ["Packet Details", str(latest_packet_info["details"])],
        [
            "Parsed Payload Size",
            f"{len(latest_packet_info['payload'])} bytes"
        ]
    ]

    packet_table = Table(
        packet_details,
        colWidths=[50 * mm, 180 * mm]
    )

    packet_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#217346")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#EAF0F6")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2DF")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(packet_table)
    story.append(Spacer(1, 10))

    payload_preview = latest_packet_info["payload"][:256]

    hex_text = (
        payload_preview.hex(" ")
        if payload_preview
        else "No payload data available."
    )

    story.append(Paragraph(
        "Hexadecimal Payload Preview (up to 256 bytes)",
        styles["Heading3"]
    ))

    story.append(Paragraph(
        hex_text,
        styles["HexDump"]
    ))

    def add_page_number(canvas, document):
        canvas.saveState()

        page_width, page_height = landscape(A4)

        canvas.setStrokeColor(colors.HexColor("#B8C7D9"))
        canvas.line(
            15 * mm,
            13 * mm,
            page_width - 15 * mm,
            13 * mm
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526579"))

        canvas.drawString(
            15 * mm,
            8 * mm,
            "Network Traffic Metric Sniffer | Confidential"
        )

        canvas.drawRightString(
            page_width - 15 * mm,
            8 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    print(f"\n{BOLD}{GREEN}")
    print("=" * 65)
    print("        NETWORK TRAFFIC REPORT GENERATED")
    print("=" * 65)
    print(f"{WHITE}Total Packets : {total_packets:,}")
    print(f"Total Data    : {format_bytes(total_bytes_captured)}")
    print(f"Duration      : {duration:.2f} seconds")
    print(f"Tracked Streams: {len(connections)}")
    print(f"\nPDF Report    : {pdf_path.resolve()}")
    print(f"{GREEN}{'=' * 65}{CLR}\n")