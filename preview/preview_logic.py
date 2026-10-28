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


#Generates a multi-line, structured Wireshark-style hex/ASCII dump window.
def hexdump_preview(data, max_bytes=256):
    if not data:
        return f"{DIM}   [ No Payload Data / Headers Only ]{CLR}"
    
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        
        hex_parts = [f"{b:02X}" for b in chunk]
        if len(hex_parts) > 8:
            hex_str = ' '.join(hex_parts[:8]) + '  ' + ' '.join(hex_parts[8:])
        else:
            hex_str = ' '.join(hex_parts)
            
        pad_length = 49 - (len(hex_parts) * 3 + (1 if len(hex_parts) > 8 else 0))
        hex_str += ' ' * max(0, pad_length)
        
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else f"{DIM}.{CLR}{WHITE}" for b in chunk)
        lines.append(f"   {DIM}{i:04X}{CLR}  {WHITE}{hex_str} │ {ascii_str}{CLR}")
        
    if len(data) > max_bytes:
        lines.append(f"   {DIM}... ({len(data) - max_bytes} more data bytes truncated) ...{CLR}")
        
    return lines