// packet_parser_512.v - 512-bit parallel packet parser for 100G Ethernet MAC
// Extracts all headers in a single cycle from 512-bit input for minimal latency
// Supports Ethernet/IP/TCP/UDP/ICMP packet parsing

module packet_parser (
    input clk,
    input rst,
    input [511:0] data,              // 512-bit data from 100G Ethernet MAC
    input [5:0] byte_count,          // Valid bytes in this word (1-64)
    input valid,                      // Data valid
    input sop,                        // Start of packet
    input eop,                        // End of packet
    
    // Extracted headers
    output reg [31:0] src_ip,
    output reg [31:0] dst_ip,
    output reg [15:0] src_port,
    output reg [15:0] dst_port,
    output reg [7:0] protocol,
    output reg [31:0] tcp_seq,
    output reg [31:0] tcp_ack_num,
    output reg [15:0] tcp_window,
    output reg [15:0] tcp_checksum,
    output reg [15:0] tcp_urgent_ptr,
    output reg [3:0] tcp_data_offset,
    output reg [7:0] tcp_flags,
    output reg tcp_syn,
    output reg tcp_ack,
    output reg tcp_fin,
    output reg tcp_rst,
    output reg tcp_psh,
    output reg tcp_urg,
    output reg [15:0] payload_len,
    output reg checksum_valid,
    output reg [1:0] packet_type,    // 0: TCP, 1: UDP, 2: ICMP/Other
    output reg [7:0] icmp_type,
    output reg [7:0] icmp_code,
    output reg [15:0] icmp_checksum,
    output reg [15:0] icmp_id,
    output reg [15:0] icmp_seq,
    output reg [15:0] ip_identification,
    output reg ip_more_fragments,
    output reg [12:0] ip_frag_offset,
    output reg [15:0] ip_total_length,
    output reg parse_done
);

// Helper function to extract bit ranges from 512-bit data
// Note: Ethernet frames are big-endian; byte 0 is at bits [511:504]
function [7:0] get_byte(input [511:0] data, input [5:0] byte_idx);
    get_byte = data[(511 - (byte_idx << 3)) -: 8];
endfunction

function [15:0] get_word16(input [511:0] data, input [5:0] byte_idx);
    get_word16 = data[(511 - (byte_idx << 3)) -: 16];
endfunction

function [31:0] get_word32(input [511:0] data, input [5:0] byte_idx);
    get_word32 = data[(511 - (byte_idx << 3)) -: 32];
endfunction

// Combinational extraction of all fields from 512-bit input
// This enables single-cycle parsing for minimal latency
wire [7:0] eth_dest_0, eth_dest_1, eth_dest_2, eth_dest_3, eth_dest_4, eth_dest_5;
wire [7:0] eth_src_0, eth_src_1, eth_src_2, eth_src_3, eth_src_4, eth_src_5;
wire [15:0] eth_type;
wire [3:0] ip_version, ip_header_len_words;
wire [15:0] ip_total_len, ip_ident;
wire [2:0] ip_flags;
wire [12:0] ip_frag_off;
wire [31:0] ip_src, ip_dst;
wire [7:0] ip_proto;
wire [15:0] ip_checksum;
wire [15:0] tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_flags_word, tcp_win;
wire [15:0] tcp_csum, tcp_urg_ptr;
wire [3:0] tcp_hdr_len;
wire [7:0] icmp_type_val, icmp_code_val;
wire [15:0] icmp_csum, icmp_id_val, icmp_seq_val;
wire udp_src_port, udp_dst_port, udp_len, udp_csum;

// Extract Ethernet header (bytes 0-13)
assign eth_dest_0 = get_byte(data, 6'd0);
assign eth_dest_1 = get_byte(data, 6'd1);
assign eth_dest_2 = get_byte(data, 6'd2);
assign eth_dest_3 = get_byte(data, 6'd3);
assign eth_dest_4 = get_byte(data, 6'd4);
assign eth_dest_5 = get_byte(data, 6'd5);
assign eth_src_0 = get_byte(data, 6'd6);
assign eth_src_1 = get_byte(data, 6'd7);
assign eth_src_2 = get_byte(data, 6'd8);
assign eth_src_3 = get_byte(data, 6'd9);
assign eth_src_4 = get_byte(data, 6'd10);
assign eth_src_5 = get_byte(data, 6'd11);
assign eth_type = get_word16(data, 6'd12);  // EtherType at bytes 12-13

// Extract IP header (bytes 14-33 for standard header)
// Assuming SOP aligns Ethernet header at byte 0
wire [7:0] ip_version_ihl = get_byte(data, 6'd14);
wire [7:0] ip_dscp_ecn = get_byte(data, 6'd15);
assign ip_total_len = get_word16(data, 6'd16);
assign ip_ident = get_word16(data, 6'd18);
wire [15:0] ip_flags_frag = get_word16(data, 6'd20);
wire [7:0] ip_ttl = get_byte(data, 6'd22);
assign ip_proto = get_byte(data, 6'd23);
assign ip_checksum = get_word16(data, 6'd24);
assign ip_src = get_word32(data, 6'd26);
assign ip_dst = get_word32(data, 6'd30);

// Decode IP fields
assign ip_version = ip_version_ihl[7:4];
assign ip_header_len_words = ip_version_ihl[3:0];
assign ip_flags = ip_flags_frag[15:13];
assign ip_frag_off = ip_flags_frag[12:0];

// Extract TCP header (at byte 34 for standard IP header)
wire [5:0] tcp_base_offset = 6'd34;  // 14 (Eth) + 20 (IP standard)
assign tcp_src_port = get_word16(data, tcp_base_offset);
assign tcp_dst_port = get_word16(data, tcp_base_offset + 2);
assign tcp_seq_num = get_word32(data, tcp_base_offset + 4);
assign tcp_ack_num = get_word32(data, tcp_base_offset + 8);
wire [15:0] tcp_hdr_flags = get_word16(data, tcp_base_offset + 12);
assign tcp_hdr_len = tcp_hdr_flags[15:12];
assign tcp_flags_word = get_word16(data, tcp_base_offset + 12);
assign tcp_win = get_word16(data, tcp_base_offset + 14);
assign tcp_csum = get_word16(data, tcp_base_offset + 16);
assign tcp_urg_ptr = get_word16(data, tcp_base_offset + 18);

// Extract UDP header (at byte 34 for standard IP header)
wire [5:0] udp_base_offset = 6'd34;  // Same as TCP

// Extract ICMP header (at byte 34 for standard IP header)
wire [5:0] icmp_base_offset = 6'd34;
assign icmp_type_val = get_byte(data, icmp_base_offset);
assign icmp_code_val = get_byte(data, icmp_base_offset + 1);
assign icmp_csum = get_word16(data, icmp_base_offset + 2);
assign icmp_id_val = get_word16(data, icmp_base_offset + 4);
assign icmp_seq_val = get_word16(data, icmp_base_offset + 6);

// Validation checks
wire is_ipv4 = (ip_version == 4'h4);
wire is_valid_eth_frame = (byte_count >= 6'd14);  // At least Ethernet header
wire is_valid_ip_header = is_ipv4 && is_valid_eth_frame && (eth_type == 16'h0800);
wire is_tcp = (ip_proto == 8'h06) && is_valid_ip_header;
wire is_udp = (ip_proto == 8'h11) && is_valid_ip_header;
wire is_icmp = (ip_proto == 8'h01) && is_valid_ip_header;
wire is_standard_ip_header = (ip_header_len_words == 4'd5);  // 5 * 4 = 20 bytes

// Calculate payload length
wire [15:0] ip_header_len_bytes = {ip_header_len_words, 2'b00};  // * 4
wire [15:0] calc_tcp_header_len = {tcp_hdr_len, 2'b00};  // * 4
wire [15:0] calc_payload_len = (ip_total_len > ip_header_len_bytes) ? (ip_total_len - ip_header_len_bytes) : 16'd0;
wire [15:0] calc_tcp_payload_len = (calc_payload_len > calc_tcp_header_len) ? (calc_payload_len - calc_tcp_header_len) : 16'd0;

// Sequential register updates on clock
always @(posedge clk or posedge rst) begin
    if (rst) begin
        src_ip <= 32'd0;
        dst_ip <= 32'd0;
        src_port <= 16'd0;
        dst_port <= 16'd0;
        protocol <= 8'd0;
        tcp_seq <= 32'd0;
        tcp_ack_num <= 32'd0;
        tcp_window <= 16'd0;
        tcp_checksum <= 16'd0;
        tcp_urgent_ptr <= 16'd0;
        tcp_data_offset <= 4'd0;
        tcp_flags <= 8'd0;
        tcp_syn <= 1'b0;
        tcp_ack <= 1'b0;
        tcp_fin <= 1'b0;
        tcp_rst <= 1'b0;
        tcp_psh <= 1'b0;
        tcp_urg <= 1'b0;
        payload_len <= 16'd0;
        checksum_valid <= 1'b0;
        packet_type <= 2'd0;
        icmp_type <= 8'd0;
        icmp_code <= 8'd0;
        icmp_checksum <= 16'd0;
        icmp_id <= 16'd0;
        icmp_seq <= 16'd0;
        ip_identification <= 16'd0;
        ip_more_fragments <= 1'b0;
        ip_frag_offset <= 13'd0;
        ip_total_length <= 16'd0;
        parse_done <= 1'b0;
    end else if (valid) begin
        // Store IP fields
        src_ip <= ip_src;
        dst_ip <= ip_dst;
        protocol <= ip_proto;
        ip_identification <= ip_ident;
        ip_more_fragments <= ip_flags[1];
        ip_frag_offset <= ip_frag_off;
        ip_total_length <= ip_total_len;
        
        // Reset protocol-specific fields each cycle
        tcp_syn <= 1'b0;
        tcp_ack <= 1'b0;
        tcp_fin <= 1'b0;
        tcp_rst <= 1'b0;
        tcp_psh <= 1'b0;
        tcp_urg <= 1'b0;
        packet_type <= 2'b10;  // Default to other
        payload_len <= 16'd0;
        parse_done <= 1'b0;
        
        // TCP packet
        if (is_tcp && is_standard_ip_header) begin
            src_port <= tcp_src_port;
            dst_port <= tcp_dst_port;
            tcp_seq <= tcp_seq_num;
            tcp_ack_num <= tcp_ack_num;
            tcp_window <= tcp_win;
            tcp_checksum <= tcp_csum;
            tcp_urgent_ptr <= tcp_urg_ptr;
            tcp_data_offset <= tcp_hdr_len;
            tcp_flags <= tcp_flags_word[7:0];  // Extract flags from flags field
            tcp_syn <= tcp_flags_word[1];
            tcp_ack <= tcp_flags_word[4];
            tcp_fin <= tcp_flags_word[0];
            tcp_rst <= tcp_flags_word[2];
            tcp_psh <= tcp_flags_word[3];
            tcp_urg <= tcp_flags_word[5];
            payload_len <= calc_tcp_payload_len;
            packet_type <= 2'b00;
            parse_done <= 1'b1;
            checksum_valid <= 1'b1;  // TODO: Implement actual checksum validation
        end
        // UDP packet
        else if (is_udp && is_standard_ip_header) begin
            src_port <= get_word16(data, udp_base_offset);
            dst_port <= get_word16(data, udp_base_offset + 2);
            payload_len <= calc_payload_len;
            packet_type <= 2'b01;
            parse_done <= 1'b1;
            checksum_valid <= 1'b1;
        end
        // ICMP packet
        else if (is_icmp && is_standard_ip_header) begin
            icmp_type <= icmp_type_val;
            icmp_code <= icmp_code_val;
            icmp_checksum <= icmp_csum;
            icmp_id <= icmp_id_val;
            icmp_seq <= icmp_seq_val;
            payload_len <= calc_payload_len;
            packet_type <= 2'b10;
            parse_done <= 1'b1;
            checksum_valid <= 1'b1;
        end
        // Fragmented or unsupported protocol
        else begin
            packet_type <= 2'b10;
            parse_done <= 1'b1;
            checksum_valid <= 1'b0;
        end
    end
end

endmodule
