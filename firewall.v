// firewall.v - Main module for hardware stateful firewall with 512-bit 100G Ethernet MAC input
module firewall (
    input clk,
    input rst,
    input [511:0] packet_data,      // 512-bit data from 100G Ethernet MAC
    input [5:0] packet_byte_count,  // Number of valid bytes in current word (1-64)
    input packet_valid,
    input packet_sop,  // Start of packet
    input packet_eop,  // End of packet
    input time_tick,
    output reg allow_packet,
    output reg packet_ready,
    output reg [3:0] matched_rule_id,
    output reg collision_detected,
    output reg parse_error,
    output reg invalid_packet,  // Invalid packet detected
    output reg [31:0] packet_count,  // Total packets processed
    output reg [31:0] invalid_count,  // Invalid packets count
    output reg syn_flood_alert,
    output reg rst_injection_alert,
    output reg tcp_hijacking_alert,
    output reg udp_rate_limit_alert,
    output reg ack_flood_alert,
    output reg icmp_flood_alert,
    output reg ping_of_death_alert,
    output reg smurf_attack_alert,
    output reg replay_attack_alert,
    output reg null_scan_alert,
    output reg xmas_scan_alert,
    output reg port_scan_alert,
    // Capacity monitoring outputs
    output reg [7:0] table_occupancy,
    output reg [7:0] capacity_percent,
    output reg capacity_alert,
    output reg table_full,
    output reg table_overflow_event
);

// Parameters
parameter MAX_PACKETS = 1024;
parameter STATE_TABLE_SIZE = 256;
parameter TCP_HEADER_MIN = 16'd54;  // Ethernet(14) + IP(20) + TCP(20) = 54 bytes

// Internal payload length calculation (updated for 512-bit input: processes up to 64 bytes per cycle)
reg [15:0] pkt_length_counter;  // Counts bytes in packet for length calculation
wire [15:0] calc_payload_len = (pkt_length_counter > TCP_HEADER_MIN) ? (pkt_length_counter - TCP_HEADER_MIN) : 16'd0;

// Internal signals
wire [31:0] src_ip, dst_ip;
wire [15:0] src_port, dst_port;
wire [7:0] protocol;
wire [31:0] tcp_seq;
wire [31:0] tcp_ack_num;
wire [15:0] tcp_window;
wire [15:0] tcp_checksum;
wire [15:0] tcp_urgent_ptr;
wire [3:0] tcp_data_offset;
wire [7:0] tcp_flags;
wire tcp_syn, tcp_ack, tcp_fin, tcp_rst, tcp_psh, tcp_urg;
wire checksum_valid;
wire [1:0] packet_type;  // 0: TCP, 1: UDP, 2: ICMP
wire [7:0] icmp_type;
wire seq_valid;
wire hijacking_detected;
wire seq_window_violation;
wire [31:0] hijacked_ip;
wire udp_rate_limit_exceeded;
wire [31:0] udp_blocked_ip;
wire [7:0] icmp_code;
wire [15:0] icmp_checksum;
wire [15:0] icmp_id;
wire [15:0] icmp_seq;
wire [15:0] payload_len;  // Payload length for sequence tracking
wire [31:0] expected_seq;  // Expected sequence from state table
wire table_overflow_event_internal;
wire ack_only;
wire ack_flood_detected;
wire [31:0] ack_blocked_src_ip;
wire icmp_flood_detected;
wire [31:0] icmp_blocked_src_ip;
wire icmp_dangerous_type;
wire [31:0] system_time;
wire reassembled_valid, reassembled_sop, reassembled_eop;
wire [7:0] reassembled_data;
wire overlap_conflict, reassembly_timeout;
wire [15:0] ip_identification;
wire ip_more_fragments;
wire [12:0] ip_frag_offset;
wire [15:0] ip_total_length;
reg packet_activity;       // Signal to reset timeout on packet activity

// Replay attack detection
wire replay_attack_detected;
wire [31:0] replay_suspicious_ip;

// Xmas scan detection
wire xmas_scan_detected;
wire [31:0] xmas_suspicious_ip;

// Port scan detection
wire port_scan_detected;
wire [31:0] port_scan_suspicious_ip;

// Packet length counter and payload length assignment
always @(posedge clk or posedge rst) begin
    if (rst) begin
        pkt_length_counter <= 0;
        system_time <= 0;
        table_occupancy <= 0;
        capacity_percent <= 0;
        capacity_alert <= 0;
        table_full <= 0;
        table_overflow_event <= 0;
    end else begin
        system_time <= system_time + 1;
        if (packet_sop) begin
            pkt_length_counter <= packet_byte_count;  // 512-bit: Start with actual byte count from MAC
        end else if (packet_valid && !packet_eop) begin
            pkt_length_counter <= pkt_length_counter + packet_byte_count;  // Add bytes per 512-bit word
        end else if (packet_eop) begin
            pkt_length_counter <= 0;
        end
    end
end

assign payload_len = calc_payload_len;
assign ack_only = tcp_ack && !tcp_syn && !tcp_fin && !tcp_rst && payload_len == 0;

// Packet parser instance - 512-bit optimized
packet_parser parser (
    .clk(clk),
    .rst(rst),
    .data(parser_data),
    .byte_count(parser_byte_count),
    .valid(parser_valid),
    .sop(parser_sop),
    .eop(parser_eop),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .protocol(protocol),
    .tcp_seq(tcp_seq),
    .tcp_ack_num(tcp_ack_num),
    .tcp_window(tcp_window),
    .tcp_checksum(tcp_checksum),
    .tcp_urgent_ptr(tcp_urgent_ptr),
    .tcp_data_offset(tcp_data_offset),
    .tcp_flags(tcp_flags),
    .tcp_syn(tcp_syn),
    .tcp_ack(tcp_ack),
    .tcp_fin(tcp_fin),
    .tcp_rst(tcp_rst),
    .tcp_psh(tcp_psh),
    .tcp_urg(tcp_urg),
    .payload_len(payload_len),
    .checksum_valid(checksum_valid),
    .packet_type(packet_type),
    .icmp_type(icmp_type),
    .icmp_code(icmp_code),
    .icmp_checksum(icmp_checksum),
    .icmp_id(icmp_id),
    .icmp_seq(icmp_seq),
    .ip_identification(ip_identification),
    .ip_more_fragments(ip_more_fragments),
    .ip_frag_offset(ip_frag_offset),
    .ip_total_length(ip_total_length)
);

// State table instance
wire state_valid;
wire [3:0] current_state;
reg update_state;
reg [3:0] new_state;

localparam [3:0] CLOSED      = 4'b0000;
localparam [3:0] SYN_SENT    = 4'b0001;
localparam [3:0] SYN_RCVD    = 4'b0010;
localparam [3:0] ESTABLISHED = 4'b0011;
localparam [3:0] FIN_WAIT_1  = 4'b0100;
localparam [3:0] FIN_WAIT_2  = 4'b0101;
localparam [3:0] CLOSE_WAIT  = 4'b0110;
localparam [3:0] CLOSING     = 4'b0111;
localparam [3:0] LAST_ACK    = 4'b1000;
localparam [3:0] TIME_WAIT   = 4'b1001;

state_table #(.TABLE_SIZE(STATE_TABLE_SIZE)) st (
    .clk(clk),
    .rst(rst),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .packet_type(packet_type),
    .tcp_syn(tcp_syn),
    .tcp_ack(tcp_ack),
    .tcp_fin(tcp_fin),
    .tcp_rst(tcp_rst),
    .tcp_seq(tcp_seq),
    .state_valid(state_valid),
    .current_state(current_state),
    .expected_seq(expected_seq),
    .update_state(update_state),
    .new_state(new_state),
    .time_tick(time_tick),
    .collision_detected(collision_detected),
    .table_occupancy(table_occupancy),
    .capacity_percent(capacity_percent),
    .capacity_alert(capacity_alert),
    .table_full(table_full),
    .table_overflow_event(table_overflow_event_internal)
);

// ACK flood detector instance
ack_flood_detector #(
    .TABLE_SIZE(256),
    .ACK_THRESHOLD(32),
    .TIME_WINDOW(256)
) ack_detector (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid),
    .is_tcp(packet_type == 2'b00),
    .ack_only(ack_only),
    .state_valid(state_valid),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .time_counter(system_time),
    .ack_flood_alert(ack_flood_detected),
    .blocked_src_ip(ack_blocked_src_ip)
);

// Fragment reassembler instance (updated for 512-bit data)
fragment_reassembler #(
    .MAX_FRAGMENTS(8),
    .FRAGMENT_TIMEOUT(1000000),
    .BUFFER_SIZE(2048)
) frag_reassembler (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid && packet_type == 2'b10),  // Only process fragments
    .packet_sop(packet_sop),
    .packet_eop(packet_eop),
    .packet_data(packet_data),
    .packet_byte_count(packet_byte_count),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .identification(ip_identification),
    .more_fragments(ip_more_fragments),
    .frag_offset(ip_frag_offset),
    .total_length(ip_total_length),
    .protocol(protocol),
    .reassembled_valid(reassembled_valid),
    .reassembled_sop(reassembled_sop),
    .reassembled_eop(reassembled_eop),
    .reassembled_data(reassembled_data),
    .overlap_conflict(overlap_conflict),
    .reassembly_timeout(reassembly_timeout)
);

// Mux packet data for parser - use reassembled data if available (512-bit path for 100G Ethernet)
// Note: For now, reassembler bypass maintains original flow; future enhancement needed for full 512-bit reassembly
wire [511:0] parser_data = reassembled_valid ? {reassembled_data, 504'b0} : packet_data;  // Expand 8-bit to 512-bit for reassembler bypass
wire [5:0] parser_byte_count = reassembled_valid ? 6'b1 : packet_byte_count;  // 1 byte from reassembler, full count from MAC
wire parser_valid = reassembled_valid ? reassembled_valid : packet_valid;
wire parser_sop = reassembled_valid ? reassembled_sop : packet_sop;
wire parser_eop = reassembled_valid ? reassembled_eop : packet_eop;

// ICMP flood detector instance
icmp_flood_detector #(
    .TABLE_SIZE(128),
    .ICMP_THRESHOLD(100),
    .TIME_WINDOW(2000)
) icmp_detector (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid),
    .is_icmp(protocol == 8'h01),  // ICMP protocol number
    .icmp_type(icmp_type),
    .src_ip(src_ip),
    .time_counter(system_time),
    .icmp_flood_alert(icmp_flood_detected),
    .blocked_src_ip(icmp_blocked_src_ip),
    .dangerous_icmp_type(icmp_dangerous_type)
);

// Ping of Death Detection
reg ping_of_death_detected;
always @(*) begin
    ping_of_death_detected = 0;
    if (packet_valid && protocol == 8'h01) begin  // ICMP packet
        // Check for oversized ICMP packets (ping of death)
        // IPv4 maximum packet size is 65535 bytes, but ICMP payloads should be reasonable
        if (ip_total_length > 16'd65500) begin
            ping_of_death_detected = 1;
        end
        // Also check for fragmented ICMP packets that might cause issues
        // ICMP should typically not be fragmented for normal ping packets
        if (ip_more_fragments || ip_frag_offset != 13'd0) begin
            // Allow small fragmented ICMP packets but flag large ones
            if (ip_total_length > 16'd1500) begin  // MTU size
                ping_of_death_detected = 1;
            end
        end
    end
end

// Smurf Attack Detection
reg smurf_attack_detected;
always @(*) begin
    smurf_attack_detected = 0;
    if (packet_valid && protocol == 8'h01) begin  // ICMP packet
        // Check for packets sent to broadcast addresses (smurf attack)
        // Limited broadcast: 255.255.255.255
        if (dst_ip == 32'hFFFFFFFF) begin
            smurf_attack_detected = 1;
        end
        // Network broadcast addresses (common patterns)
        // Class A network broadcast: x.255.255.255 where x != 127 (loopback)
        else if (dst_ip[23:0] == 24'hFFFFFF && dst_ip[31:24] != 8'h7F) begin
            smurf_attack_detected = 1;
        end
        // Class B network broadcast: x.x.255.255
        else if (dst_ip[15:0] == 16'hFFFF) begin
            smurf_attack_detected = 1;
        end
        // Class C network broadcast: x.x.x.255
        else if (dst_ip[7:0] == 8'hFF) begin
            smurf_attack_detected = 1;
        end
    end
end

// Replay attack detector instance
replay_attack_detector #(
    .TABLE_SIZE(256),
    .TIME_WINDOW(1000),
    .MAX_DUPLICATES(3)
) replay_detector (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid),
    .is_tcp(packet_type == 2'b00),
    .state_valid(state_valid),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .tcp_seq(tcp_seq),
    .tcp_ack_num(tcp_ack_num),
    .time_counter(system_time),
    .replay_detected(replay_attack_detected),
    .suspicious_ip(replay_suspicious_ip)
);

// Xmas scan detector instance
xmas_scan_detector #(
    .TABLE_SIZE(64),
    .XMAS_THRESHOLD(5),
    .TIME_WINDOW(1000)
) xmas_detector (
    .clk(clk),
    .rst(rst),
    .src_ip(src_ip),
    .tcp_fin(tcp_fin),
    .tcp_psh(tcp_psh),
    .tcp_urg(tcp_urg),
    .packet_valid(packet_valid),
    .xmas_scan_detected(xmas_scan_detected),
    .suspicious_ip(xmas_suspicious_ip)
);

// Port scan detector instance
port_scan_detector #(
    .TABLE_SIZE(64),
    .PORT_THRESHOLD(10),
    .TIME_WINDOW(2000)
) port_detector (
    .clk(clk),
    .rst(rst),
    .src_ip(src_ip),
    .dst_port(dst_port),
    .tcp_syn(tcp_syn),
    .packet_valid(packet_valid),
    .port_scan_detected(port_scan_detected),
    .suspicious_ip(port_scan_suspicious_ip)
);

// Rule checker instance
rule_checker rc (
    .clk(clk),
    .rst(rst),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .protocol(protocol),
    .packet_type(packet_type),
    .state_valid(state_valid),
    .current_state(current_state),
    .tcp_flags(tcp_flags),
    .icmp_type(icmp_type),
    .allow(allow_packet),
    .rule_matched(),
    .matched_rule_id()
);

// TCP hijacking detector
 tcp_hijacking_detector #(.TABLE_SIZE(STATE_TABLE_SIZE)) hijack_det (
    .clk(clk),
    .rst(rst),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .tcp_seq(tcp_seq),
    .tcp_payload_len(payload_len),
    .tcp_syn(tcp_syn),
    .tcp_ack(tcp_ack),
    .tcp_psh(tcp_psh),
    .packet_valid(packet_valid),
    .state_valid(state_valid),
    .current_state(current_state),
    .expected_seq(expected_seq),
    .hijacking_detected(hijacking_detected),
    .anomalous_ip(hijacked_ip),
    .seq_window_violation(seq_window_violation),
    .seq_valid(seq_valid)
);

// UDP rate limiter for state exhaustion protection
udp_rate_limiter #(
    .TABLE_SIZE(64),
    .UDP_PKT_THRESHOLD(64),
    .TIME_WINDOW(1024)
) udp_limiter (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid),
    .is_udp(packet_type == 2'b01),
    .src_ip(src_ip),
    .limit_exceeded(udp_rate_limit_exceeded),
    .blocked_ip(udp_blocked_ip)
);

// State update logic with sequence number window validation
always @(posedge clk or posedge rst) begin
    if (rst) begin
        packet_ready <= 0;
        update_state <= 0;
        new_state <= CLOSED;
        packet_activity <= 0;
        packet_count <= 0;
        invalid_count <= 0;
        invalid_packet <= 0;
        udp_rate_limit_alert <= 0;
        ack_flood_alert <= 0;
        icmp_flood_alert <= 0;
        ping_of_death_alert <= 0;
        smurf_attack_alert <= 0;
        replay_attack_alert <= 0;
        xmas_scan_alert <= 0;
        port_scan_alert <= 0;
        parse_error <= 0;
    end else if (packet_eop) begin
        packet_ready <= 1;
        packet_count <= packet_count + 1;
        update_state <= 0;
        new_state <= current_state;
        packet_activity <= state_valid;  // Reset timeout for any valid connection activity
        parse_error <= 0;
        invalid_packet <= 0;

        if (packet_type == 2'b10 && !reassembled_valid) begin
            // Handle fragmented packets - let reassembler process them
            // Reassembled packets will come through reassembled_* signals
            allow_packet <= 0;  // Don't allow fragments directly
            if (overlap_conflict) begin
                invalid_packet <= 1;
                parse_error <= 1;
                invalid_count <= invalid_count + 1;
            end else if (reassembly_timeout) begin
                invalid_packet <= 1;
                parse_error <= 1;
                invalid_count <= invalid_count + 1;
            end
        end else begin
            // Process normal packets or reassembled packets
            allow_packet <= 1;  // Default allow, checks below may deny
        end

        // Check sequence validity for established connections
        if (allow_packet && packet_type == 0 && state_valid) begin
            // For established connections, verify sequence window
            if (current_state == ESTABLISHED && !seq_valid) begin
                // INVALID sequence - drop packet
                allow_packet <= 0;
                invalid_packet <= 1;
                invalid_count <= invalid_count + 1;
            end
        end

        if (ack_flood_detected) begin
            allow_packet <= 0;
            invalid_packet <= 1;
            invalid_count <= invalid_count + 1;
            ack_flood_alert <= 1;
        end else begin
            ack_flood_alert <= 0;
        end

        if (icmp_flood_detected) begin
            allow_packet <= 0;
            invalid_packet <= 1;
            invalid_count <= invalid_count + 1;
            icmp_flood_alert <= 1;
        end else begin
            icmp_flood_alert <= 0;
        end

        if (ping_of_death_detected) begin
            allow_packet <= 0;
            invalid_packet <= 1;
            invalid_count <= invalid_count + 1;
            ping_of_death_alert <= 1;
        end else begin
            ping_of_death_alert <= 0;
        end

        if (smurf_attack_detected) begin
            allow_packet <= 0;
            invalid_packet <= 1;
            invalid_count <= invalid_count + 1;
            smurf_attack_alert <= 1;
        end else begin
            smurf_attack_alert <= 0;
        end

        if (replay_attack_detected) begin
            allow_packet <= 0;
            invalid_packet <= 1;
            invalid_count <= invalid_count + 1;
            replay_attack_alert <= 1;
        end else begin
            replay_attack_alert <= 0;
        end

        if (allow_packet && packet_type == 2'b01) begin
            if (udp_rate_limit_exceeded) begin
                allow_packet <= 0;
                invalid_packet <= 1;
                invalid_count <= invalid_count + 1;
                udp_rate_limit_alert <= 1;
            end else begin
                udp_rate_limit_alert <= 0;
            end
        end else begin
            udp_rate_limit_alert <= 0;
        end

        if (allow_packet && protocol == 8'h01) begin  // ICMP
            if (icmp_dangerous_type) begin
                // Dangerous ICMP types should be more strictly filtered
                // Allow through but mark for lower threshold in detector
            end
        end

        if (allow_packet && packet_type == 0) begin  // TCP
            if (xmas_scan_detected) begin
                allow_packet <= 0;
                invalid_packet <= 1;
                invalid_count <= invalid_count + 1;
                xmas_scan_alert <= 1;
            end else begin
                xmas_scan_alert <= 0;
            end

            if (port_scan_detected) begin
                allow_packet <= 0;
                invalid_packet <= 1;
                invalid_count <= invalid_count + 1;
                port_scan_alert <= 1;
            end else begin
                port_scan_alert <= 0;
            end

            if (tcp_rst) begin
                // Immediate connection teardown on RST
                new_state <= CLOSED;
                update_state <= 1;
            end else begin
                case (current_state)
                    CLOSED: begin
                        if (tcp_syn && !tcp_ack && !tcp_fin) begin
                            // First SYN: create a new half-open connection
                            new_state <= SYN_SENT;
                            update_state <= 1;
                        end
                    end
                    SYN_SENT: begin
                        if (tcp_syn && tcp_ack) begin
                            // SYN-ACK completes the handshake in the reverse direction
                            new_state <= ESTABLISHED;
                            update_state <= 1;
                        end else if (tcp_syn && !tcp_ack) begin
                            // Simultaneous open - both sides sent SYN
                            new_state <= SYN_RCVD;
                            update_state <= 1;
                        end
                    end
                    SYN_RCVD: begin
                        if (tcp_ack && !tcp_syn) begin
                            // Final ACK of three-way handshake
                            new_state <= ESTABLISHED;
                            update_state <= 1;
                        end
                    end
                    ESTABLISHED: begin
                        // Check sequence validity before state transitions
                        if (!seq_valid) begin
                            // Keep connection in ESTABLISHED but don't process state changes
                        end else if (tcp_fin) begin
                            // Active close: FIN from established connection
                            new_state <= FIN_WAIT_1;
                            update_state <= 1;
                        end
                        // Data/ACK packets keep the connection established
                    end
                    FIN_WAIT_1: begin
                        if (tcp_fin) begin
                            // Simultaneous close
                            new_state <= CLOSING;
                            update_state <= 1;
                        end else if (tcp_ack) begin
                            // FIN acknowledged, wait for peer FIN
                            new_state <= FIN_WAIT_2;
                            update_state <= 1;
                        end
                    end
                    FIN_WAIT_2: begin
                        if (tcp_fin) begin
                            // Peer FIN received
                            new_state <= TIME_WAIT;
                            update_state <= 1;
                        end
                    end
                    CLOSE_WAIT: begin
                        if (tcp_fin) begin
                            // Application has closed, send FIN
                            new_state <= LAST_ACK;
                            update_state <= 1;
                        end
                    end
                    CLOSING: begin
                        if (tcp_ack) begin
                            // Both sides have closed
                            new_state <= TIME_WAIT;
                            update_state <= 1;
                        end
                    end
                    LAST_ACK: begin
                        if (tcp_ack) begin
                            // Final ACK received
                            new_state <= CLOSED;
                            update_state <= 1;
                        end
                    end
                    TIME_WAIT: begin
                        // Stay in TIME_WAIT for 2*MSL (simplified - would timeout)
                        new_state <= CLOSED;
                        update_state <= 1;
                    end
                    default: begin
                        new_state <= current_state;
                    end
                endcase
            end
        end
    end else begin
        packet_ready <= 0;
        update_state <= 0;
        packet_activity <= 0;
        ack_flood_alert <= 0;
    end
end

// TCP Hijacking Detection - Sequence Number Window Validation
// Detects packets with sequence numbers outside expected TCP window
always @(posedge clk or posedge rst) begin
    if (rst) begin
        tcp_hijacking_alert <= 0;
    end else begin
        tcp_hijacking_alert <= hijacking_detected;
    end
end

// Connection Table Overflow Detection and Alerts
// Uses state table overflow events as the source of truth for LRU eviction activity
always @(posedge clk or posedge rst) begin
    if (rst) begin
        table_overflow_event <= 0;
    end else begin
        table_overflow_event <= table_overflow_event_internal;
    end
end

endmodule