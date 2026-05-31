// rule_checker.v - Detailed Rule checker for firewall policies with configurable rules
module rule_checker #(
    parameter NUM_RULES = 16,
    parameter RULE_WIDTH = 136  // Rule format: [action(1), protocol(8), src_port(16), dst_port(16), src_ip(32), dst_ip(32), state_req(2), flags_req(8), icmp_type(8), reserved(1)]
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input [31:0] dst_ip,
    input [15:0] src_port,
    input [15:0] dst_port,
    input [7:0] protocol,
    input packet_type,  // 0: TCP, 1: UDP, 2: ICMP
    input state_valid,
    input [1:0] current_state,
    input [7:0] tcp_flags,  // TCP flags for detailed matching
    input [7:0] icmp_type,  // ICMP type for ICMP packet matching
    output reg allow,
    output reg rule_matched,
    output reg [3:0] matched_rule_id
);

// Define states
localparam CLOSED = 2'b00;
localparam SYN_SENT = 2'b01;
localparam ESTABLISHED = 2'b10;
localparam FIN_WAIT = 2'b11;

// Rule memory
reg [RULE_WIDTH-1:0] rule_table [0:NUM_RULES-1];

// Rule format:
// [135:135] action (0: deny, 1: allow)
// [134:127] protocol (0x06: TCP, 0x11: UDP, 0x01: ICMP, 0xFF: any)
// [126:111] src_port (0xFFFF: any)
// [110:95] dst_port (0xFFFF: any)
// [94:63] src_ip (32'hFFFFFFFF: any)
// [62:31] dst_ip (32'hFFFFFFFF: any)
// [30:29] state_req (2'b11: any state)
// [28:21] flags_req (TCP flags required, 8'hFF: any)
// [20:13] icmp_type (8'hFF: any ICMP type, otherwise specific type)
// [12:0] reserved

initial begin
    // Initialize with default rules (extended format with ICMP type field)
    // Rule 0: Allow established TCP connections
    rule_table[0] = {1'b1, 8'h06, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'hFF, 1'b0};
    // Rule 1: Allow TCP SYN to port 80 (HTTP)
    rule_table[1] = {1'b1, 8'h06, 16'hFFFF, 16'd80, 32'hFFFFFFFF, 32'hFFFFFFFF, CLOSED, 8'h02, 8'hFF, 1'b0};
    // Rule 2: Allow TCP SYN to port 443 (HTTPS)
    rule_table[2] = {1'b1, 8'h06, 16'hFFFF, 16'd443, 32'hFFFFFFFF, 32'hFFFFFFFF, CLOSED, 8'h02, 8'hFF, 1'b0};
    // Rule 3: Allow UDP DNS queries
    rule_table[3] = {1'b1, 8'h11, 16'hFFFF, 16'd53, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'hFF, 1'b0};
    // Rule 4: Allow UDP NTP
    rule_table[4] = {1'b1, 8'h11, 16'hFFFF, 16'd123, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'hFF, 1'b0};
    // Rule 5: Allow ICMP Echo Reply (Type 0)
    rule_table[5] = {1'b1, 8'h01, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'd0, 1'b0};
    // Rule 6: Deny ICMP Echo Request (Type 8) - can implement rate limiting separately
    rule_table[6] = {1'b1, 8'h01, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'd8, 1'b0};
    // Rule 7: Deny ICMP Redirect (Type 5) - potentially dangerous
    rule_table[7] = {1'b0, 8'h01, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'd5, 1'b0};
    // Rule 8: Deny ICMP Timestamp (Type 13) - potentially dangerous
    rule_table[8] = {1'b0, 8'h01, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'd13, 1'b0};
    // Rule 9: Deny all (default deny)
    rule_table[9] = {1'b0, 8'hFF, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'hFF, 1'b0};

    // Initialize remaining rules to deny all
    integer i;
    for (i = 10; i < NUM_RULES; i = i + 1) begin
        rule_table[i] = {1'b0, 8'hFF, 16'hFFFF, 16'hFFFF, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF, 8'hFF, 1'b0};
    end
end

// Rule matching logic
always @(*) begin
    allow = 0;
    rule_matched = 0;
    matched_rule_id = 0;

    integer i;
    for (i = 0; i < NUM_RULES; i = i + 1) begin
        reg rule_action;
        reg [7:0] rule_protocol;
        reg [15:0] rule_src_port, rule_dst_port;
        reg [31:0] rule_src_ip, rule_dst_ip;
        reg [1:0] rule_state_req;
        reg [7:0] rule_flags_req;
        reg [7:0] rule_icmp_type;
        reg rule_reserved;

        {rule_action, rule_protocol, rule_src_port, rule_dst_port,
         rule_src_ip, rule_dst_ip, rule_state_req, rule_flags_req,
         rule_icmp_type, rule_reserved} = rule_table[i];

        // Check if rule matches
        reg protocol_match = (rule_protocol == 8'hFF) || (rule_protocol == protocol);
        reg src_port_match = (rule_src_port == 16'hFFFF) || (rule_src_port == src_port);
        reg dst_port_match = (rule_dst_port == 16'hFFFF) || (rule_dst_port == dst_port);
        reg src_ip_match = (rule_src_ip == 32'hFFFFFFFF) || (rule_src_ip == src_ip);
        reg dst_ip_match = (rule_dst_ip == 32'hFFFFFFFF) || (rule_dst_ip == dst_ip);
        reg state_match = (rule_state_req == 2'b11) || (!state_valid && rule_state_req == CLOSED) ||
                         (state_valid && rule_state_req == current_state);
        reg flags_match = (rule_flags_req == 8'hFF) || ((tcp_flags & rule_flags_req) == rule_flags_req);
        reg icmp_match = (rule_icmp_type == 8'hFF) || (rule_icmp_type == icmp_type);

        if (protocol_match && src_port_match && dst_port_match &&
            src_ip_match && dst_ip_match && state_match && flags_match && icmp_match) begin
            allow = rule_action;
            rule_matched = 1;
            matched_rule_id = i;
            break;  // First match wins
        end
    end
end

endmodule