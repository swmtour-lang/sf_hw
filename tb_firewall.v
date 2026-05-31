// tb_firewall.v - Comprehensive testbench for 512-bit firewall (100G Ethernet MAC)
`timescale 1ns / 1ps

module tb_firewall;

// Testbench signals (512-bit)
reg clk;
reg rst;
reg [511:0] packet_data;           // 512-bit data
reg [5:0] packet_byte_count;       // Valid bytes (1-64)
reg packet_valid;
reg packet_sop;
reg packet_eop;
wire allow_packet;
wire packet_ready;
wire [3:0] matched_rule_id;
wire collision_detected;
wire parse_error;
wire syn_flood_alert;
wire rst_injection_alert;

// Instantiate DUT (updated for 512-bit)
firewall dut (
    .clk(clk),
    .rst(rst),
    .packet_data(packet_data),
    .packet_byte_count(packet_byte_count),
    .packet_valid(packet_valid),
    .packet_sop(packet_sop),
    .packet_eop(packet_eop),
    .allow_packet(allow_packet),
    .packet_ready(packet_ready),
    .matched_rule_id(matched_rule_id),
    .collision_detected(collision_detected),
    .parse_error(parse_error),
    .syn_flood_alert(syn_flood_alert),
    .rst_injection_alert(rst_injection_alert)
);

// Clock generation
always #5 clk = ~clk;

// Test packet data storage (as byte arrays)
reg [7:0] test_packets [0:9][0:127];  // 10 test packets, max 128 bytes each
reg [7:0] packet_lengths [0:9];
reg [3:0] expected_rule_ids [0:9];
reg expected_allow [0:9];

// Helper function: Pack bytes into 512-bit word (big-endian)
function [511:0] pack_512bit;
    input [7:0] bytes [0:63];
    input [5:0] num_bytes;
    integer i;
    begin
        pack_512bit = 512'b0;
        for (i = 0; i < 64 && i < num_bytes; i = i + 1) begin
            pack_512bit[(511 - (i*8)) -: 8] = bytes[i];
        end
    end
endfunction

// Send packet procedure (512-bit word-based)
task send_packet_512;
    input [7:0] pkt [0:127];
    input integer pkt_len;
    integer word_idx, word_count, byte_offset, bytes_in_word;
    reg [7:0] word_bytes [0:63];
    integer i;
    begin
        word_count = (pkt_len + 63) / 64;  // Calculate number of 512-bit words
        
        for (word_idx = 0; word_idx < word_count; word_idx = word_idx + 1) begin
            // Extract bytes for this word
            byte_offset = word_idx * 64;
            for (i = 0; i < 64; i = i + 1) begin
                if (byte_offset + i < pkt_len) begin
                    word_bytes[i] = pkt[byte_offset + i];
                end else begin
                    word_bytes[i] = 8'b0;
                end
            end
            
            // Calculate valid bytes in this word
            if (byte_offset + 64 <= pkt_len) begin
                bytes_in_word = 64;
            end else begin
                bytes_in_word = pkt_len - byte_offset;
            end
            
            // Send word
            packet_data <= pack_512bit(word_bytes, bytes_in_word);
            packet_byte_count <= bytes_in_word[5:0];
            packet_valid <= 1;
            packet_sop <= (word_idx == 0);
            packet_eop <= (word_idx == word_count - 1);
            #10;
        end
        
        // Clear signals
        packet_valid <= 0;
        packet_sop <= 0;
        packet_eop <= 0;
    end
endtask

initial begin
    // Initialize
    clk = 0;
    rst = 1;
    packet_valid = 0;
    packet_sop = 0;
    packet_eop = 0;
    packet_data = 0;
    packet_byte_count = 0;

    // Reset
    #10 rst = 0;
    #10;

    // Test Packet 0: TCP SYN to port 80 (should be allowed, rule 1)
    create_tcp_syn_packet(0, 32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80);
    packet_lengths[0] = 54;
    expected_allow[0] = 1;
    expected_rule_ids[0] = 1;

    // Test Packet 1: TCP SYN to port 443 (should be allowed, rule 2)
    create_tcp_syn_packet(1, 32'hC0A80101, 32'hC0A80102, 16'd12346, 16'd443);
    packet_lengths[1] = 54;
    expected_allow[1] = 1;
    expected_rule_ids[1] = 2;

    // Test Packet 2: UDP DNS query (should be allowed, rule 3)
    create_udp_packet(2, 32'hC0A80101, 32'hC0A80102, 16'd12347, 16'd53, 8'd28);
    packet_lengths[2] = 42;
    expected_allow[2] = 1;
    expected_rule_ids[2] = 3;

    // Test Packet 3: TCP SYN to blocked port (should be denied, rule 5)
    create_tcp_syn_packet(3, 32'hC0A80101, 32'hC0A80102, 16'd12348, 16'd22);
    packet_lengths[3] = 54;
    expected_allow[3] = 0;
    expected_rule_ids[3] = 5;

    // Test Packet 4: TCP ACK for established connection (should be allowed, rule 0)
    // First establish connection with SYN
    create_tcp_syn_packet(4, 32'hC0A80101, 32'hC0A80102, 16'd12349, 16'd80);
    packet_lengths[4] = 54;
    expected_allow[4] = 1;
    expected_rule_ids[4] = 1;

    // Test Packet 5: TCP SYN+ACK response (should be allowed, updates state)
    create_tcp_syn_ack_packet(5, 32'hC0A80102, 32'hC0A80101, 16'd80, 16'd12349);
    packet_lengths[5] = 54;
    expected_allow[5] = 1;
    expected_rule_ids[5] = 0;  // Established rule

    // Test Packet 6: TCP ACK in established state (should be allowed, rule 0)
    create_tcp_ack_packet(6, 32'hC0A80101, 32'hC0A80102, 16'd12349, 16'd80);
    packet_lengths[6] = 54;
    expected_allow[6] = 1;
    expected_rule_ids[6] = 0;

    // Test Packet 7: TCP FIN to close connection (should be allowed, rule 0)
    create_tcp_fin_packet(7, 32'hC0A80101, 32'hC0A80102, 16'd12349, 16'd80);
    packet_lengths[7] = 54;
    expected_allow[7] = 1;
    expected_rule_ids[7] = 0;

    // Test Packet 8: UDP NTP query (should be allowed, rule 4)
    create_udp_packet(8, 32'hC0A80101, 32'hC0A80102, 16'd12350, 16'd123, 8'd28);
    packet_lengths[8] = 42;
    expected_allow[8] = 1;
    expected_rule_ids[8] = 4;

    // Test Packet 9: Invalid packet (non-IP) (should be denied)
    create_invalid_packet(9);
    packet_lengths[9] = 64;
    expected_allow[9] = 0;
    expected_rule_ids[9] = 5;

    // Run tests
    run_tests();

    $finish;
end

task create_tcp_syn_packet(input integer pkt_id, input [31:0] src_ip, input [31:0] dst_ip,
                          input [15:0] src_port, input [15:0] dst_port);
begin
    // Ethernet header
    test_packets[pkt_id][0] = 8'hFF; test_packets[pkt_id][1] = 8'hFF; test_packets[pkt_id][2] = 8'hFF;
    test_packets[pkt_id][3] = 8'hFF; test_packets[pkt_id][4] = 8'hFF; test_packets[pkt_id][5] = 8'hFF;
    test_packets[pkt_id][6] = 8'h00; test_packets[pkt_id][7] = 8'h00; test_packets[pkt_id][8] = 8'h00;
    test_packets[pkt_id][9] = 8'h00; test_packets[pkt_id][10] = 8'h00; test_packets[pkt_id][11] = 8'h00;
    test_packets[pkt_id][12] = 8'h08; test_packets[pkt_id][13] = 8'h00;

    // IP header
    test_packets[pkt_id][14] = 8'h45; test_packets[pkt_id][15] = 8'h00;
    test_packets[pkt_id][16] = 8'h00; test_packets[pkt_id][17] = 8'h3C;  // Total length 60
    test_packets[pkt_id][18] = 8'h00; test_packets[pkt_id][19] = 8'h00;
    test_packets[pkt_id][20] = 8'h00; test_packets[pkt_id][21] = 8'h00;
    test_packets[pkt_id][22] = 8'h40; test_packets[pkt_id][23] = 8'h06;  // Protocol TCP
    test_packets[pkt_id][24] = 8'h00; test_packets[pkt_id][25] = 8'h00;  // Checksum
    test_packets[pkt_id][26] = src_ip[31:24]; test_packets[pkt_id][27] = src_ip[23:16];
    test_packets[pkt_id][28] = src_ip[15:8]; test_packets[pkt_id][29] = src_ip[7:0];
    test_packets[pkt_id][30] = dst_ip[31:24]; test_packets[pkt_id][31] = dst_ip[23:16];
    test_packets[pkt_id][32] = dst_ip[15:8]; test_packets[pkt_id][33] = dst_ip[7:0];

    // TCP header
    test_packets[pkt_id][34] = src_port[15:8]; test_packets[pkt_id][35] = src_port[7:0];
    test_packets[pkt_id][36] = dst_port[15:8]; test_packets[pkt_id][37] = dst_port[7:0];
    test_packets[pkt_id][38] = 8'h00; test_packets[pkt_id][39] = 8'h00; test_packets[pkt_id][40] = 8'h00; test_packets[pkt_id][41] = 8'h00;
    test_packets[pkt_id][42] = 8'h00; test_packets[pkt_id][43] = 8'h00; test_packets[pkt_id][44] = 8'h00; test_packets[pkt_id][45] = 8'h00;
    test_packets[pkt_id][46] = 8'h50; test_packets[pkt_id][47] = 8'h02;  // SYN flag
    test_packets[pkt_id][48] = 8'h00; test_packets[pkt_id][49] = 8'h00;
    test_packets[pkt_id][50] = 8'h00; test_packets[pkt_id][51] = 8'h00;
    test_packets[pkt_id][52] = 8'h00; test_packets[pkt_id][53] = 8'h00;
end
endtask

task create_tcp_syn_ack_packet(input integer pkt_id, input [31:0] src_ip, input [31:0] dst_ip,
                              input [15:0] src_port, input [15:0] dst_port);
begin
    create_tcp_syn_packet(pkt_id, src_ip, dst_ip, src_port, dst_port);
    test_packets[pkt_id][47] = 8'h12;  // SYN+ACK flags
end
endtask

task create_tcp_ack_packet(input integer pkt_id, input [31:0] src_ip, input [31:0] dst_ip,
                          input [15:0] src_port, input [15:0] dst_port);
begin
    create_tcp_syn_packet(pkt_id, src_ip, dst_ip, src_port, dst_port);
    test_packets[pkt_id][47] = 8'h10;  // ACK flag
end
endtask

task create_tcp_fin_packet(input integer pkt_id, input [31:0] src_ip, input [31:0] dst_ip,
                          input [15:0] src_port, input [15:0] dst_port);
begin
    create_tcp_syn_packet(pkt_id, src_ip, dst_ip, src_port, dst_port);
    test_packets[pkt_id][47] = 8'h11;  // FIN+ACK flags
end
endtask

task create_udp_packet(input integer pkt_id, input [31:0] src_ip, input [31:0] dst_ip,
                      input [15:0] src_port, input [15:0] dst_port, input [7:0] data_len);
begin
    // Ethernet header
    test_packets[pkt_id][0] = 8'hFF; test_packets[pkt_id][1] = 8'hFF; test_packets[pkt_id][2] = 8'hFF;
    test_packets[pkt_id][3] = 8'hFF; test_packets[pkt_id][4] = 8'hFF; test_packets[pkt_id][5] = 8'hFF;
    test_packets[pkt_id][6] = 8'h00; test_packets[pkt_id][7] = 8'h00; test_packets[pkt_id][8] = 8'h00;
    test_packets[pkt_id][9] = 8'h00; test_packets[pkt_id][10] = 8'h00; test_packets[pkt_id][11] = 8'h00;
    test_packets[pkt_id][12] = 8'h08; test_packets[pkt_id][13] = 8'h00;

    // IP header
    test_packets[pkt_id][14] = 8'h45; test_packets[pkt_id][15] = 8'h00;
    test_packets[pkt_id][16] = 8'h00; test_packets[pkt_id][17] = data_len + 8'd28;  // Total length
    test_packets[pkt_id][18] = 8'h00; test_packets[pkt_id][19] = 8'h00;
    test_packets[pkt_id][20] = 8'h00; test_packets[pkt_id][21] = 8'h00;
    test_packets[pkt_id][22] = 8'h40; test_packets[pkt_id][23] = 8'h11;  // Protocol UDP
    test_packets[pkt_id][24] = 8'h00; test_packets[pkt_id][25] = 8'h00;
    test_packets[pkt_id][26] = src_ip[31:24]; test_packets[pkt_id][27] = src_ip[23:16];
    test_packets[pkt_id][28] = src_ip[15:8]; test_packets[pkt_id][29] = src_ip[7:0];
    test_packets[pkt_id][30] = dst_ip[31:24]; test_packets[pkt_id][31] = dst_ip[23:16];
    test_packets[pkt_id][32] = dst_ip[15:8]; test_packets[pkt_id][33] = dst_ip[7:0];

    // UDP header
    test_packets[pkt_id][34] = src_port[15:8]; test_packets[pkt_id][35] = src_port[7:0];
    test_packets[pkt_id][36] = dst_port[15:8]; test_packets[pkt_id][37] = dst_port[7:0];
    test_packets[pkt_id][38] = 8'h00; test_packets[pkt_id][39] = data_len + 8'd8;  // UDP length
    test_packets[pkt_id][40] = 8'h00; test_packets[pkt_id][41] = 8'h00;  // Checksum
end
endtask

task create_invalid_packet(input integer pkt_id);
begin
    integer i;
    for (i = 0; i < 64; i = i + 1) begin
        test_packets[pkt_id][i] = i[7:0];
    end
end
endtask

task send_packet(input integer pkt_id);
integer i;
begin
    packet_sop = 1;
    packet_valid = 1;
    for (i = 0; i < packet_lengths[pkt_id]; i = i + 1) begin
        packet_data = test_packets[pkt_id][i];
        if (i == packet_lengths[pkt_id] - 1) packet_eop = 1;
        #10;
    end
    packet_valid = 0;
    packet_sop = 0;
    packet_eop = 0;
    #10;
end
endtask

task run_tests();
integer i;
integer passed = 0;
integer total = 10;
begin
    for (i = 0; i < total; i = i + 1) begin
        $display("Testing packet %0d...", i);
        send_packet(i);

        // Wait for decision
        wait(packet_ready);

        if (allow_packet == expected_allow[i] &&
            (!expected_allow[i] || matched_rule_id == expected_rule_ids[i])) begin
            $display("PASS: Packet %0d - Allow: %0d, Rule: %0d, Collision: %0d, Error: %0d",
                    i, allow_packet, matched_rule_id, collision_detected, parse_error);
            passed = passed + 1;
        end else begin
            $display("FAIL: Packet %0d - Expected Allow: %0d Rule: %0d, Got Allow: %0d Rule: %0d, Collision: %0d, Error: %0d",
                    i, expected_allow[i], expected_rule_ids[i], allow_packet, matched_rule_id, collision_detected, parse_error);
        end

        // Reset for next packet
        rst = 1;
        #20;
        rst = 0;
        #10;
    end

    $display("Test Results: %0d/%0d passed", passed, total);
end
endtask

endmodule