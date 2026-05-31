// tb_tcp_hijacking.v - Testbench for TCP session hijacking detection
`timescale 1ns / 1ps

module tb_tcp_hijacking;

    // Clock and reset
    reg clk;
    reg rst;

    // Packet data interface
    reg [7:0] packet_data;
    reg packet_valid;
    reg packet_sop;
    reg packet_eop;

    // Firewall outputs
    wire allow_packet;
    wire packet_ready;
    wire [3:0] matched_rule_id;
    wire collision_detected;
    wire parse_error;
    wire syn_flood_alert;
    wire rst_injection_alert;
    wire tcp_hijacking_alert;

    // DUT instantiation
    firewall fw (
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
        .rst_injection_alert(rst_injection_alert),
        .tcp_hijacking_alert(tcp_hijacking_alert)
    );

    // Clock generation (100MHz)
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Reset
    initial begin
        rst = 1;
        #100;
        rst = 0;
        #20;
    end

    // Task to send a TCP packet with specific sequence number
    task send_tcp_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] src_port;
        input [15:0] dst_port;
        input [31:0] seq_num;
        input [7:0] flags;        // TCP flags
        input [15:0] payload_bytes; // Payload length
        begin
            integer i;
            reg [7:0] packet [0:127];
            reg [15:0] total_len;

            // Calculate total packet length
            total_len = 20 + 20 + payload_bytes;  // IP header (20) + TCP header (20) + payload

            // Build Ethernet header (14 bytes)
            packet[0] = 8'hFF; packet[1] = 8'hFF; packet[2] = 8'hFF; packet[3] = 8'hFF; packet[4] = 8'hFF; packet[5] = 8'hFF; // DST MAC
            packet[6] = 8'h00; packet[7] = 8'h00; packet[8] = 8'h00; packet[9] = 8'h00; packet[10] = 8'h00; packet[11] = 8'h00; // SRC MAC
            packet[12] = 8'h08; packet[13] = 8'h00; // EtherType (IP)

            // Build IP header (20 bytes)
            packet[14] = 8'h45; // Version/IHL
            packet[15] = 8'h00; // DSCP/ECN
            packet[16] = total_len[15:8]; packet[17] = total_len[7:0]; // Total Length
            packet[18] = 8'h00; packet[19] = 8'h00; // Identification
            packet[20] = 8'h00; packet[21] = 8'h00; // Flags/Fragment
            packet[22] = 8'h40; // TTL
            packet[23] = 8'h06; // Protocol (TCP)
            packet[24] = 8'h00; packet[25] = 8'h00; // Header Checksum (simplified)
            packet[26] = src_ip[31:24]; packet[27] = src_ip[23:16]; packet[28] = src_ip[15:8]; packet[29] = src_ip[7:0]; // SRC IP
            packet[30] = dst_ip[31:24]; packet[31] = dst_ip[23:16]; packet[32] = dst_ip[15:8]; packet[33] = dst_ip[7:0]; // DST IP

            // Build TCP header (20 bytes)
            packet[34] = src_port[15:8]; packet[35] = src_port[7:0]; // SRC Port
            packet[36] = dst_port[15:8]; packet[37] = dst_port[7:0]; // DST Port
            packet[38] = seq_num[31:24]; packet[39] = seq_num[23:16]; packet[40] = seq_num[15:8]; packet[41] = seq_num[7:0]; // SEQ Number
            packet[42] = 8'h00; packet[43] = 8'h00; packet[44] = 8'h00; packet[45] = 8'h00; // ACK Number
            packet[46] = 8'h50; // Data Offset (5) + Reserved
            packet[47] = flags; // TCP Flags
            packet[48] = 8'h20; packet[49] = 8'h00; // Window Size
            packet[50] = 8'h00; packet[51] = 8'h00; // Checksum
            packet[52] = 8'h00; packet[53] = 8'h00; // Urgent Pointer

            // Fill payload with zeros for simplicity
            for (i = 54; i < (54 + payload_bytes); i = i + 1) begin
                packet[i] = 8'h00;
            end

            // Send packet
            packet_sop = 1;
            packet_valid = 1;
            packet_data = packet[0];
            #10;

            packet_sop = 0;
            for (i = 1; i < (54 + payload_bytes); i = i + 1) begin
                packet_data = packet[i];
                #10;
            end

            packet_eop = 1;
            packet_data = packet[53 + payload_bytes];
            #10;

            packet_valid = 0;
            packet_eop = 0;
            #10;
        end
    endtask

    // Test sequence
    initial begin
        // Wait for reset
        #150;

        $display("========================================");
        $display("TCP Session Hijacking Detection Test");
        $display("========================================");

        // Establish legitimate TCP connection (SYN-SYN/ACK-ACK)
        $display("\n[1] Establishing legitimate TCP connection...");
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h00000001, 8'h02, 16'd0); // SYN
        #200;
        send_tcp_packet(32'hC0A80101, 32'hC0A80164, 16'd80, 16'd1234, 32'h00000100, 8'h12, 16'd0); // SYN-ACK
        #200;
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h00000002, 8'h10, 16'd0); // ACK
        #200;

        // Send legitimate data packets
        $display("[2] Sending legitimate data packets with correct sequence numbers...");
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h00000002, 8'h18, 16'd50); // PSH+ACK with 50 bytes data
        #200;
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h00000032, 8'h18, 16'd50); // Next seq (2 + 50 = 52 = 0x34)
        #200;

        // Send hijacking attempt - data packet with sequence number way off
        $display("[3] Sending HIJACK ATTEMPT with invalid sequence number...");
        send_tcp_packet(32'hC0A80165, 32'hC0A80101, 16'd1234, 16'd80, 32'h00001000, 8'h18, 16'd100); // Attacker with wrong seq
        #200;

        // Send another hijacking attempt with huge sequence jump
        $display("[4] Sending HIJACK ATTEMPT with large sequence jump...");
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'hFFFFFFFF, 8'h18, 16'd100); // Huge seq number
        #200;

        // Legitimate continuation after hijack attempts
        $display("[5] Sending legitimate packet after hijack attempts...");
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h00000052, 8'h18, 16'd50); // Correct sequence
        #200;

        // Send data without PSH flag (should be allowed even if seq is off)
        $display("[6] Sending ACK-only packet with invalid sequence (should be allowed)...");
        send_tcp_packet(32'hC0A80164, 32'hC0A80101, 16'd1234, 16'd80, 32'h11111111, 8'h10, 16'd0); // ACK only, wrong seq
        #200;

        $display("\n========================================");
        $display("Test completed.");
        $display("========================================");
        #1000;
        $finish;
    end

    // Monitor hijacking alerts
    always @(posedge tcp_hijacking_alert) begin
        $display("⚠️  TCP HIJACKING DETECTED at time %t!", $time);
    end

    // Log packet decisions
    always @(posedge packet_ready) begin
        if (allow_packet)
            $display("✓  Packet ALLOWED at time %t", $time);
        else
            $display("✗  Packet BLOCKED at time %t", $time);
    end

endmodule
