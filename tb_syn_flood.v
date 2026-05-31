// tb_syn_flood.v - Testbench for SYN flood detection
`timescale 1ns / 1ps

module tb_syn_flood;

    // Clock and reset
    reg clk;
    reg rst;

    // Packet data interface (512-bit for 100G Ethernet MAC)
    reg [511:0] packet_data;
    reg [5:0] packet_byte_count;
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
        .syn_flood_alert(syn_flood_alert)
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

    // Test task to send a SYN packet
    task send_syn_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] src_port;
        input [15:0] dst_port;
        begin
            integer i;
            reg [7:0] packet [0:53]; // Ethernet(14) + IP(20) + TCP(20) = 54 bytes

            // Build Ethernet header (simplified)
            packet[0] = 8'hFF; packet[1] = 8'hFF; packet[2] = 8'hFF; packet[3] = 8'hFF; packet[4] = 8'hFF; packet[5] = 8'hFF; // DST MAC
            packet[6] = 8'h00; packet[7] = 8'h00; packet[8] = 8'h00; packet[9] = 8'h00; packet[10] = 8'h00; packet[11] = 8'h00; // SRC MAC
            packet[12] = 8'h08; packet[13] = 8'h00; // EtherType (IP)

            // Build IP header
            packet[14] = 8'h45; // Version/IHL
            packet[15] = 8'h00; // DSCP/ECN
            packet[16] = 8'h00; packet[17] = 8'h3C; // Total Length (60 bytes)
            packet[18] = 8'h00; packet[19] = 8'h00; // Identification
            packet[20] = 8'h00; packet[21] = 8'h00; // Flags/Fragment
            packet[22] = 8'h40; // TTL
            packet[23] = 8'h06; // Protocol (TCP)
            packet[24] = 8'h00; packet[25] = 8'h00; // Header Checksum (simplified)
            packet[26] = src_ip[31:24]; packet[27] = src_ip[23:16]; packet[28] = src_ip[15:8]; packet[29] = src_ip[7:0]; // SRC IP
            packet[30] = dst_ip[31:24]; packet[31] = dst_ip[23:16]; packet[32] = dst_ip[15:8]; packet[33] = dst_ip[7:0]; // DST IP

            // Build TCP header
            packet[34] = src_port[15:8]; packet[35] = src_port[7:0]; // SRC Port
            packet[36] = dst_port[15:8]; packet[37] = dst_port[7:0]; // DST Port
            packet[38] = 8'h00; packet[39] = 8'h00; packet[40] = 8'h00; packet[41] = 8'h00; // SEQ Number
            packet[42] = 8'h00; packet[43] = 8'h00; packet[44] = 8'h00; packet[45] = 8'h00; // ACK Number
            packet[46] = 8'h50; // Data Offset (5) + Reserved
            packet[47] = 8'h02; // Flags (SYN)
            packet[48] = 8'h20; packet[49] = 8'h00; // Window Size
            packet[50] = 8'h00; packet[51] = 8'h00; // Checksum
            packet[52] = 8'h00; packet[53] = 8'h00; // Urgent Pointer

            // Send packet
            packet_sop = 1;
            packet_valid = 1;
            packet_data = packet[0];
            #10;

            packet_sop = 0;
            for (i = 1; i < 53; i = i + 1) begin
                packet_data = packet[i];
                #10;
            end

            packet_eop = 1;
            packet_data = packet[53];
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

        $display("Starting SYN flood test...");

        // Send 5 SYN packets from same IP (should be allowed)
        $display("Sending 5 SYN packets from 192.168.1.100...");
        repeat (5) begin
            send_syn_packet(32'hC0A80164, 32'hC0A80101, 16'd12345, 16'd80); // 192.168.1.100 -> 192.168.1.1:80
            #100; // Wait between packets
        end

        // Send 6 more SYN packets (should trigger flood detection)
        $display("Sending 6 more SYN packets (should trigger flood detection)...");
        repeat (6) begin
            send_syn_packet(32'hC0A80164, 32'hC0A80101, 16'd12346, 16'd80);
            #100;
        end

        // Send SYN from different IP (should be allowed)
        $display("Sending SYN from different IP (should be allowed)...");
        send_syn_packet(32'hC0A80165, 32'hC0A80101, 16'd12347, 16'd80); // 192.168.1.101
        #100;

        $display("Test completed.");
        #1000;
        $finish;
    end

    // Monitor results
    always @(posedge syn_flood_alert) begin
        $display("SYN FLOOD DETECTED at time %t!", $time);
    end

    always @(posedge allow_packet) begin
        $display("Packet ALLOWED at time %t", $time);
    end

    always @(negedge allow_packet) begin
        if (packet_ready)
            $display("Packet BLOCKED at time %t", $time);
    end

endmodule