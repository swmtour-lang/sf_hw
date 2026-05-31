// tb_port_scan.v - Testbench for TCP Connect port scan detection
`timescale 1ns / 1ps

module tb_port_scan;

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
    wire invalid_packet;
    wire [31:0] packet_count;
    wire [31:0] invalid_count;
    wire syn_flood_alert;
    wire rst_injection_alert;
    wire tcp_hijacking_alert;
    wire udp_rate_limit_alert;
    wire ack_flood_alert;
    wire icmp_flood_alert;
    wire ping_of_death_alert;
    wire smurf_attack_alert;
    wire replay_attack_alert;
    wire null_scan_alert;
    wire xmas_scan_alert;
    wire port_scan_alert;
    wire [7:0] table_occupancy;
    wire [7:0] capacity_percent;
    wire capacity_alert;
    wire table_full;
    wire table_overflow_event;

    // DUT instantiation
    firewall fw (
        .clk(clk),
        .rst(rst),
        .packet_data(packet_data),
        .packet_byte_count(packet_byte_count),
        .packet_valid(packet_valid),
        .packet_sop(packet_sop),
        .packet_eop(packet_eop),
        .time_tick(1'b0),  // Not used in test
        .allow_packet(allow_packet),
        .packet_ready(packet_ready),
        .matched_rule_id(matched_rule_id),
        .collision_detected(collision_detected),
        .parse_error(parse_error),
        .invalid_packet(invalid_packet),
        .packet_count(packet_count),
        .invalid_count(invalid_count),
        .syn_flood_alert(syn_flood_alert),
        .rst_injection_alert(rst_injection_alert),
        .tcp_hijacking_alert(tcp_hijacking_alert),
        .udp_rate_limit_alert(udp_rate_limit_alert),
        .ack_flood_alert(ack_flood_alert),
        .icmp_flood_alert(icmp_flood_alert),
        .ping_of_death_alert(ping_of_death_alert),
        .smurf_attack_alert(smurf_attack_alert),
        .replay_attack_alert(replay_attack_alert),
        .null_scan_alert(null_scan_alert),
        .xmas_scan_alert(xmas_scan_alert),
        .port_scan_alert(port_scan_alert),
        .table_occupancy(table_occupancy),
        .capacity_percent(capacity_percent),
        .capacity_alert(capacity_alert),
        .table_full(table_full),
        .table_overflow_event(table_overflow_event)
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

    // Test task to send a SYN packet to a specific port
    task send_syn_to_port;
        input [31:0] src_ip;
        input [31:0] dst_ip;
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
            packet[34] = 16'h1234; packet[35] = 8'h00; // SRC Port (fixed)
            packet[36] = dst_port[15:8]; packet[37] = dst_port[7:0]; // DST Port
            packet[38] = 8'h00; packet[39] = 8'h00; packet[40] = 8'h00; packet[41] = 8'h00; // SEQ Number
            packet[42] = 8'h00; packet[43] = 8'h00; packet[44] = 8'h00; packet[45] = 8'h00; // ACK Number
            packet[46] = 8'h50; // Data Offset (5) + Reserved
            packet[47] = 8'h02; // Flags (SYN)
            packet[48] = 8'h20; packet[49] = 8'h00; // Window Size
            packet[50] = 8'h00; packet[51] = 8'h00; // Checksum
            packet[52] = 8'h00; packet[53] = 8'h00; // Urgent Pointer

            // Send packet (simplified for 512-bit interface)
            packet_sop = 1;
            packet_valid = 1;
            packet_byte_count = 54; // 54 bytes
            for (i = 0; i < 54; i = i + 1) begin
                packet_data[i*8 +: 8] = packet[i];
            end
            #10;

            packet_sop = 0;
            packet_eop = 1;
            #10;

            packet_valid = 0;
            packet_eop = 0;
            #10;
        end
    endtask

    // Test sequence
    initial begin
        // Wait for reset
        #200;

        $display("Starting TCP Connect port scan test...");

        // Send SYN packets to different ports from same IP
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd22);   // SSH
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd80);   // HTTP
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd443);  // HTTPS
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd21);   // FTP
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd25);   // SMTP
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd53);   // DNS
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd110);  // POP3
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd143);  // IMAP
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd993);  // IMAPS
        #100;
        send_syn_to_port(32'hC0A80101, 32'hC0A80102, 16'd995);  // POP3S - should trigger alert
        #100;

        // Check if alert was triggered
        if (port_scan_alert) begin
            $display("SUCCESS: Port scan alert triggered after 10 different ports");
        end else begin
            $display("FAILURE: Port scan alert not triggered");
        end

        #1000;
        $finish;
    end

endmodule