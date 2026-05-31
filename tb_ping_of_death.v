// tb_ping_of_death.v - Testbench for Ping of Death attack detection
`timescale 1ns / 1ps

module tb_ping_of_death;

    // Test parameters
    parameter CLK_PERIOD = 10;

    // Testbench signals (512-bit for 100G Ethernet MAC)
    reg clk;
    reg rst;
    reg [511:0] packet_data;
    reg [5:0] packet_byte_count;
    reg packet_valid;
    reg packet_sop;
    reg packet_eop;
    reg time_tick;
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
    wire [7:0] table_occupancy;
    wire [7:0] capacity_percent;
    wire capacity_alert;
    wire table_full;
    wire table_overflow_event;

    // Instantiate firewall
    firewall dut (
        .clk(clk),
        .rst(rst),
        .packet_data(packet_data),
        .packet_byte_count(packet_byte_count),
        .packet_valid(packet_valid),
        .packet_sop(packet_sop),
        .packet_eop(packet_eop),
        .time_tick(time_tick),
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
        .table_occupancy(table_occupancy),
        .capacity_percent(capacity_percent),
        .capacity_alert(capacity_alert),
        .table_full(table_full),
        .table_overflow_event(table_overflow_event)
    );

    // Clock generation
    always begin
        clk = 0;
        #(CLK_PERIOD/2);
        clk = 1;
        #(CLK_PERIOD/2);
    end

    // Test packet generation
    task send_icmp_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] total_length;
        input [7:0] icmp_type;
        input [7:0] icmp_code;
        input integer payload_size;
        input string desc;
        integer i;
        begin
            $display("Sending ICMP packet: %s (length=%0d, type=%0d)", desc, total_length, icmp_type);

            // Ethernet header (14 bytes) - simplified
            packet_sop = 1;
            packet_valid = 1;

            // Destination MAC (6 bytes)
            for (i = 0; i < 6; i = i + 1) begin
                packet_data = 8'hFF; // Broadcast MAC for simplicity
                if (i == 5) packet_sop = 0;
                @(posedge clk);
            end

            // Source MAC (6 bytes)
            for (i = 0; i < 6; i = i + 1) begin
                packet_data = 8'hAA;
                @(posedge clk);
            end

            // EtherType (2 bytes) - IPv4
            packet_data = 8'h08;
            @(posedge clk);
            packet_data = 8'h00;
            @(posedge clk);

            // IP header (20 bytes)
            // Version/IHL
            packet_data = 8'h45;
            @(posedge clk);
            // DSCP/ECN
            packet_data = 8'h00;
            @(posedge clk);
            // Total Length (high byte)
            packet_data = total_length[15:8];
            @(posedge clk);
            // Total Length (low byte)
            packet_data = total_length[7:0];
            @(posedge clk);
            // Identification
            packet_data = 8'h12;
            @(posedge clk);
            packet_data = 8'h34;
            @(posedge clk);
            // Flags/Fragment Offset
            packet_data = 8'h00; // No fragmentation
            @(posedge clk);
            packet_data = 8'h00;
            @(posedge clk);
            // TTL
            packet_data = 8'h40;
            @(posedge clk);
            // Protocol (ICMP = 1)
            packet_data = 8'h01;
            @(posedge clk);
            // Header Checksum
            packet_data = 8'h00;
            @(posedge clk);
            packet_data = 8'h00;
            @(posedge clk);
            // Source IP
            packet_data = src_ip[31:24];
            @(posedge clk);
            packet_data = src_ip[23:16];
            @(posedge clk);
            packet_data = src_ip[15:8];
            @(posedge clk);
            packet_data = src_ip[7:0];
            @(posedge clk);
            // Destination IP
            packet_data = dst_ip[31:24];
            @(posedge clk);
            packet_data = dst_ip[23:16];
            @(posedge clk);
            packet_data = dst_ip[15:8];
            @(posedge clk);
            packet_data = dst_ip[7:0];
            @(posedge clk);

            // ICMP header (8 bytes minimum)
            // Type
            packet_data = icmp_type;
            @(posedge clk);
            // Code
            packet_data = icmp_code;
            @(posedge clk);
            // Checksum
            packet_data = 8'h00;
            @(posedge clk);
            packet_data = 8'h00;
            @(posedge clk);
            // Identifier
            packet_data = 8'h00;
            @(posedge clk);
            packet_data = 8'h01;
            @(posedge clk);
            // Sequence Number
            packet_data = 8'h00;
            @(posedge clk);
            packet_data = 8'h01;
            @(posedge clk);

            // Payload (variable size)
            for (i = 0; i < payload_size; i = i + 1) begin
                packet_data = i[7:0]; // Simple pattern
                @(posedge clk);
            end

            // End packet
            packet_eop = 1;
            packet_data = 8'h00; // Last byte
            @(posedge clk);

            packet_valid = 0;
            packet_eop = 0;
            packet_sop = 0;

            // Wait for processing
            @(posedge clk);
            while (!packet_ready) @(posedge clk);
            @(posedge clk);
        end
    endtask

    // Test scenarios
    initial begin
        // Initialize signals
        rst = 1;
        packet_data = 0;
        packet_valid = 0;
        packet_sop = 0;
        packet_eop = 0;
        time_tick = 0;

        #(2*CLK_PERIOD);
        rst = 0;
        #(CLK_PERIOD);

        $display("========================================");
        $display("Ping of Death Attack Testbench");
        $display("========================================");

        // Test 1: Normal ICMP Echo Request (should be allowed)
        $display("\n[TEST 1] Normal ICMP Echo Request");
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 16'd84, 8'd8, 8'd0, 32, "Normal ping");
        if (allow_packet && !ping_of_death_alert) begin
            $display("PASS: Normal ping allowed");
        end else begin
            $display("FAIL: Normal ping blocked or flagged as ping of death");
        end

        // Test 2: Large ICMP packet (close to max size, should be allowed)
        $display("\n[TEST 2] Large but valid ICMP packet");
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 16'd1500, 8'd8, 8'd0, 1456, "Large ping");
        if (allow_packet && !ping_of_death_alert) begin
            $display("PASS: Large ping allowed");
        end else begin
            $display("FAIL: Large ping blocked or flagged as ping of death");
        end

        // Test 3: Ping of Death - Oversized packet (> 65500 bytes)
        $display("\n[TEST 3] Ping of Death - Oversized packet");
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 16'd65501, 8'd8, 8'd0, 65457, "Oversized ping");
        if (!allow_packet && ping_of_death_alert) begin
            $display("PASS: Ping of death correctly detected and blocked");
        end else begin
            $display("FAIL: Ping of death not detected (allowed=%0d, alert=%0d)", allow_packet, ping_of_death_alert);
        end

        // Test 4: Fragmented ICMP packet (should be suspicious)
        $display("\n[TEST 4] Fragmented ICMP packet");
        // Note: For simplicity, we'll just test with fragmentation flags set
        // In a real implementation, this would need proper fragmentation simulation
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 16'd1500, 8'd8, 8'd0, 1456, "Fragmented ping");
        // Fragmentation detection would need to be implemented in packet parser
        $display("INFO: Fragmentation test requires enhanced packet parser");

        // Test 5: ICMP packet exactly at maximum size
        $display("\n[TEST 5] ICMP packet at maximum IPv4 size");
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 16'd65535, 8'd8, 8'd0, 65491, "Max size ping");
        if (!allow_packet && ping_of_death_alert) begin
            $display("PASS: Maximum size ping correctly flagged");
        end else begin
            $display("FAIL: Maximum size ping not flagged (allowed=%0d, alert=%0d)", allow_packet, ping_of_death_alert);
        end

        // Test 6: Non-ICMP packet (should not trigger ping of death alert)
        $display("\n[TEST 6] Non-ICMP packet (TCP SYN)");
        // This would require implementing TCP packet generation
        $display("INFO: Non-ICMP test requires TCP packet generation");

        #(10*CLK_PERIOD);
        $display("\n========================================");
        $display("Testbench Complete");
        $display("========================================");
        $display("Summary:");
        $display("  Total packets processed: %0d", packet_count);
        $display("  Invalid packets: %0d", invalid_count);
        $display("  Ping of death alerts: %0d", ping_of_death_alert ? 1 : 0);
        $finish;
    end

endmodule
