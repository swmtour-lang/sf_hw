// tb_smurf_attack.v - Testbench for Smurf attack detection
`timescale 1ns / 1ps

module tb_smurf_attack;

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
    wire smurf_attack_alert;
    wire replay_attack_alert;
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
        .smurf_attack_alert(smurf_attack_alert),
        .replay_attack_alert(replay_attack_alert),
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
        input [7:0] icmp_type;
        input [7:0] icmp_code;
        input string desc;
        integer i;
        begin
            $display("Sending ICMP packet: %s (src=%0p, dst=%0p, type=%0d)", desc, src_ip, dst_ip, icmp_type);

            // Ethernet header (14 bytes) - simplified
            packet_sop = 1;
            packet_valid = 1;

            // Destination MAC (6 bytes) - broadcast for smurf attack simulation
            for (i = 0; i < 6; i = i + 1) begin
                packet_data = 8'hFF; // Broadcast MAC
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
            // Total Length (84 bytes for standard ICMP echo)
            packet_data = 8'h00;
            @(posedge clk);
            packet_data = 8'h54;
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

            // Payload (32 bytes for standard ping)
            for (i = 0; i < 32; i = i + 1) begin
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
        $display("Smurf Attack Testbench");
        $display("========================================");

        // Test 1: Normal ICMP Echo Request (should be allowed)
        $display("\n[TEST 1] Normal ICMP Echo Request to unicast");
        send_icmp_packet(32'hC0A80101, 32'hC0A80102, 8'd8, 8'd0, "Normal ping to unicast");
        if (allow_packet && !smurf_attack_alert) begin
            $display("PASS: Normal unicast ping allowed");
        end else begin
            $display("FAIL: Normal unicast ping blocked or flagged as smurf attack");
        end

        // Test 2: ICMP to limited broadcast (255.255.255.255) - Smurf attack
        $display("\n[TEST 2] ICMP to limited broadcast - Smurf attack");
        send_icmp_packet(32'hC0A80101, 32'hFFFFFFFF, 8'd8, 8'd0, "Ping to limited broadcast");
        if (!allow_packet && smurf_attack_alert) begin
            $display("PASS: Limited broadcast ping correctly detected as smurf attack");
        end else begin
            $display("FAIL: Limited broadcast ping not detected (allowed=%0d, alert=%0d)", allow_packet, smurf_attack_alert);
        end

        // Test 3: ICMP to Class A network broadcast (10.255.255.255)
        $display("\n[TEST 3] ICMP to Class A network broadcast");
        send_icmp_packet(32'hC0A80101, 32'h0AFFFFFF, 8'd8, 8'd0, "Ping to 10.255.255.255");
        if (!allow_packet && smurf_attack_alert) begin
            $display("PASS: Class A broadcast ping correctly detected");
        end else begin
            $display("FAIL: Class A broadcast ping not detected (allowed=%0d, alert=%0d)", allow_packet, smurf_attack_alert);
        end

        // Test 4: ICMP to Class B network broadcast (192.168.1.255)
        $display("\n[TEST 4] ICMP to Class B network broadcast");
        send_icmp_packet(32'hC0A80101, 32'hC0A801FF, 8'd8, 8'd0, "Ping to 192.168.1.255");
        if (!allow_packet && smurf_attack_alert) begin
            $display("PASS: Class B broadcast ping correctly detected");
        end else begin
            $display("FAIL: Class B broadcast ping not detected (allowed=%0d, alert=%0d)", allow_packet, smurf_attack_alert);
        end

        // Test 5: ICMP to Class C network broadcast (192.168.1.255 again, same as test 4)
        $display("\n[TEST 5] ICMP to Class C network broadcast");
        send_icmp_packet(32'hC0A80101, 32'hC0A801FF, 8'd8, 8'd0, "Ping to 192.168.1.255 (Class C)");
        if (!allow_packet && smurf_attack_alert) begin
            $display("PASS: Class C broadcast ping correctly detected");
        end else begin
            $display("FAIL: Class C broadcast ping not detected (allowed=%0d, alert=%0d)", allow_packet, smurf_attack_alert);
        end

        // Test 6: ICMP Reply to broadcast (should still be blocked)
        $display("\n[TEST 6] ICMP Echo Reply to broadcast");
        send_icmp_packet(32'hC0A80101, 32'hFFFFFFFF, 8'd0, 8'd0, "Echo reply to broadcast");
        if (!allow_packet && smurf_attack_alert) begin
            $display("PASS: ICMP reply to broadcast also blocked");
        end else begin
            $display("FAIL: ICMP reply to broadcast not blocked (allowed=%0d, alert=%0d)", allow_packet, smurf_attack_alert);
        end

        // Test 7: Non-ICMP packet to broadcast (should be allowed - not our concern)
        $display("\n[TEST 7] TCP SYN to broadcast (not ICMP, should be allowed by firewall rules)");
        // Note: This would require implementing TCP packet generation
        $display("INFO: Non-ICMP broadcast test requires TCP packet generation");

        #(10*CLK_PERIOD);
        $display("\n========================================");
        $display("Testbench Complete");
        $display("========================================");
        $display("Summary:");
        $display("  Total packets processed: %0d", packet_count);
        $display("  Invalid packets: %0d", invalid_count);
        $display("  Smurf attack alerts: %0d", smurf_attack_alert ? 1 : 0);
        $finish;
    end

endmodule
