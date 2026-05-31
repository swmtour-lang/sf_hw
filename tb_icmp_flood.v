// tb_icmp_flood.v - Testbench for ICMP flood detector
`timescale 1ns / 1ps

module tb_icmp_flood;

    // Test parameters
    parameter CLK_PERIOD = 10;
    parameter TABLE_SIZE = 128;
    parameter ICMP_THRESHOLD = 100;
    parameter TIME_WINDOW = 2000;

    // Testbench signals
    reg clk;
    reg rst;
    reg packet_valid;
    reg is_icmp;
    reg [7:0] icmp_type;
    reg [31:0] src_ip;
    reg [31:0] time_counter;
    wire icmp_flood_alert;
    wire [31:0] blocked_src_ip;
    wire dangerous_icmp_type;

    // ICMP type constants
    localparam ICMP_ECHO_REQUEST = 8'd8;
    localparam ICMP_ECHO_REPLY = 8'd0;
    localparam ICMP_TIMESTAMP = 8'd13;
    localparam ICMP_TIMESTAMP_REPLY = 8'd14;

    // Instantiate ICMP flood detector
    icmp_flood_detector #(
        .TABLE_SIZE(TABLE_SIZE),
        .ICMP_THRESHOLD(ICMP_THRESHOLD),
        .TIME_WINDOW(TIME_WINDOW)
    ) dut (
        .clk(clk),
        .rst(rst),
        .packet_valid(packet_valid),
        .is_icmp(is_icmp),
        .icmp_type(icmp_type),
        .src_ip(src_ip),
        .time_counter(time_counter),
        .icmp_flood_alert(icmp_flood_alert),
        .blocked_src_ip(blocked_src_ip),
        .dangerous_icmp_type(dangerous_icmp_type)
    );

    // Clock generation
    always begin
        clk = 0;
        #(CLK_PERIOD/2);
        clk = 1;
        #(CLK_PERIOD/2);
    end

    // Test scenarios
    initial begin
        // Initialize signals
        rst = 1;
        packet_valid = 0;
        is_icmp = 0;
        icmp_type = 0;
        src_ip = 0;
        time_counter = 0;

        #(2*CLK_PERIOD);
        rst = 0;
        #(CLK_PERIOD);

        $display("========================================");
        $display("ICMP Flood Detector Testbench");
        $display("========================================");

        // Test 1: Normal ICMP traffic (should not alert)
        $display("\n[TEST 1] Normal ICMP traffic (Echo Reply)");
        send_icmp_packets(32'hC0A80101, ICMP_ECHO_REPLY, 10, "Normal Echo Reply");
        if (icmp_flood_alert)
            $display("FAIL: Alert triggered for normal traffic");
        else
            $display("PASS: No false alarm for normal traffic");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 2: Moderate ICMP traffic (should not alert)
        $display("\n[TEST 2] Moderate ICMP traffic (Echo Request)");
        send_icmp_packets(32'hC0A80102, ICMP_ECHO_REQUEST, 50, "Moderate Echo Request");
        if (icmp_flood_alert)
            $display("FAIL: Alert triggered for moderate traffic");
        else
            $display("PASS: No alert for moderate traffic");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 3: Echo Request flood attack (should alert after threshold)
        $display("\n[TEST 3] Echo Request Flood Attack");
        send_icmp_packets_with_alert(32'hC0A80103, ICMP_ECHO_REQUEST, 120, "Echo Flood Attack");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 4: Dangerous ICMP type (Timestamp) with lower threshold
        $display("\n[TEST 4] Timestamp Request Flood (Dangerous Type)");
        send_icmp_packets_with_alert(32'hC0A80104, ICMP_TIMESTAMP, 60, "Timestamp Flood");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 5: Multiple source IPs (each within threshold but from different sources)
        $display("\n[TEST 5] Multiple source IPs (no cross-source aggregation)");
        send_icmp_packets(32'hC0A80105, ICMP_ECHO_REQUEST, 80, "Source 1");
        #(10*CLK_PERIOD);
        send_icmp_packets(32'hC0A80106, ICMP_ECHO_REQUEST, 80, "Source 2");
        if (icmp_flood_alert)
            $display("FAIL: Alert triggered when each source is below threshold");
        else
            $display("PASS: No alert - ICMP rates per-source tracked correctly");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 6: Time window reset (packets after window should reset counter)
        $display("\n[TEST 6] Time Window Reset");
        send_icmp_packets(32'hC0A80107, ICMP_ECHO_REQUEST, 60, "Packets in window 1");
        // Advance time beyond window
        #(100*CLK_PERIOD);
        time_counter = TIME_WINDOW + 100;
        send_icmp_packets(32'hC0A80107, ICMP_ECHO_REQUEST, 60, "Packets in window 2");
        if (icmp_flood_alert)
            $display("FAIL: Alert triggered after time window reset");
        else
            $display("PASS: Time window reset correctly");

        // Reset time
        #(CLK_PERIOD);
        time_counter = 0;

        // Test 7: Confirm dangerous ICMP flag works
        $display("\n[TEST 7] Dangerous ICMP Type Detection");
        send_icmp_with_flag_check(32'hC0A80108, ICMP_TIMESTAMP, "Timestamp (dangerous)");
        send_icmp_with_flag_check(32'hC0A80109, ICMP_ECHO_REQUEST, "Echo Request (normal)");

        #(10*CLK_PERIOD);
        $display("\n========================================");
        $display("Testbench Complete");
        $display("========================================");
        $finish;
    end

    // Helper task: Send normal ICMP packets
    task send_icmp_packets(input [31:0] source_ip, input [7:0] type, input integer count, input string desc);
        integer i;
        begin
            for (i = 0; i < count; i = i + 1) begin
                @(posedge clk);
                packet_valid = 1;
                is_icmp = 1;
                icmp_type = type;
                src_ip = source_ip;
                time_counter = time_counter + 1;
            end
            @(posedge clk);
            packet_valid = 0;
            is_icmp = 0;
            $display("  Sent %0d packets from %s: %0pS", count, desc, source_ip);
        end
    endtask

    // Helper task: Send ICMP packets and check for alert
    task send_icmp_packets_with_alert(input [31:0] source_ip, input [7:0] type, input integer count, input string desc);
        integer i;
        integer alert_cycle = 0;
        begin
            for (i = 0; i < count; i = i + 1) begin
                @(posedge clk);
                packet_valid = 1;
                is_icmp = 1;
                icmp_type = type;
                src_ip = source_ip;
                time_counter = time_counter + 1;
                
                if (icmp_flood_alert && alert_cycle == 0) begin
                    alert_cycle = i;
                    $display("  ALERT detected at packet %0d from %s: %0pS (blocked)", 
                             i, desc, blocked_src_ip);
                end
            end
            @(posedge clk);
            packet_valid = 0;
            is_icmp = 0;
            
            if (alert_cycle > 0) begin
                $display("  PASS: Flood detected correctly after threshold exceeded");
            end else begin
                $display("  FAIL: No alert for flood attack (%0d packets sent)", count);
            end
        end
    endtask

    // Helper task: Check dangerous ICMP flag
    task send_icmp_with_flag_check(input [31:0] source_ip, input [7:0] type, input string desc);
        begin
            @(posedge clk);
            packet_valid = 1;
            is_icmp = 1;
            icmp_type = type;
            src_ip = source_ip;
            
            @(posedge clk);
            if (dangerous_icmp_type) begin
                $display("  PASS: Dangerous flag SET for %s (Type %0d)", desc, type);
            end else begin
                if (type == ICMP_TIMESTAMP || type == ICMP_TIMESTAMP + 1)
                    $display("  FAIL: Dangerous flag NOT set for %s (Type %0d)", desc, type);
                else
                    $display("  PASS: Dangerous flag NOT set for %s (Type %0d)", desc, type);
            end
            
            packet_valid = 0;
            is_icmp = 0;
        end
    endtask

endmodule
