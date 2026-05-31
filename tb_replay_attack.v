// tb_replay_attack.v - Testbench for TCP replay attack detection
`timescale 1ns / 1ps

module tb_replay_attack;

    // Test parameters
    parameter CLK_PERIOD = 10;
    parameter TABLE_SIZE = 256;
    parameter TIME_WINDOW = 1000;
    parameter MAX_DUPLICATES = 3;

    // Testbench signals
    reg clk;
    reg rst;
    reg packet_valid;
    reg is_tcp;
    reg state_valid;
    reg [31:0] src_ip;
    reg [31:0] dst_ip;
    reg [15:0] src_port;
    reg [15:0] dst_port;
    reg [31:0] tcp_seq;
    reg [31:0] tcp_ack_num;
    reg [31:0] time_counter;
    wire replay_detected;
    wire [31:0] suspicious_ip;

    // Instantiate replay attack detector
    replay_attack_detector #(
        .TABLE_SIZE(TABLE_SIZE),
        .TIME_WINDOW(TIME_WINDOW),
        .MAX_DUPLICATES(MAX_DUPLICATES)
    ) dut (
        .clk(clk),
        .rst(rst),
        .packet_valid(packet_valid),
        .is_tcp(is_tcp),
        .state_valid(state_valid),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
        .src_port(src_port),
        .dst_port(dst_port),
        .tcp_seq(tcp_seq),
        .tcp_ack_num(tcp_ack_num),
        .time_counter(time_counter),
        .replay_detected(replay_detected),
        .suspicious_ip(suspicious_ip)
    );

    // Clock generation
    always begin
        clk = 0;
        #(CLK_PERIOD/2);
        clk = 1;
        #(CLK_PERIOD/2);
    end

    // Test packet generation
    task send_tcp_packet;
        input [31:0] source_ip;
        input [31:0] dest_ip;
        input [15:0] source_port;
        input [15:0] dest_port;
        input [31:0] seq_num;
        input [31:0] ack_num;
        input string desc;
        begin
            @(posedge clk);
            packet_valid = 1;
            is_tcp = 1;
            state_valid = 1;
            src_ip = source_ip;
            dst_ip = dest_ip;
            src_port = source_port;
            dst_port = dest_port;
            tcp_seq = seq_num;
            tcp_ack_num = ack_num;
            $display("Sending TCP packet: %s (SEQ=%0d, ACK=%0d, Time=%0d)", desc, seq_num, ack_num, time_counter);
        end
    endtask

    task advance_time;
        input integer cycles;
        integer i;
        begin
            for (i = 0; i < cycles; i = i + 1) begin
                @(posedge clk);
                time_counter = time_counter + 1;
            end
        end
    endtask

    // Test scenarios
    initial begin
        // Initialize signals
        rst = 1;
        packet_valid = 0;
        is_tcp = 0;
        state_valid = 0;
        src_ip = 0;
        dst_ip = 0;
        src_port = 0;
        dst_port = 0;
        tcp_seq = 0;
        tcp_ack_num = 0;
        time_counter = 0;

        #(2*CLK_PERIOD);
        rst = 0;
        #(CLK_PERIOD);

        $display("========================================");
        $display("Replay Attack Detector Testbench");
        $display("========================================");

        // Test 1: Normal TCP traffic (should not trigger replay detection)
        $display("\n[TEST 1] Normal TCP traffic");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Normal packet 1");
        advance_time(10);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Normal packet 2");
        advance_time(10);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Normal packet 3");
        if (replay_detected) begin
            $display("FAIL: Normal traffic triggered replay detection");
        end else begin
            $display("PASS: Normal traffic did not trigger replay detection");
        end

        // Reset for next test
        rst = 1;
        #(CLK_PERIOD);
        rst = 0;
        time_counter = 0;
        #(CLK_PERIOD);

        // Test 2: Exact duplicate packets (replay attack)
        $display("\n[TEST 2] Exact duplicate packets (replay attack)");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Original packet");
        advance_time(5);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Duplicate 1");
        advance_time(5);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Duplicate 2");
        advance_time(5);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Duplicate 3");
        advance_time(5);
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Duplicate 4");

        if (replay_detected) begin
            $display("PASS: Duplicate packet replay attack detected (suspicious IP: %0h)", suspicious_ip);
        end else begin
            $display("FAIL: Duplicate packet replay attack not detected");
        end

        // Reset for next test
        rst = 1;
        #(CLK_PERIOD);
        rst = 0;
        time_counter = 0;
        #(CLK_PERIOD);

        // Test 3: Timestamp-based replay (old packet replay)
        $display("\n[TEST 3] Timestamp-based replay (old packet)");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Fresh packet");
        advance_time(TIME_WINDOW + 100);  // Advance time beyond window
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Old packet replay");

        if (replay_detected) begin
            $display("PASS: Timestamp-based replay attack detected (suspicious IP: %0h)", suspicious_ip);
        end else begin
            $display("FAIL: Timestamp-based replay attack not detected");
        end

        // Reset for next test
        rst = 1;
        #(CLK_PERIOD);
        rst = 0;
        time_counter = 0;
        #(CLK_PERIOD);

        // Test 4: Different connections (should not interfere)
        $display("\n[TEST 4] Multiple connections (no cross-contamination)");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Connection 1");
        send_tcp_packet(32'hC0A80103, 32'hC0A80104, 16'd12346, 16'd80, 32'd1000, 32'd2000, "Connection 2");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Connection 1 duplicate");

        if (replay_detected) begin
            $display("PASS: Cross-connection isolation maintained, replay detected for correct connection");
        end else begin
            $display("FAIL: Cross-connection contamination or missed replay detection");
        end

        // Reset for next test
        rst = 1;
        #(CLK_PERIOD);
        rst = 0;
        time_counter = 0;
        #(CLK_PERIOD);

        // Test 5: Boundary condition (exactly MAX_DUPLICATES)
        $display("\n[TEST 5] Boundary condition (exactly MAX_DUPLICATES)");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Original");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Dup 1");
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Dup 2");
        // MAX_DUPLICATES = 3, so this should trigger detection
        send_tcp_packet(32'hC0A80101, 32'hC0A80102, 16'd12345, 16'd80, 32'd1000, 32'd2000, "Dup 3 (should trigger)");

        if (replay_detected) begin
            $display("PASS: Boundary condition handled correctly");
        end else begin
            $display("FAIL: Boundary condition not handled correctly");
        end

        // Reset for next test
        rst = 1;
        #(CLK_PERIOD);
        rst = 0;
        time_counter = 0;
        #(CLK_PERIOD);

        // Test 6: Non-TCP packets (should be ignored)
        $display("\n[TEST 6] Non-TCP packets (should be ignored)");
        @(posedge clk);
        packet_valid = 1;
        is_tcp = 0;  // Not TCP
        state_valid = 1;
        src_ip = 32'hC0A80101;
        dst_ip = 32'hC0A80102;
        src_port = 16'd12345;
        dst_port = 16'd80;
        tcp_seq = 32'd1000;
        tcp_ack_num = 32'd2000;

        if (replay_detected) begin
            $display("FAIL: Non-TCP packet triggered replay detection");
        end else begin
            $display("PASS: Non-TCP packets correctly ignored");
        end

        #(10*CLK_PERIOD);
        $display("\n========================================");
        $display("Testbench Complete");
        $display("========================================");
        $finish;
    end

    // Monitor for replay detection
    always @(posedge replay_detected) begin
        $display("REPLAY DETECTED: Suspicious IP = %0h at time %0d", suspicious_ip, time_counter);
    end

endmodule
