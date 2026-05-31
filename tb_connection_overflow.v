// tb_connection_overflow.v - Testbench for connection table overflow and LRU eviction
`timescale 1ns / 1ps

module tb_connection_overflow;

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
    wire rst_injection_alert;
    wire tcp_hijacking_alert;
    // Capacity monitoring outputs
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
        .allow_packet(allow_packet),
        .packet_ready(packet_ready),
        .matched_rule_id(matched_rule_id),
        .collision_detected(collision_detected),
        .parse_error(parse_error),
        .syn_flood_alert(syn_flood_alert),
        .rst_injection_alert(rst_injection_alert),
        .tcp_hijacking_alert(tcp_hijacking_alert),
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

    // Task to send a TCP packet with specific parameters
    task send_tcp_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] src_port;
        input [15:0] dst_port;
        input [31:0] seq_num;
        input [7:0] flags;        // TCP flags
        begin
            integer i;
            reg [7:0] packet [0:127];

            // Build Ethernet header (14 bytes)
            packet[0] = 8'hFF; packet[1] = 8'hFF; packet[2] = 8'hFF; packet[3] = 8'hFF; packet[4] = 8'hFF; packet[5] = 8'hFF; // DST MAC
            packet[6] = 8'h00; packet[7] = 8'h00; packet[8] = 8'h00; packet[9] = 8'h00; packet[10] = 8'h00; packet[11] = 8'h00; // SRC MAC
            packet[12] = 8'h08; packet[13] = 8'h00; // EtherType (IP)

            // Build IP header (20 bytes)
            packet[14] = 8'h45; // Version/IHL
            packet[15] = 8'h00; // DSCP/ECN
            packet[16] = 8'h00; packet[17] = 8'h54; // Total Length (84 bytes)
            packet[18] = 8'h00; packet[19] = 8'h00; // Identification
            packet[20] = 8'h00; packet[21] = 8'h00; // Flags/Fragment
            packet[22] = 8'h40; // TTL
            packet[23] = 8'h06; // Protocol (TCP)
            packet[24] = 8'h00; packet[25] = 8'h00; // Header Checksum
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

            // Send packet (54 bytes total)
            packet_sop = 1;
            packet_valid = 1;
            packet_data = packet[0];
            #10;

            packet_sop = 0;
            for (i = 1; i < 54; i = i + 1) begin
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

        $display("========================================");
        $display("Connection Table Overflow Test");
        $display("========================================");

        $display("\n[Phase 1] Creating connections one-by-one and monitoring capacity...");
        $display("Expected: Capacity increases as connections are added");

        // Create multiple connections
        // For a 256-entry table, create ~280 connections to trigger overflow
        // (accounting for hash collisions that might not use all 256 entries)
        for (int conn = 0; conn < 280; conn = conn + 1) begin
            // Vary source IPs and ports to create different connections
            reg [31:0] src;
            reg [15:0] port;
            
            src = 32'hC0A80100 + conn;  // 192.168.1.x + conn
            port = 16'd1000 + conn;

            send_tcp_packet(src, 32'hC0A80101, port, 16'd80, 32'h10000000, 8'h02); // SYN
            
            // Print capacity status every 32 connections
            if ((conn % 32) == 0 && conn > 0) begin
                #100;
                $display("[%t] Conn %d: Table Occupancy=%d, Capacity=%d%%, Alert=%b, Full=%b, Overflow=%b", 
                    $time, conn, table_occupancy, capacity_percent, capacity_alert, table_full, table_overflow_event);
            end
        end

        #200;

        $display("\n[Phase 2] Monitoring final table state...");
        $display("Peak Occupancy=%d entries", table_occupancy);
        $display("Peak Capacity=%d%%", capacity_percent);
        $display("Capacity Alert Active=%b", capacity_alert);
        $display("Table Full=%b", table_full);

        $display("\n[Phase 3] Testing LRU eviction by reusing least-recently-used slots...");
        // Try to establish a new connection (should trigger LRU eviction if table full)
        send_tcp_packet(32'hDEADBEEF, 32'hC0A80101, 16'd5555, 16'd80, 32'h20000000, 8'h02);
        
        #200;
        $display("After LRU eviction attempt:");
        $display("Occupancy=%d entries", table_occupancy);
        $display("Capacity=%d%%", capacity_percent);
        $display("Overflow Event Detected=%b", table_overflow_event);

        $display("\n[Phase 4] Testing capacity alert threshold...");
        $display("Capacity Alert (threshold >=90%%) is %s", capacity_alert ? "ACTIVE" : "INACTIVE");

        $display("\n========================================");
        $display("Test completed.");
        $display("========================================");
        #1000;
        $finish;
    end

    // Monitor capacity in real-time
    always @(posedge clk) begin
        if (capacity_alert && !packet_sop) begin
            // Log when capacity alert is triggered
            static int alert_count = 0;
            if (alert_count == 0) begin
                $display("[%t] ⚠️  CAPACITY ALERT: Table usage exceeded threshold!", $time);
                alert_count = alert_count + 1;
            end
        end
    end

    // Monitor table full condition
    always @(posedge table_full) begin
        $display("[%t] 🚨 TABLE FULL: Connection table is at capacity!", $time);
    end

    // Monitor overflow events
    always @(posedge table_overflow_event) begin
        $display("[%t] ⚠️  OVERFLOW EVENT: Attempting to add connection with table full!", $time);
    end

    // Log packet decisions with capacity context
    always @(posedge packet_ready) begin
        if (allow_packet)
            $display("[%t] ✓  Packet ALLOWED (Occupancy: %d/%d, %d%%)", $time, table_occupancy, 256, capacity_percent);
        else if (table_full)
            $display("[%t] ✗  Packet BLOCKED - Table full (Occupancy: %d/%d, %d%%)", $time, table_occupancy, 256, capacity_percent);
        else
            $display("[%t] ✗  Packet BLOCKED (Occupancy: %d/%d, %d%%)", $time, table_occupancy, 256, capacity_percent);
    end

endmodule
