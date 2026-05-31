// tb_udp_rate_limit.v - Testbench for UDP rate limiting and state exhaustion mitigation
`timescale 1ns / 1ps

module tb_udp_rate_limit;

    reg clk;
    reg rst;
    reg [7:0] packet_data;
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
    wire syn_flood_alert;
    wire rst_injection_alert;
    wire tcp_hijacking_alert;
    wire udp_rate_limit_alert;
    wire [7:0] table_occupancy;
    wire [7:0] capacity_percent;
    wire capacity_alert;
    wire table_full;
    wire table_overflow_event;

    firewall dut (
        .clk(clk),
        .rst(rst),
        .packet_data(packet_data),        .packet_byte_count(packet_byte_count),        .packet_valid(packet_valid),
        .packet_sop(packet_sop),
        .packet_eop(packet_eop),
        .time_tick(time_tick),
        .allow_packet(allow_packet),
        .packet_ready(packet_ready),
        .matched_rule_id(matched_rule_id),
        .collision_detected(collision_detected),
        .parse_error(parse_error),
        .invalid_packet(invalid_packet),
        .packet_count(),
        .invalid_count(),
        .syn_flood_alert(syn_flood_alert),
        .rst_injection_alert(rst_injection_alert),
        .tcp_hijacking_alert(tcp_hijacking_alert),
        .udp_rate_limit_alert(udp_rate_limit_alert),
        .table_occupancy(table_occupancy),
        .capacity_percent(capacity_percent),
        .capacity_alert(capacity_alert),
        .table_full(table_full),
        .table_overflow_event(table_overflow_event)
    );

    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        time_tick = 0;
        forever #10 time_tick = ~time_tick;
    end

    initial begin
        rst = 1;
        packet_valid = 0;
        packet_sop = 0;
        packet_eop = 0;
        packet_data = 0;
        #100;
        rst = 0;
        #20;

        $display("Starting UDP rate limiting test...");
        send_udp_packets(32'hC0A80164, 32'hC0A80101, 16'd12345, 16'd53, 66);

        #1000;
        $display("Sending UDP packet from a second source to verify fresh entry...");
        send_udp_packets(32'hC0A80165, 32'hC0A80101, 16'd12346, 16'd53, 2);

        #100;
        $display("Test completed.");
        #1000;
        $finish;
    end

    task send_udp_packets;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] src_port;
        input [15:0] dst_port;
        input integer count;
        integer i;
        for (i = 0; i < count; i = i + 1) begin
            send_udp_packet(src_ip, dst_ip, src_port, dst_port);
            #100;
        end
    endtask

    task send_udp_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] src_port;
        input [15:0] dst_port;
        reg [7:0] packet [0:39];
        integer j;
        begin
            packet[0] = 8'hFF; packet[1] = 8'hFF; packet[2] = 8'hFF; packet[3] = 8'hFF; packet[4] = 8'hFF; packet[5] = 8'hFF;
            packet[6] = 8'h00; packet[7] = 8'h00; packet[8] = 8'h00; packet[9] = 8'h00; packet[10] = 8'h00; packet[11] = 8'h00;
            packet[12] = 8'h08; packet[13] = 8'h00; // IPv4
            packet[14] = 8'h45; // Version/IHL = 5
            packet[15] = 8'h00; // DSCP/ECN
            packet[16] = 8'h00; packet[17] = 8'h28; // Total Length = 40 bytes
            packet[18] = 8'h00; packet[19] = 8'h00; // Identification
            packet[20] = 8'h00; packet[21] = 8'h00; // Flags/Fragment
            packet[22] = 8'h40; // TTL
            packet[23] = 8'h11; // Protocol (UDP)
            packet[24] = 8'h00; packet[25] = 8'h00; // Header checksum (ignored)
            packet[26] = src_ip[31:24]; packet[27] = src_ip[23:16]; packet[28] = src_ip[15:8]; packet[29] = src_ip[7:0];
            packet[30] = dst_ip[31:24]; packet[31] = dst_ip[23:16]; packet[32] = dst_ip[15:8]; packet[33] = dst_ip[7:0];
            packet[34] = src_port[15:8]; packet[35] = src_port[7:0];
            packet[36] = dst_port[15:8]; packet[37] = dst_port[7:0];
            packet[38] = 8'h00; packet[39] = 8'h08; // UDP length = 8 bytes

            packet_sop = 1;
            packet_valid = 1;
            packet_data = packet[0];
            #10;
            packet_sop = 0;

            for (j = 1; j < 40; j = j + 1) begin
                packet_data = packet[j];
                packet_eop = (j == 39);
                #10;
            end

            packet_valid = 0;
            packet_eop = 0;
            #10;
        end
    endtask

    always @(posedge udp_rate_limit_alert) begin
        $display("UDP rate limit triggered at time %0t", $time);
    end

    always @(posedge allow_packet) begin
        if (!udp_rate_limit_alert)
            $display("UDP packet allowed at time %0t", $time);
        else
            $display("UDP packet blocked due to rate limit at time %0t", $time);
    end

endmodule
