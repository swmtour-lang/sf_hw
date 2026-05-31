// example_100g_mac_integration.v
// Example integration of 512-bit Firewall with 100G Ethernet MAC
// This demonstrates typical signal connections and usage patterns

module firewall_100g_top (
    // System signals
    input clk,                          // 322 MHz typical for 100G
    input rst_n,
    
    // 100G Ethernet MAC TX (to firewall)
    input [511:0] mac_tx_data,
    input [63:0] mac_tx_keep,           // Byte enable signals
    input mac_tx_valid,
    input mac_tx_sop,
    input mac_tx_eop,
    
    // 100G Ethernet MAC RX (optional, for TX direction filtering)
    input [511:0] mac_rx_data,
    input [63:0] mac_rx_keep,
    input mac_rx_valid,
    input mac_rx_sop,
    input mac_rx_eop,
    
    // Firewall outputs
    output allow_packet_tx,
    output allow_packet_rx,
    output [7:0] capacity_utilization,
    output [3:0] active_alerts
);

    // Internal signals
    wire [5:0] tx_byte_count;
    wire [5:0] rx_byte_count;
    wire fw_syn_flood, fw_rst_inj, fw_tcp_hijack, fw_udp_rl;
    wire fw_ack_flood, fw_icmp_flood, fw_ping_of_death, fw_smurf;
    wire fw_replay, fw_null_scan;
    wire fw_allow_tx, fw_allow_rx;
    
    // ====================================================================
    // TX Path: 100G MAC → Firewall (inspecting outgoing traffic)
    // ====================================================================
    
    // Convert byte enable signals (64-bit TKEEP) to byte count
    // Count the number of '1' bits in keep signal
    wire [5:0] tx_byte_count_calc;
    assign tx_byte_count_calc = 
        mac_tx_keep[0] + mac_tx_keep[1] + mac_tx_keep[2] + mac_tx_keep[3] +
        mac_tx_keep[4] + mac_tx_keep[5] + mac_tx_keep[6] + mac_tx_keep[7] +
        mac_tx_keep[8] + mac_tx_keep[9] + mac_tx_keep[10] + mac_tx_keep[11] +
        mac_tx_keep[12] + mac_tx_keep[13] + mac_tx_keep[14] + mac_tx_keep[15] +
        mac_tx_keep[16] + mac_tx_keep[17] + mac_tx_keep[18] + mac_tx_keep[19] +
        mac_tx_keep[20] + mac_tx_keep[21] + mac_tx_keep[22] + mac_tx_keep[23] +
        mac_tx_keep[24] + mac_tx_keep[25] + mac_tx_keep[26] + mac_tx_keep[27] +
        mac_tx_keep[28] + mac_tx_keep[29] + mac_tx_keep[30] + mac_tx_keep[31] +
        mac_tx_keep[32] + mac_tx_keep[33] + mac_tx_keep[34] + mac_tx_keep[35] +
        mac_tx_keep[36] + mac_tx_keep[37] + mac_tx_keep[38] + mac_tx_keep[39] +
        mac_tx_keep[40] + mac_tx_keep[41] + mac_tx_keep[42] + mac_tx_keep[43] +
        mac_tx_keep[44] + mac_tx_keep[45] + mac_tx_keep[46] + mac_tx_keep[47] +
        mac_tx_keep[48] + mac_tx_keep[49] + mac_tx_keep[50] + mac_tx_keep[51] +
        mac_tx_keep[52] + mac_tx_keep[53] + mac_tx_keep[54] + mac_tx_keep[55] +
        mac_tx_keep[56] + mac_tx_keep[57] + mac_tx_keep[58] + mac_tx_keep[59] +
        mac_tx_keep[60] + mac_tx_keep[61] + mac_tx_keep[62] + mac_tx_keep[63];
    
    assign tx_byte_count = tx_byte_count_calc[5:0];  // Limit to 64 max
    
    // Firewall instance for TX path
    firewall u_fw_tx (
        .clk(clk),
        .rst(!rst_n),
        
        // Data inputs
        .packet_data(mac_tx_data),
        .packet_byte_count(tx_byte_count),
        .packet_valid(mac_tx_valid),
        .packet_sop(mac_tx_sop),
        .packet_eop(mac_tx_eop),
        .time_tick(1'b0),  // Could use timer here
        
        // Outputs
        .allow_packet(fw_allow_tx),
        .packet_ready(),
        .matched_rule_id(),
        .collision_detected(),
        .parse_error(),
        .invalid_packet(),
        .packet_count(),
        .invalid_count(),
        
        // Attack detection alerts
        .syn_flood_alert(fw_syn_flood),
        .rst_injection_alert(fw_rst_inj),
        .tcp_hijacking_alert(fw_tcp_hijack),
        .udp_rate_limit_alert(fw_udp_rl),
        .ack_flood_alert(fw_ack_flood),
        .icmp_flood_alert(fw_icmp_flood),
        .ping_of_death_alert(fw_ping_of_death),
        .smurf_attack_alert(fw_smurf),
        .replay_attack_alert(fw_replay),
        .null_scan_alert(fw_null_scan),
        
        // Capacity monitoring
        .table_occupancy(capacity_utilization),
        .capacity_percent(),
        .capacity_alert(),
        .table_full(),
        .table_overflow_event()
    );
    
    // ====================================================================
    // RX Path: 100G MAC → Firewall (inspecting incoming traffic)
    // ====================================================================
    
    wire [5:0] rx_byte_count_calc;
    assign rx_byte_count_calc = 
        mac_rx_keep[0] + mac_rx_keep[1] + mac_rx_keep[2] + mac_rx_keep[3] +
        mac_rx_keep[4] + mac_rx_keep[5] + mac_rx_keep[6] + mac_rx_keep[7] +
        mac_rx_keep[8] + mac_rx_keep[9] + mac_rx_keep[10] + mac_rx_keep[11] +
        mac_rx_keep[12] + mac_rx_keep[13] + mac_rx_keep[14] + mac_rx_keep[15] +
        mac_rx_keep[16] + mac_rx_keep[17] + mac_rx_keep[18] + mac_rx_keep[19] +
        mac_rx_keep[20] + mac_rx_keep[21] + mac_rx_keep[22] + mac_rx_keep[23] +
        mac_rx_keep[24] + mac_rx_keep[25] + mac_rx_keep[26] + mac_rx_keep[27] +
        mac_rx_keep[28] + mac_rx_keep[29] + mac_rx_keep[30] + mac_rx_keep[31] +
        mac_rx_keep[32] + mac_rx_keep[33] + mac_rx_keep[34] + mac_rx_keep[35] +
        mac_rx_keep[36] + mac_rx_keep[37] + mac_rx_keep[38] + mac_rx_keep[39] +
        mac_rx_keep[40] + mac_rx_keep[41] + mac_rx_keep[42] + mac_rx_keep[43] +
        mac_rx_keep[44] + mac_rx_keep[45] + mac_rx_keep[46] + mac_rx_keep[47] +
        mac_rx_keep[48] + mac_rx_keep[49] + mac_rx_keep[50] + mac_rx_keep[51] +
        mac_rx_keep[52] + mac_rx_keep[53] + mac_rx_keep[54] + mac_rx_keep[55] +
        mac_rx_keep[56] + mac_rx_keep[57] + mac_rx_keep[58] + mac_rx_keep[59] +
        mac_rx_keep[60] + mac_rx_keep[61] + mac_rx_keep[62] + mac_rx_keep[63];
    
    assign rx_byte_count = rx_byte_count_calc[5:0];
    
    firewall u_fw_rx (
        .clk(clk),
        .rst(!rst_n),
        
        // Data inputs
        .packet_data(mac_rx_data),
        .packet_byte_count(rx_byte_count),
        .packet_valid(mac_rx_valid),
        .packet_sop(mac_rx_sop),
        .packet_eop(mac_rx_eop),
        .time_tick(1'b0),
        
        // Outputs
        .allow_packet(fw_allow_rx),
        .packet_ready(),
        .matched_rule_id(),
        .collision_detected(),
        .parse_error(),
        .invalid_packet(),
        .packet_count(),
        .invalid_count(),
        
        // Attack detection alerts
        .syn_flood_alert(),
        .rst_injection_alert(),
        .tcp_hijacking_alert(),
        .udp_rate_limit_alert(),
        .ack_flood_alert(),
        .icmp_flood_alert(),
        .ping_of_death_alert(),
        .smurf_attack_alert(),
        .replay_attack_alert(),
        .null_scan_alert(),
        
        // Capacity monitoring
        .table_occupancy(),
        .capacity_percent(),
        .capacity_alert(),
        .table_full(),
        .table_overflow_event()
    );
    
    // ====================================================================
    // Output Generation
    // ====================================================================
    
    assign allow_packet_tx = fw_allow_tx;
    assign allow_packet_rx = fw_allow_rx;
    
    // Aggregate alerts into 4-bit vector
    assign active_alerts = {
        fw_syn_flood | fw_rst_inj | fw_tcp_hijack,
        fw_udp_rl | fw_ack_flood | fw_icmp_flood,
        fw_ping_of_death | fw_smurf,
        fw_replay | fw_null_scan
    };

endmodule


// ========================================================================
// Simplified Alternative: Single Direction (TX only)
// ========================================================================

module firewall_100g_tx_only (
    input clk,
    input rst_n,
    
    // 100G Ethernet MAC TX
    input [511:0] mac_tx_data,
    input [63:0] mac_tx_keep,
    input mac_tx_valid,
    input mac_tx_sop,
    input mac_tx_eop,
    
    // Outputs
    output allow_packet,
    output syn_flood_detect,
    output rst_injection_detect,
    output udp_rate_limit_alert
);
    
    wire [5:0] byte_count_calc;
    assign byte_count_calc = 
        mac_tx_keep[0] + mac_tx_keep[1] + mac_tx_keep[2] + mac_tx_keep[3] +
        mac_tx_keep[4] + mac_tx_keep[5] + mac_tx_keep[6] + mac_tx_keep[7] +
        mac_tx_keep[8] + mac_tx_keep[9] + mac_tx_keep[10] + mac_tx_keep[11] +
        mac_tx_keep[12] + mac_tx_keep[13] + mac_tx_keep[14] + mac_tx_keep[15] +
        mac_tx_keep[16] + mac_tx_keep[17] + mac_tx_keep[18] + mac_tx_keep[19] +
        mac_tx_keep[20] + mac_tx_keep[21] + mac_tx_keep[22] + mac_tx_keep[23] +
        mac_tx_keep[24] + mac_tx_keep[25] + mac_tx_keep[26] + mac_tx_keep[27] +
        mac_tx_keep[28] + mac_tx_keep[29] + mac_tx_keep[30] + mac_tx_keep[31] +
        mac_tx_keep[32] + mac_tx_keep[33] + mac_tx_keep[34] + mac_tx_keep[35] +
        mac_tx_keep[36] + mac_tx_keep[37] + mac_tx_keep[38] + mac_tx_keep[39] +
        mac_tx_keep[40] + mac_tx_keep[41] + mac_tx_keep[42] + mac_tx_keep[43] +
        mac_tx_keep[44] + mac_tx_keep[45] + mac_tx_keep[46] + mac_tx_keep[47] +
        mac_tx_keep[48] + mac_tx_keep[49] + mac_tx_keep[50] + mac_tx_keep[51] +
        mac_tx_keep[52] + mac_tx_keep[53] + mac_tx_keep[54] + mac_tx_keep[55] +
        mac_tx_keep[56] + mac_tx_keep[57] + mac_tx_keep[58] + mac_tx_keep[59] +
        mac_tx_keep[60] + mac_tx_keep[61] + mac_tx_keep[62] + mac_tx_keep[63];
    
    firewall u_fw (
        .clk(clk),
        .rst(!rst_n),
        .packet_data(mac_tx_data),
        .packet_byte_count(byte_count_calc[5:0]),
        .packet_valid(mac_tx_valid),
        .packet_sop(mac_tx_sop),
        .packet_eop(mac_tx_eop),
        .time_tick(1'b0),
        .allow_packet(allow_packet),
        .packet_ready(),
        .matched_rule_id(),
        .collision_detected(),
        .parse_error(),
        .invalid_packet(),
        .packet_count(),
        .invalid_count(),
        .syn_flood_alert(syn_flood_detect),
        .rst_injection_alert(rst_injection_detect),
        .tcp_hijacking_alert(),
        .udp_rate_limit_alert(udp_rate_limit_alert),
        .ack_flood_alert(),
        .icmp_flood_alert(),
        .ping_of_death_alert(),
        .smurf_attack_alert(),
        .replay_attack_alert(),
        .null_scan_alert(),
        .table_occupancy(),
        .capacity_percent(),
        .capacity_alert(),
        .table_full(),
        .table_overflow_event()
    );

endmodule
