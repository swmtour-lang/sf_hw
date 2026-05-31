// syn_flood_detector.v - SYN flood detection and mitigation module
module syn_flood_detector #(
    parameter TABLE_SIZE = 64,      // Number of IP addresses to track
    parameter SYN_THRESHOLD = 10,   // Max SYN packets per IP per time window
    parameter TIME_WINDOW = 1000    // Time window in clock cycles (adjust based on clock frequency)
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input tcp_syn,
    input packet_valid,
    output reg syn_flood_detected,
    output reg [31:0] blocked_ip
);

// Hash function for IP address distribution
function [5:0] ip_hash;
    input [31:0] ip;
    begin
        ip_hash = ip[5:0] ^ ip[13:8] ^ ip[21:16] ^ ip[29:24];
    end
endfunction

// SYN counter table
reg [15:0] syn_count [0:TABLE_SIZE-1];  // SYN packet count per IP
reg [31:0] ip_table [0:TABLE_SIZE-1];   // Stored IP addresses
reg [31:0] timestamp [0:TABLE_SIZE-1]; // Last update timestamp
reg valid_entry [0:TABLE_SIZE-1];      // Valid entry flag

// Global timestamp counter
reg [31:0] global_time;

// Current packet processing
wire [5:0] hash_idx = ip_hash(src_ip);
wire syn_packet = tcp_syn && packet_valid;

// SYN flood detection logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        integer i;
        global_time <= 0;
        syn_flood_detected <= 0;
        blocked_ip <= 0;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            syn_count[i] <= 0;
            ip_table[i] <= 0;
            timestamp[i] <= 0;
            valid_entry[i] <= 0;
        end
    end else begin
        global_time <= global_time + 1;

        // Reset syn_flood_detected at each cycle unless we're detecting a new flood
        syn_flood_detected <= 0;

        if (syn_packet) begin
            // Check if IP already exists in table
            if (valid_entry[hash_idx] && ip_table[hash_idx] == src_ip) begin
                // Existing IP - check time window
                if (global_time - timestamp[hash_idx] > TIME_WINDOW) begin
                    // Time window expired, reset counter
                    syn_count[hash_idx] <= 1;
                    timestamp[hash_idx] <= global_time;
                end else begin
                    // Within time window, increment counter
                    syn_count[hash_idx] <= syn_count[hash_idx] + 1;
                    if (syn_count[hash_idx] >= SYN_THRESHOLD) begin
                        // SYN flood detected!
                        syn_flood_detected <= 1;
                        blocked_ip <= src_ip;
                    end
                end
            end else begin
                // New IP or hash collision - add to table
                ip_table[hash_idx] <= src_ip;
                syn_count[hash_idx] <= 1;
                timestamp[hash_idx] <= global_time;
                valid_entry[hash_idx] <= 1;
            end
        end

        // Periodically clean up old entries (every 1000 cycles)
        if (global_time[9:0] == 10'b0000000000) begin
            integer j;
            for (j = 0; j < TABLE_SIZE; j = j + 1) begin
                if (valid_entry[j] && (global_time - timestamp[j] > TIME_WINDOW * 2)) begin
                    // Entry is too old, clear it
                    valid_entry[j] <= 0;
                    syn_count[j] <= 0;
                end
            end
        end
    end
end

endmodule</content>
<parameter name="filePath">/workspaces/sf_hw/syn_flood_detector.v