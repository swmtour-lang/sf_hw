// xmas_scan_detector.v - Xmas scan detection module
// Xmas scan: TCP packets with FIN, PSH, and URG flags set simultaneously
module xmas_scan_detector #(
    parameter TABLE_SIZE = 64,      // Number of IP addresses to track
    parameter XMAS_THRESHOLD = 5,   // Max Xmas packets per IP per time window
    parameter TIME_WINDOW = 1000    // Time window in clock cycles (adjust based on clock frequency)
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input tcp_fin,
    input tcp_psh,
    input tcp_urg,
    input packet_valid,
    output reg xmas_scan_detected,
    output reg [31:0] suspicious_ip
);

// Hash function for IP address distribution
function [5:0] ip_hash;
    input [31:0] ip;
    begin
        ip_hash = ip[5:0] ^ ip[13:8] ^ ip[21:16] ^ ip[29:24];
    end
endfunction

// Xmas packet counter table
reg [15:0] xmas_count [0:TABLE_SIZE-1];  // Xmas packet count per IP
reg [31:0] ip_table [0:TABLE_SIZE-1];    // Stored IP addresses
reg [31:0] timestamp [0:TABLE_SIZE-1];  // Last update timestamp
reg valid_entry [0:TABLE_SIZE-1];       // Valid entry flag

// Global timestamp counter
reg [31:0] global_time;

// Current packet processing
wire [5:0] hash_idx = ip_hash(src_ip);
wire xmas_packet = tcp_fin && tcp_psh && tcp_urg && packet_valid;

// Xmas scan detection logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        integer i;
        global_time <= 0;
        xmas_scan_detected <= 0;
        suspicious_ip <= 0;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            xmas_count[i] <= 0;
            ip_table[i] <= 0;
            timestamp[i] <= 0;
            valid_entry[i] <= 0;
        end
    end else begin
        global_time <= global_time + 1;

        // Reset xmas_scan_detected at each cycle unless we're detecting a new scan
        xmas_scan_detected <= 0;

        if (xmas_packet) begin
            // Check if IP already exists in table
            if (valid_entry[hash_idx] && ip_table[hash_idx] == src_ip) begin
                // Existing IP - check time window
                if (global_time - timestamp[hash_idx] > TIME_WINDOW) begin
                    // Time window expired, reset counter
                    xmas_count[hash_idx] <= 1;
                    timestamp[hash_idx] <= global_time;
                end else begin
                    // Within time window, increment counter
                    xmas_count[hash_idx] <= xmas_count[hash_idx] + 1;
                    if (xmas_count[hash_idx] >= XMAS_THRESHOLD) begin
                        // Xmas scan detected!
                        xmas_scan_detected <= 1;
                        suspicious_ip <= src_ip;
                    end
                end
            end else begin
                // New IP or hash collision - add to table
                ip_table[hash_idx] <= src_ip;
                xmas_count[hash_idx] <= 1;
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
                    xmas_count[j] <= 0;
                end
            end
        end
    end
end

endmodule