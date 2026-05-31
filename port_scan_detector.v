// port_scan_detector.v - TCP Connect scan detection module
// TCP Connect scan: SYN packets to multiple ports from same IP
module port_scan_detector #(
    parameter TABLE_SIZE = 64,      // Number of IP addresses to track
    parameter PORT_THRESHOLD = 10,  // Max unique ports per IP per time window
    parameter TIME_WINDOW = 2000    // Time window in clock cycles (adjust based on clock frequency)
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input [15:0] dst_port,
    input tcp_syn,
    input packet_valid,
    output reg port_scan_detected,
    output reg [31:0] suspicious_ip
);

// Hash function for IP address distribution
function [5:0] ip_hash;
    input [31:0] ip;
    begin
        ip_hash = ip[5:0] ^ ip[13:8] ^ ip[21:16] ^ ip[29:24];
    end
endfunction

// Port tracking table
reg [15:0] port_count [0:TABLE_SIZE-1];  // Unique port count per IP
reg [31:0] ip_table [0:TABLE_SIZE-1];    // Stored IP addresses
reg [31:0] timestamp [0:TABLE_SIZE-1];  // Last update timestamp
reg valid_entry [0:TABLE_SIZE-1];       // Valid entry flag
reg [65535:0] port_bitmap [0:TABLE_SIZE-1]; // Bitmap of ports accessed (up to 64K ports)

// Global timestamp counter
reg [31:0] global_time;

// Current packet processing
wire [5:0] hash_idx = ip_hash(src_ip);
wire syn_packet = tcp_syn && packet_valid;

// Port scan detection logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        integer i;
        global_time <= 0;
        port_scan_detected <= 0;
        suspicious_ip <= 0;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            port_count[i] <= 0;
            ip_table[i] <= 0;
            timestamp[i] <= 0;
            valid_entry[i] <= 0;
            port_bitmap[i] <= 0;
        end
    end else begin
        global_time <= global_time + 1;

        // Reset port_scan_detected at each cycle unless we're detecting a new scan
        port_scan_detected <= 0;

        if (syn_packet) begin
            // Check if IP already exists in table
            if (valid_entry[hash_idx] && ip_table[hash_idx] == src_ip) begin
                // Existing IP - check time window
                if (global_time - timestamp[hash_idx] > TIME_WINDOW) begin
                    // Time window expired, reset counter and bitmap
                    port_count[hash_idx] <= 1;
                    timestamp[hash_idx] <= global_time;
                    port_bitmap[hash_idx] <= (1 << dst_port);
                end else begin
                    // Within time window, check if port is new
                    if (!(port_bitmap[hash_idx] & (1 << dst_port))) begin
                        // New port accessed
                        port_count[hash_idx] <= port_count[hash_idx] + 1;
                        port_bitmap[hash_idx] <= port_bitmap[hash_idx] | (1 << dst_port);
                        if (port_count[hash_idx] >= PORT_THRESHOLD) begin
                            // Port scan detected!
                            port_scan_detected <= 1;
                            suspicious_ip <= src_ip;
                        end
                    end
                end
            end else begin
                // New IP or hash collision - add to table
                ip_table[hash_idx] <= src_ip;
                port_count[hash_idx] <= 1;
                timestamp[hash_idx] <= global_time;
                valid_entry[hash_idx] <= 1;
                port_bitmap[hash_idx] <= (1 << dst_port);
            end
        end

        // Periodically clean up old entries (every 1000 cycles)
        if (global_time[9:0] == 10'b0000000000) begin
            integer j;
            for (j = 0; j < TABLE_SIZE; j = j + 1) begin
                if (valid_entry[j] && (global_time - timestamp[j] > TIME_WINDOW * 2)) begin
                    // Entry is too old, clear it
                    valid_entry[j] <= 0;
                    port_count[j] <= 0;
                    port_bitmap[j] <= 0;
                end
            end
        end
    end
end

endmodule