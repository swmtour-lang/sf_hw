// rst_injection_detector.v - RST injection attack detection and mitigation
module rst_injection_detector #(
    parameter TABLE_SIZE = 128,     // Number of connections to track
    parameter RST_THRESHOLD = 3,    // Max RST packets per connection per time window
    parameter TIME_WINDOW = 500     // Time window in clock cycles
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input [31:0] dst_ip,
    input [15:0] src_port,
    input [15:0] dst_port,
    input tcp_rst,
    input packet_valid,
    input [31:0] tcp_seq,           // TCP sequence number
    input state_valid,              // Connection exists in state table
    input [1:0] current_state,      // Current connection state
    input [31:0] expected_seq,      // Expected sequence number from state table
    output reg rst_injection_detected,
    output reg [31:0] suspicious_ip,
    output reg seq_mismatch_alert
);

// Connection key for tracking
wire [95:0] conn_key = {src_ip, dst_ip, src_port, dst_port};

// Hash function for connection distribution
function [6:0] conn_hash;
    input [95:0] key;
    begin
        // Simple hash using XOR of different bit fields
        conn_hash = key[6:0] ^ key[14:8] ^ key[22:16] ^ key[30:24] ^
                   key[38:32] ^ key[46:40] ^ key[54:48] ^ key[62:56] ^
                   key[70:64] ^ key[78:72] ^ key[86:80] ^ key[94:88];
    end
endfunction

// RST tracking table
reg [15:0] rst_count [0:TABLE_SIZE-1];     // RST packet count per connection
reg [95:0] conn_table [0:TABLE_SIZE-1];    // Stored connection keys
reg [31:0] timestamp [0:TABLE_SIZE-1];     // Last update timestamp
reg valid_entry [0:TABLE_SIZE-1];          // Valid entry flag

// Global timestamp counter
reg [31:0] global_time;

// Current packet processing
wire [6:0] hash_idx = conn_hash(conn_key);
wire rst_packet = tcp_rst && packet_valid;

// Sequence number validation
wire seq_valid = (tcp_seq == expected_seq) || (tcp_seq == expected_seq + 1);

// RST injection detection logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        integer i;
        global_time <= 0;
        rst_injection_detected <= 0;
        suspicious_ip <= 0;
        seq_mismatch_alert <= 0;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            rst_count[i] <= 0;
            conn_table[i] <= 0;
            timestamp[i] <= 0;
            valid_entry[i] <= 0;
        end
    end else begin
        global_time <= global_time + 1;

        // Reset alerts at each cycle unless we're detecting new attacks
        rst_injection_detected <= 0;
        seq_mismatch_alert <= 0;

        if (rst_packet) begin
            // Check if connection exists in table
            if (valid_entry[hash_idx] && conn_table[hash_idx] == conn_key) begin
                // Existing connection - check time window and sequence
                if (global_time - timestamp[hash_idx] > TIME_WINDOW) begin
                    // Time window expired, reset counter
                    rst_count[hash_idx] <= 1;
                    timestamp[hash_idx] <= global_time;
                end else begin
                    // Within time window, increment counter
                    rst_count[hash_idx] <= rst_count[hash_idx] + 1;
                    if (rst_count[hash_idx] >= RST_THRESHOLD) begin
                        // RST injection detected!
                        rst_injection_detected <= 1;
                        suspicious_ip <= src_ip;
                    end
                end
            end else begin
                // New connection or hash collision - add to table
                conn_table[hash_idx] <= conn_key;
                rst_count[hash_idx] <= 1;
                timestamp[hash_idx] <= global_time;
                valid_entry[hash_idx] <= 1;
            end

            // Check sequence number validity for RST packets
            if (state_valid && !seq_valid && (current_state != 2'b00)) begin
                // RST packet with invalid sequence number for active connection
                seq_mismatch_alert <= 1;
                suspicious_ip <= src_ip;
            end
        end

        // Periodically clean up old entries (every 1000 cycles)
        if (global_time[9:0] == 10'b0000000000) begin
            integer j;
            for (j = 0; j < TABLE_SIZE; j = j + 1) begin
                if (valid_entry[j] && (global_time - timestamp[j] > TIME_WINDOW * 2)) begin
                    // Entry is too old, clear it
                    valid_entry[j] <= 0;
                    rst_count[j] <= 0;
                end
            end
        end
    end
end

endmodule</content>
<parameter name="filePath">/workspaces/sf_hw/rst_injection_detector.v