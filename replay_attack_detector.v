// replay_attack_detector.v - TCP replay attack detection using timestamp validation
module replay_attack_detector #(
    parameter TABLE_SIZE = 256,
    parameter TIME_WINDOW = 1000,     // Maximum age for valid packets (in clock cycles)
    parameter MAX_DUPLICATES = 3      // Maximum duplicate packets allowed
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        packet_valid,
    input  wire        is_tcp,
    input  wire        state_valid,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] src_port,
    input  wire [15:0] dst_port,
    input  wire [31:0] tcp_seq,
    input  wire [31:0] tcp_ack_num,
    input  wire [31:0] time_counter,
    output reg         replay_detected,
    output reg [31:0]  suspicious_ip
);

    // Connection key for tracking
    wire [95:0] conn_key = {src_ip, dst_ip, src_port, dst_port};

    // Hash function for connection distribution
    function [7:0] conn_hash;
        input [95:0] key;
        begin
            conn_hash = key[7:0] ^ key[15:8] ^ key[23:16] ^ key[31:24] ^
                       key[39:32] ^ key[47:40] ^ key[55:48] ^ key[63:56] ^
                       key[71:64] ^ key[79:72] ^ key[87:80] ^ key[95:88];
        end
    endfunction

    // Packet signature for duplicate detection
    wire [63:0] packet_sig = {tcp_seq, tcp_ack_num};

    // Tracking tables
    reg [95:0] conn_table [0:TABLE_SIZE-1];        // Connection keys
    reg [31:0] last_timestamp [0:TABLE_SIZE-1];    // Last packet timestamp
    reg [63:0] last_packet_sig [0:TABLE_SIZE-1];   // Last packet signature
    reg [3:0] duplicate_count [0:TABLE_SIZE-1];    // Duplicate packet counter
    reg valid_entry [0:TABLE_SIZE-1];              // Valid entry flag

    integer i;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            replay_detected <= 0;
            suspicious_ip <= 0;
            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                conn_table[i] <= 0;
                last_timestamp[i] <= 0;
                last_packet_sig[i] <= 0;
                duplicate_count[i] <= 0;
                valid_entry[i] <= 0;
            end
        end else begin
            // Default: no replay detected
            replay_detected <= 0;
            suspicious_ip <= 0;

            if (packet_valid && is_tcp && state_valid) begin
                wire [7:0] hash_idx = conn_hash(conn_key);

                // Check if connection exists in table
                if (valid_entry[hash_idx] && conn_table[hash_idx] == conn_key) begin
                    // Existing connection - check for replay attacks

                    // 1. Timestamp validation (packet too old?)
                    if (time_counter - last_timestamp[hash_idx] > TIME_WINDOW) begin
                        // Packet is too old - potential replay attack
                        replay_detected <= 1;
                        suspicious_ip <= src_ip;
                    end

                    // 2. Duplicate packet detection
                    if (last_packet_sig[hash_idx] == packet_sig) begin
                        // Same packet signature as last one
                        duplicate_count[hash_idx] <= duplicate_count[hash_idx] + 1;

                        if (duplicate_count[hash_idx] >= MAX_DUPLICATES) begin
                            // Too many duplicates - replay attack
                            replay_detected <= 1;
                            suspicious_ip <= src_ip;
                        end
                    end else begin
                        // Different packet - reset duplicate counter
                        duplicate_count[hash_idx] <= 0;
                        last_packet_sig[hash_idx] <= packet_sig;
                    end

                    // Update timestamp
                    last_timestamp[hash_idx] <= time_counter;

                end else begin
                    // New connection or hash collision - add to table
                    conn_table[hash_idx] <= conn_key;
                    last_timestamp[hash_idx] <= time_counter;
                    last_packet_sig[hash_idx] <= packet_sig;
                    duplicate_count[hash_idx] <= 0;
                    valid_entry[hash_idx] <= 1;
                end
            end
        end
    end

endmodule
