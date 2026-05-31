// tcp_hijacking_detector.v - TCP session hijacking detection and mitigation
module tcp_hijacking_detector #(
    parameter TABLE_SIZE = 128,          // Number of connections to track
    parameter SEQ_WINDOW_SIZE = 65536    // TCP sequence window size
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input [31:0] dst_ip,
    input [15:0] src_port,
    input [15:0] dst_port,
    input [31:0] tcp_seq,                // TCP sequence number
    input [15:0] tcp_payload_len,        // Payload length
    input tcp_syn,
    input tcp_ack,
    input tcp_psh,
    input packet_valid,
    input state_valid,                   // Connection exists
    input [3:0] current_state,           // Current connection state
    input [31:0] expected_seq,           // Expected sequence from state table
    output reg hijacking_detected,
    output reg [31:0] anomalous_ip,
    output reg seq_window_violation,
    output reg seq_valid
);

    // Connection key
    wire [95:0] conn_key = {src_ip, dst_ip, src_port, dst_port};

    // Hash function for connection distribution
    wire [6:0] hash_idx;
    
    // Compute hash as combinational
    assign hash_idx = conn_key[6:0] ^ conn_key[14:8] ^ conn_key[22:16] ^ conn_key[30:24] ^
                      conn_key[38:32] ^ conn_key[46:40] ^ conn_key[54:48] ^ conn_key[62:56] ^
                      conn_key[70:64] ^ conn_key[78:72] ^ conn_key[86:80] ^ conn_key[94:88];

    // Sequence offset calculation
    wire [31:0] seq_offset = tcp_seq - expected_seq;
    
    // Sequence window validation (accounts for wraparound)
    wire seq_in_window = (seq_offset < SEQ_WINDOW_SIZE) || 
                         (seq_offset > (32'hFFFFFFFF - SEQ_WINDOW_SIZE));
    
    localparam [3:0] HIGHEST_STATE = 4'b0011; // ESTABLISHED state code used for hijacking detection
    localparam [3:0] ESTABLISHED = 4'b0011;

    // Randomized ISN seed
    reg [31:0] isb_seed;
    wire [31:0] next_isb_seed = {isb_seed[30:0], 
                                  isb_seed[31] ^ isb_seed[6] ^ isb_seed[5] ^ isb_seed[4] ^ isb_seed[3]};

    // These would normally be stored in BRAM for large TABLE_SIZE
    // For now, use registers (for simulation purposes)
    reg [95:0] conn_table [0:TABLE_SIZE-1];
    reg valid_entry [0:TABLE_SIZE-1];
    reg [3:0] last_state [0:TABLE_SIZE-1];

    // Detection logic
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            integer i;
            hijacking_detected <= 0;
            seq_window_violation <= 0;
            seq_valid <= 1;
            anomalous_ip <= 0;
            isb_seed <= 32'hDEADBEEF;

            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                conn_table[i] <= 0;
                valid_entry[i] <= 0;
                last_state[i] <= 0;
            end
        end else begin
            // Update ISN seed (randomized initial sequence number source)
            isb_seed <= next_isb_seed;

            // Default: no attack and valid sequence
            hijacking_detected <= 0;
            seq_window_violation <= 0;
            seq_valid <= 1;

            if (packet_valid && state_valid) begin
                // Existing connection handling
                if (valid_entry[hash_idx] && conn_table[hash_idx] == conn_key) begin
                    // Data packet in established state
                    if ((tcp_psh || tcp_payload_len > 0) && (current_state == ESTABLISHED)) begin
                        if (!seq_in_window) begin
                            // Sequence outside window = hijacking attempt
                            hijacking_detected <= 1;
                            seq_window_violation <= 1;
                            seq_valid <= 0;
                            anomalous_ip <= src_ip;
                        end else begin
                            seq_valid <= 1;
                        end
                    end

                    // Update state
                    last_state[hash_idx] <= current_state;

                end else if (tcp_syn && !tcp_ack) begin
                    // New connection (SYN)
                    conn_table[hash_idx] <= conn_key;
                    valid_entry[hash_idx] <= 1;
                    last_state[hash_idx] <= 4'b0001;  // SYN_SENT

                end else if (tcp_syn && tcp_ack) begin
                    // SYN-ACK response
                    if (valid_entry[hash_idx] && conn_table[hash_idx] == conn_key) begin
                        last_state[hash_idx] <= 4'b0011;  // ESTABLISHED
                    end
                end
            end

            // Periodic cleanup of closed connections
            if (isb_seed[15:0] == 16'h0000) begin
                integer j;
                for (j = 0; j < TABLE_SIZE; j = j + 1) begin
                    if (valid_entry[j] && (last_state[j] == 4'b0000)) begin
                        valid_entry[j] <= 0;
                    end
                end
            end
        end
    end

endmodule
