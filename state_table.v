// state_table.v - Detailed State table for connection tracking with LRU eviction and capacity alerts
module state_table #(
    parameter TABLE_SIZE = 256,
    parameter KEY_WIDTH = 96,                           // 32-bit src_ip + 32-bit dst_ip + 16-bit src_port + 16-bit dst_port
    parameter CAPACITY_THRESHOLD = 90,                  // Percentage (0-100) for capacity alert
    parameter LRU_TIMER_WIDTH = 16                      // LRU timestamp width (cycles mod 2^16)
)(
    input clk,
    input rst,
    input [31:0] src_ip,
    input [31:0] dst_ip,
    input [15:0] src_port,
    input [15:0] dst_port,
    input packet_type,  // 0: TCP, 1: UDP
    input tcp_syn,
    input tcp_ack,
    input tcp_fin,
    input tcp_rst,
    input [31:0] tcp_seq,                   // TCP sequence number (for RST validation)
    output reg state_valid,
    output reg [3:0] current_state,
    output reg [31:0] expected_seq,         // Expected sequence number for validation
    input update_state,
    input [3:0] new_state,
    input time_tick,  // Timeout tick
    output reg timeout_expired,
    output reg collision_detected,
    // Capacity monitoring outputs
    output reg [7:0] table_occupancy,       // Number of valid entries
    output reg [7:0] capacity_percent,      // 0-100 percentage
    output reg capacity_alert,              // High when table usage exceeds threshold
    output reg table_full,                  // High when table is completely full
    output reg table_overflow_event         // Pulses when LRU eviction happens on full table
);

// States
localparam [3:0] CLOSED      = 4'b0000;
localparam [3:0] SYN_SENT    = 4'b0001;
localparam [3:0] ESTABLISHED = 4'b0010;
localparam [3:0] FIN_WAIT    = 4'b0011;

// Hash function: CRC-32 like hash for better distribution
function [7:0] compute_hash;
    input [95:0] key;
    reg [31:0] crc;
    integer i;
    begin
        crc = 32'hFFFFFFFF;
        for (i = 0; i < 96; i = i + 1) begin
            if ((crc ^ key[i]) & 1) begin
                crc = (crc >> 1) ^ 32'hEDB88320;
            end else begin
                crc = crc >> 1;
            end
        end
        compute_hash = crc[7:0] ^ crc[15:8] ^ crc[23:16] ^ crc[31:24];
    end
endfunction

// Connection key
wire [95:0] conn_key = {src_ip, dst_ip, src_port, dst_port};
wire [7:0] hash = compute_hash(conn_key);

// State memory: 4 bits per entry
reg [3:0] state_mem [0:TABLE_SIZE-1];
reg valid_mem [0:TABLE_SIZE-1];
reg [95:0] key_mem [0:TABLE_SIZE-1];           // Store full key for collision detection
reg [31:0] seq_mem [0:TABLE_SIZE-1];           // Store sequence number for RST validation
reg [LRU_TIMER_WIDTH-1:0] lru_timer [0:TABLE_SIZE-1]; // LRU timestamp for each entry
reg [31:0] timeout_counter [0:TABLE_SIZE-1];   // Timeout counter per entry
// Global LRU timestamp (increments each cycle)
reg [LRU_TIMER_WIDTH-1:0] global_lru_timer;

// Occupancy counter
integer occupancy_count;

// Find LRU (Least Recently Used) entry
function [7:0] find_lru;
    input [95:0] dummy;  // Unused, for function compatibility
    reg [7:0] i;
    reg [7:0] lru_idx;
    reg [LRU_TIMER_WIDTH-1:0] lru_val;
    begin
        lru_idx = 0;
        lru_val = lru_timer[0];
        for (i = 1; i < TABLE_SIZE; i = i + 1) begin
            if (valid_mem[i] && lru_timer[i] < lru_val) begin
                lru_val = lru_timer[i];
                lru_idx = i;
            end
        end
        find_lru = lru_idx;
    end
endfunction

// Read state with collision check and LRU update on access
always @(posedge clk) begin
    if (rst) begin
        current_state <= CLOSED;
        expected_seq <= 0;
        state_valid <= 0;
        collision_detected <= 0;
    end else begin
        if (valid_mem[hash] && key_mem[hash] == conn_key) begin
            current_state <= state_mem[hash];
            expected_seq <= seq_mem[hash];
            state_valid <= 1;
            collision_detected <= 0;
            // Update LRU timestamp on access (will be applied in sequential block below)
        end else if (valid_mem[hash] && key_mem[hash] != conn_key) begin
            // Hash collision
            current_state <= CLOSED;
            expected_seq <= 0;
            state_valid <= 0;
            collision_detected <= 1;
        end else begin
            current_state <= CLOSED;
            expected_seq <= 0;
            state_valid <= 0;
            collision_detected <= 0;
        end
    end
end


// Update state with LRU eviction on overflow
always @(posedge clk or posedge rst) begin
    if (rst) begin
        integer i;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            state_mem[i] <= CLOSED;
            valid_mem[i] <= 0;
            key_mem[i] <= 0;
            seq_mem[i] <= 0;
            lru_timer[i] <= 0;
            timeout_counter[i] <= 0;
        end
        global_lru_timer <= 0;
        collision_detected <= 0;
        table_overflow_event <= 0;
    end else begin
        // Increment global LRU timer every cycle
        global_lru_timer <= global_lru_timer + 1;
        table_overflow_event <= 0;
        
        // Update LRU timestamp on read access
        if (valid_mem[hash] && key_mem[hash] == conn_key) begin
            lru_timer[hash] <= global_lru_timer;
        end
        
        // Handle state updates
        if (update_state) begin
            if (!valid_mem[hash] || key_mem[hash] == conn_key) begin
                // No collision or same key - normal update
                state_mem[hash] <= new_state;
                seq_mem[hash] <= tcp_seq;
                valid_mem[hash] <= 1;
                key_mem[hash] <= conn_key;
                lru_timer[hash] <= global_lru_timer;  // Update LRU on write
                timeout_counter[hash] <= 0;  // Reset timeout
                collision_detected <= 0;
            end else begin
                // Hash collision - check if table is full
                reg [7:0] lru_idx;
                
                // Count occupied entries
                // (occupancy_count updated in always block below)
                if (occupancy_count >= TABLE_SIZE) begin
                    // Table full - evict LRU entry
                    lru_idx = find_lru(0);
                    state_mem[lru_idx] <= new_state;
                    seq_mem[lru_idx] <= tcp_seq;
                    valid_mem[lru_idx] <= 1;
                    key_mem[lru_idx] <= conn_key;
                    lru_timer[lru_idx] <= global_lru_timer;
                    timeout_counter[lru_idx] <= 0;
                    collision_detected <= 0;
                    table_overflow_event <= 1;
                end else begin
                    // Hash collision but table not full - keep collision flag
                    collision_detected <= 1;
                end
            end
        end
        
        // Timeout logic - age entries and clear expired ones
        begin
            integer i;
            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                if (valid_mem[i]) begin
                    timeout_counter[i] <= timeout_counter[i] + 1;
                    // Clear closed connections after timeout (1000000 cycles)
                    if (timeout_counter[i] > 1000000 && state_mem[i] == CLOSED) begin
                        valid_mem[i] <= 0;
                        state_mem[i] <= CLOSED;
                        key_mem[i] <= 0;
                        seq_mem[i] <= 0;
                    end
                end else begin
                    timeout_counter[i] <= 0;
                end
            end
        end
    end
end

// Capacity monitoring block
always @(posedge clk or posedge rst) begin
    if (rst) begin
        occupancy_count <= 0;
        table_occupancy <= 0;
        capacity_percent <= 0;
        capacity_alert <= 0;
        table_full <= 0;
    end else begin
        // Count occupied entries
        integer i;
        integer count;
        count = 0;
        for (i = 0; i < TABLE_SIZE; i = i + 1) begin
            if (valid_mem[i]) begin
                count = count + 1;
            end
        end
        occupancy_count <= count;
        table_occupancy <= count[7:0];  // Occupancy in number of entries
        
        // Calculate capacity percentage (count * 100) / TABLE_SIZE
        // Simplified: capacity_percent = (count << 6) / TABLE_SIZE (approximation)
        capacity_percent <= (count * 100) / TABLE_SIZE;
        
        // Capacity alerts
        if ((count * 100) / TABLE_SIZE >= CAPACITY_THRESHOLD) begin
            capacity_alert <= 1;  // > 90% by default
        end else begin
            capacity_alert <= 0;
        end
        
        if (count >= TABLE_SIZE) begin
            table_full <= 1;
        end else begin
            table_full <= 0;
        end
    end
end

endmodule