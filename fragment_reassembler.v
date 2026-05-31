// fragment_reassembler.v - IP fragment reassembly with 512-bit input support
// Note: 512-bit input processed internally as byte stream for compatibility
module fragment_reassembler #(
    parameter MAX_FRAGMENTS = 8,
    parameter FRAGMENT_TIMEOUT = 1000000,  // Cycles before timeout
    parameter BUFFER_SIZE = 2048  // Max reassembled packet size
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        packet_valid,
    input  wire        packet_sop,
    input  wire        packet_eop,
    input  wire [511:0] packet_data,      // 512-bit input from 100G MAC
    input  wire [5:0]  packet_byte_count, // Valid bytes in packet_data (1-64)
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] identification,
    input  wire        more_fragments,
    input  wire [12:0] frag_offset,
    input  wire [15:0] total_length,
    input  wire [7:0]  protocol,
    output reg         reassembled_valid,
    output reg         reassembled_sop,
    output reg         reassembled_eop,
    output reg [7:0]   reassembled_data,
    output reg         overlap_conflict,
    output reg         reassembly_timeout
);

    // Fragment storage
    reg [7:0] fragment_buffer [0:BUFFER_SIZE-1];
    reg [BUFFER_SIZE-1:0] valid_bytes;
    reg [15:0] expected_length;
    reg [31:0] fragment_src_ip, fragment_dst_ip;
    reg [15:0] fragment_id;
    reg [7:0] fragment_protocol;
    reg [31:0] last_update_time;
    reg active_reassembly;
    reg [3:0] fragment_count;

    // Current fragment accumulation
    reg [7:0] current_fragment [0:BUFFER_SIZE-1];
    reg [11:0] current_frag_ptr;
    reg [15:0] current_frag_offset;
    reg current_frag_more;
    
    // 512-bit deserializer for byte-stream processing
    reg [5:0] byte_index;  // Current byte index within 512-bit word
    wire [7:0] current_byte = packet_data[(511 - (byte_index << 3)) -: 8];  // Extract current byte

    // Reassembly state
    reg [1:0] state;
    localparam IDLE = 2'b00, COLLECTING = 2'b01, OUTPUTTING = 2'b10, CONFLICT = 2'b11;

    // Output control
    reg [11:0] output_ptr;
    reg outputting;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            active_reassembly <= 0;
            fragment_count <= 0;
            expected_length <= 0;
            fragment_src_ip <= 0;
            fragment_dst_ip <= 0;
            fragment_id <= 0;
            fragment_protocol <= 0;
            last_update_time <= 0;
            valid_bytes <= 0;
            state <= IDLE;
            output_ptr <= 0;
            outputting <= 0;
            reassembled_valid <= 0;
            reassembled_sop <= 0;
            reassembled_eop <= 0;
            reassembled_data <= 0;
            overlap_conflict <= 0;
            reassembly_timeout <= 0;
            current_frag_ptr <= 0;
            current_frag_offset <= 0;
            current_frag_more <= 0;
        end else begin
            last_update_time <= last_update_time + 1;
            reassembled_valid <= 0;
            reassembled_sop <= 0;
            reassembled_eop <= 0;
            overlap_conflict <= 0;
            reassembly_timeout <= 0;

            // Check for timeout
            if (active_reassembly && (last_update_time - last_update_time) > FRAGMENT_TIMEOUT) begin
                active_reassembly <= 0;
                fragment_count <= 0;
                valid_bytes <= 0;
                state <= IDLE;
                reassembly_timeout <= 1;
            end

            case (state)
                IDLE: begin
                    if (packet_valid && packet_sop && more_fragments) begin
                        // Start new reassembly for first fragment
                        fragment_src_ip <= src_ip;
                        fragment_dst_ip <= dst_ip;
                        fragment_id <= identification;
                        fragment_protocol <= protocol;
                        expected_length <= total_length;
                        active_reassembly <= 1;
                        fragment_count <= 1;
                        last_update_time <= last_update_time;
                        state <= COLLECTING;
                        // Start accumulating fragment
                        current_frag_ptr <= 0;
                        current_frag_offset <= frag_offset;
                        current_frag_more <= more_fragments;
                        if (frag_offset == 0) begin
                            // Skip IP header for first fragment
                            current_frag_ptr <= 20;
                        end
                    end
                end

                COLLECTING: begin
                    if (packet_valid) begin
                        // Accumulate fragment data
                        if (current_frag_ptr < BUFFER_SIZE) begin
                            current_fragment[current_frag_ptr] <= packet_data;
                            current_frag_ptr <= current_frag_ptr + 1;
                        end

                        if (packet_eop) begin
                            // Fragment complete, check for conflicts and store
                            if (check_overlap_conflict(current_frag_offset * 8, current_frag_ptr)) begin
                                state <= CONFLICT;
                                overlap_conflict <= 1;
                                active_reassembly <= 0;
                                valid_bytes <= 0;
                            end else begin
                                store_fragment(current_frag_offset * 8, current_frag_ptr);
                                fragment_count <= fragment_count + 1;
                                last_update_time <= last_update_time;

                                // Check if this is the last fragment
                                if (!current_frag_more) begin
                                    // Start outputting reassembled packet
                                    state <= OUTPUTTING;
                                    output_ptr <= 0;
                                    outputting <= 1;
                                    reassembled_sop <= 1;
                                end else begin
                                    // Reset for next fragment
                                    current_frag_ptr <= 0;
                                end
                            end
                        end
                    end else if (packet_sop && !packet_valid) begin
                        // New fragment starting
                        current_frag_ptr <= 0;
                        current_frag_offset <= frag_offset;
                        current_frag_more <= more_fragments;
                        if (frag_offset == 0) begin
                            current_frag_ptr <= 20;  // Skip header
                        end
                    end
                end

                OUTPUTTING: begin
                    if (outputting) begin
                        if (output_ptr < expected_length) begin
                            reassembled_valid <= valid_bytes[output_ptr];
                            reassembled_data <= fragment_buffer[output_ptr];
                            output_ptr <= output_ptr + 1;

                            if (output_ptr == expected_length - 1) begin
                                reassembled_eop <= 1;
                                outputting <= 0;
                                active_reassembly <= 0;
                                fragment_count <= 0;
                                valid_bytes <= 0;
                                state <= IDLE;
                            end
                        end
                    end
                end

                CONFLICT: begin
                    // Stay in conflict state briefly, then reset
                    active_reassembly <= 0;
                    valid_bytes <= 0;
                    state <= IDLE;
                end
            endcase
        end
    end

    // Task to store fragment data
    task store_fragment;
        input [15:0] offset;
        input [11:0] frag_size;
        integer i;
        begin
            for (i = 0; i < frag_size; i = i + 1) begin
                if (offset + i < BUFFER_SIZE) begin
                    fragment_buffer[offset + i] <= current_fragment[i];
                    valid_bytes[offset + i] <= 1;
                end
            end
        end
    endtask

    // Function to check for overlap conflicts
    function check_overlap_conflict;
        input [15:0] offset;
        input [11:0] frag_size;
        integer i;
        begin
            check_overlap_conflict = 0;
            for (i = 0; i < frag_size; i = i + 1) begin
                if (offset + i < BUFFER_SIZE && valid_bytes[offset + i]) begin
                    if (fragment_buffer[offset + i] != current_fragment[i]) begin
                        check_overlap_conflict = 1;
                    end
                end
            end
        end
    endfunction

endmodule