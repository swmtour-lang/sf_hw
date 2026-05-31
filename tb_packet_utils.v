// tb_packet_utils.v - Testbench utilities for 512-bit packet generation
// Simplifies creating and transmitting 512-bit packets for 100G MAC simulation

module packet_packer #(
    parameter MAX_PACKET_SIZE = 1024
) (
    // Inputs: Byte-level packet data (easy to define in tests)
    input [7:0] byte_packets [0:MAX_PACKET_SIZE-1],
    input [11:0] packet_length,     // Packet length in bytes (max 4096)
    
    // Outputs: 512-bit word format
    output reg [511:0] word_512,
    output reg [5:0] valid_bytes,   // Number of valid bytes (1-64)
    output reg word_valid,
    output reg word_sop,            // Start of packet
    output reg word_eop             // End of packet
);

    // Convert byte packet to 512-bit words
    task generate_word;
        input integer word_index;
        input integer total_words;
        begin
            integer byte_offset;
            integer i;
            
            byte_offset = word_index * 64;
            
            // Clear word
            word_512 = 512'b0;
            
            // Determine valid bytes in this word
            if (byte_offset + 64 <= packet_length) begin
                valid_bytes = 6'd64;  // Full word
            end else if (byte_offset < packet_length) begin
                valid_bytes = packet_length - byte_offset;  // Partial word
            end else begin
                valid_bytes = 6'd0;   // No valid bytes
            end
            
            // Pack bytes into 512-bit word (big-endian format)
            // Byte 0 -> bits [511:504], Byte 1 -> bits [503:496], etc.
            for (i = 0; i < 64 && i < valid_bytes; i = i + 1) begin
                word_512[(511 - (i*8)) -: 8] = byte_packets[byte_offset + i];
            end
            
            // Control signals
            word_valid = (valid_bytes > 0);
            word_sop = (word_index == 0);
            word_eop = ((byte_offset + valid_bytes) >= packet_length);
        end
    endtask
    
endmodule


// Example usage in testbench:
/*
    reg [7:0] test_packet [0:127];
    wire [511:0] tx_word;
    wire [5:0] tx_valid_bytes;
    wire tx_valid, tx_sop, tx_eop;
    
    packet_packer packer (
        .byte_packets(test_packet),
        .packet_length(64),
        .word_512(tx_word),
        .valid_bytes(tx_valid_bytes),
        .word_valid(tx_valid),
        .word_sop(tx_sop),
        .word_eop(tx_eop)
    );
    
    // In test sequence:
    for (i = 0; i < num_words; i = i + 1) begin
        packer.generate_word(i, num_words);
        packet_data <= tx_word;
        packet_byte_count <= tx_valid_bytes;
        packet_valid <= tx_valid;
        packet_sop <= tx_sop;
        packet_eop <= tx_eop;
        #10;  // Clock edge
    end
*/
