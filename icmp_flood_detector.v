// icmp_flood_detector.v - Per-source ICMP packet flood detection and rate limiting
module icmp_flood_detector #(
    parameter TABLE_SIZE = 128,
    parameter ICMP_THRESHOLD = 100,    // Max ICMP packets per source per time window
    parameter TIME_WINDOW = 2000       // Time window in clock cycles
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        packet_valid,
    input  wire        is_icmp,
    input  wire [7:0]  icmp_type,
    input  wire [31:0] src_ip,
    input  wire [31:0] time_counter,
    output reg         icmp_flood_alert,
    output reg [31:0]  blocked_src_ip,
    output reg         dangerous_icmp_type  // Flag for dangerous ICMP types
);

    // Hash function for IP address distribution
    function [7:0] ip_hash;
        input [31:0] ip;
        begin
            ip_hash = ip[7:0] ^ ip[15:8] ^ ip[23:16] ^ ip[31:24];
        end
    endfunction

    // ICMP type classification
    localparam ICMP_ECHO_REQUEST = 8'd8;      // Ping request (most common attack)
    localparam ICMP_ECHO_REPLY = 8'd0;        // Ping reply
    localparam ICMP_UNREACHABLE = 8'd3;       // Destination unreachable
    localparam ICMP_SOURCE_QUENCH = 8'd4;     // Source quench (deprecated)
    localparam ICMP_REDIRECT = 8'd5;          // Redirect (potentially dangerous)
    localparam ICMP_ROUTER_ADV = 8'd9;        // Router advertisement
    localparam ICMP_ROUTER_SOL = 8'd10;       // Router solicitation
    localparam ICMP_TIME_EXCEEDED = 8'd11;    // Time exceeded
    localparam ICMP_TIMESTAMP = 8'd13;        // Timestamp request (potentially dangerous)
    localparam ICMP_TIMESTAMP_REPLY = 8'd14;  // Timestamp reply

    // Tracking table for source IPs
    reg [31:0] ip_table [0:TABLE_SIZE-1];          // Stored source IPs
    reg [31:0] icmp_count [0:TABLE_SIZE-1];        // ICMP packet count per source
    reg [31:0] last_timestamp [0:TABLE_SIZE-1];    // Last update timestamp
    reg valid_entry [0:TABLE_SIZE-1];              // Valid entry flag

    integer i;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            icmp_flood_alert <= 0;
            blocked_src_ip <= 0;
            dangerous_icmp_type <= 0;
            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                ip_table[i] <= 0;
                icmp_count[i] <= 0;
                last_timestamp[i] <= 0;
                valid_entry[i] <= 0;
            end
        end else begin
            // Default: no alert this cycle
            icmp_flood_alert <= 0;
            blocked_src_ip <= 0;
            dangerous_icmp_type <= 0;

            if (packet_valid && is_icmp) begin
                // Check for dangerous ICMP types that should be rate-limited aggressively
                case (icmp_type)
                    ICMP_REDIRECT,
                    ICMP_TIMESTAMP:
                        dangerous_icmp_type <= 1;
                    default:
                        dangerous_icmp_type <= 0;
                endcase

                wire [7:0] hash_idx = ip_hash(src_ip);

                // Check if source IP already in table
                if (valid_entry[hash_idx] && ip_table[hash_idx] == src_ip) begin
                    // Existing source - check time window
                    if (time_counter - last_timestamp[hash_idx] > TIME_WINDOW) begin
                        // Time window expired - reset counter
                        icmp_count[hash_idx] <= 1;
                        last_timestamp[hash_idx] <= time_counter;
                    end else begin
                        // Within time window - increment counter
                        icmp_count[hash_idx] <= icmp_count[hash_idx] + 1;

                        // Lower threshold for dangerous ICMP types
                        wire [31:0] threshold = dangerous_icmp_type ? (ICMP_THRESHOLD / 2) : ICMP_THRESHOLD;

                        if (icmp_count[hash_idx] >= threshold) begin
                            // ICMP flood detected!
                            icmp_flood_alert <= 1;
                            blocked_src_ip <= src_ip;
                        end
                    end
                end else begin
                    // New source IP or hash collision - add to table
                    ip_table[hash_idx] <= src_ip;
                    icmp_count[hash_idx] <= 1;
                    last_timestamp[hash_idx] <= time_counter;
                    valid_entry[hash_idx] <= 1;
                end
            end
        end
    end

endmodule
