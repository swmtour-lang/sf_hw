// udp_rate_limiter.v - UDP source rate limiting and per-source connection mitigation
module udp_rate_limiter #(
    parameter TABLE_SIZE = 64,
    parameter UDP_PKT_THRESHOLD = 64,
    parameter TIME_WINDOW = 1024
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        packet_valid,
    input  wire        is_udp,
    input  wire [31:0] src_ip,
    output reg         limit_exceeded,
    output reg [31:0] blocked_ip
);

    // Simple hash for source IP distribution
    wire [5:0] hash_idx = src_ip[5:0] ^ src_ip[13:8] ^ src_ip[21:16] ^ src_ip[29:24];

    reg [31:0] src_ip_mem [0:TABLE_SIZE-1];
    reg [15:0] count_mem [0:TABLE_SIZE-1];
    reg [31:0] last_time [0:TABLE_SIZE-1];
    reg valid_mem [0:TABLE_SIZE-1];
    reg [31:0] global_time;

    integer i;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            global_time <= 0;
            limit_exceeded <= 0;
            blocked_ip <= 0;
            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                src_ip_mem[i] <= 0;
                count_mem[i] <= 0;
                last_time[i] <= 0;
                valid_mem[i] <= 0;
            end
        end else begin
            global_time <= global_time + 1;
            limit_exceeded <= 0;
            blocked_ip <= 0;

            if (packet_valid && is_udp) begin
                if (valid_mem[hash_idx] && src_ip_mem[hash_idx] == src_ip) begin
                    if (global_time - last_time[hash_idx] > TIME_WINDOW) begin
                        count_mem[hash_idx] <= 1;
                        last_time[hash_idx] <= global_time;
                    end else begin
                        count_mem[hash_idx] <= count_mem[hash_idx] + 1;
                    end
                end else begin
                    // Create or refresh source entry on new UDP activity
                    src_ip_mem[hash_idx] <= src_ip;
                    valid_mem[hash_idx] <= 1;
                    count_mem[hash_idx] <= 1;
                    last_time[hash_idx] <= global_time;
                end

                if (count_mem[hash_idx] > UDP_PKT_THRESHOLD) begin
                    limit_exceeded <= 1;
                    blocked_ip <= src_ip;
                end
            end
        end
    end

endmodule
