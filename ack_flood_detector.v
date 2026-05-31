// ack_flood_detector.v - Per-session ACK flood detection and rate limiting
module ack_flood_detector #(
    parameter TABLE_SIZE = 256,
    parameter ACK_THRESHOLD = 32,
    parameter TIME_WINDOW = 256
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        packet_valid,
    input  wire        is_tcp,
    input  wire        ack_only,
    input  wire        state_valid,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] src_port,
    input  wire [15:0] dst_port,
    input  wire [31:0] time_counter,
    output reg         ack_flood_alert,
    output reg [31:0]  blocked_src_ip
);

    // Simple hash function using source/destination tuple bits
    wire [7:0] hash = src_ip[7:0] ^ dst_ip[15:8] ^ src_port[7:0] ^ dst_port[15:8] ^ src_ip[23:16];
    wire [95:0] conn_key = {src_ip, dst_ip, src_port, dst_port};

    reg [95:0] key_mem [0:TABLE_SIZE-1];
    reg valid_mem [0:TABLE_SIZE-1];
    reg [15:0] count_mem [0:TABLE_SIZE-1];
    reg [31:0] last_time [0:TABLE_SIZE-1];

    integer i;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            ack_flood_alert <= 0;
            blocked_src_ip <= 0;
            for (i = 0; i < TABLE_SIZE; i = i + 1) begin
                key_mem[i] <= 0;
                valid_mem[i] <= 1'b0;
                count_mem[i] <= 0;
                last_time[i] <= 0;
            end
        end else begin
            ack_flood_alert <= 0;
            blocked_src_ip <= 0;

            if (packet_valid && is_tcp && ack_only && state_valid) begin
                if (valid_mem[hash] && key_mem[hash] == conn_key) begin
                    if (time_counter - last_time[hash] > TIME_WINDOW) begin
                        count_mem[hash] <= 1;
                        last_time[hash] <= time_counter;
                    end else begin
                        count_mem[hash] <= count_mem[hash] + 1;
                    end
                end else begin
                    valid_mem[hash] <= 1'b1;
                    key_mem[hash] <= conn_key;
                    count_mem[hash] <= 1;
                    last_time[hash] <= time_counter;
                end

                if (count_mem[hash] >= ACK_THRESHOLD) begin
                    ack_flood_alert <= 1;
                    blocked_src_ip <= src_ip;
                end
            end
        end
    end

endmodule
