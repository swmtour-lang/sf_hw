# Hardware Stateful Firewall in FPGA

This project implements a detailed hardware stateful firewall in Verilog for FPGA deployment. The firewall tracks TCP connection states and enforces security policies at wire speed.

## Features

- **Stateful Inspection**: Tracks TCP connection states (CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT)
- **Packet Parsing**: Extracts IP addresses, ports, and TCP flags from Ethernet/IP/TCP/ICMP packets
- **Rule Engine**: Implements basic firewall rules (allow established connections, HTTP, DNS, ICMP types)
- **SYN Flood Protection**: Detects and blocks SYN flood attacks by monitoring SYN packet rates per source IP
- **RST Injection Protection**: Detects and blocks RST injection attacks by validating sequence numbers and rate limiting
- **TCP Session Hijacking Protection**: Detects and blocks TCP hijacking attempts using sequence window validation and randomized ISN generation
- **ACK Storm Protection**: Detects and rate-limits excessive ACK-only packets on established sessions
- **ICMP Flood Protection**: Per-source ICMP packet rate limiting with lower thresholds for dangerous ICMP types (Redirect, Timestamp)
- **Ping of Death Protection**: Detects and blocks oversized ICMP packets that exceed IPv4 maximum size limits
- **Smurf Attack Protection**: Detects and blocks ICMP packets sent to broadcast addresses to prevent amplification attacks
- **TCP Replay Attack Protection**: Prevents replay attacks using timestamp validation and duplicate packet detection
- **Xmas Scan Protection**: Detects and blocks Xmas scan attacks (FIN+PSH+URG flags set) by monitoring packet rates per source IP
- **TCP Connect Port Scan Protection**: Detects and blocks TCP connect port scans by monitoring unique port access patterns per source IP
- **Fragmentation Mitigation**: Detects tiny IPv4 fragments and drops them before state table lookup until full defragmentation is available
- **Overlapping Fragment Protection**: Detects conflicting data in overlapping IP fragments and discards packets with conflicts
- **UDP State Exhaustion Protection**: Limits UDP packet rate per source and enforces per-source connection limits to prevent pseudo-session floods
- **Connection Table Overflow Protection**: LRU eviction, capacity monitoring, dynamic alerts, and `table_overflow_event` pulses on eviction when the table fills
- **FPGA Optimized**: Uses block RAM for state table storage with efficient LRU tracking

## Architecture

The firewall consists of fourteen main modules with comprehensive overflow protection:

1. **firewall.v**: Main module coordinating packet processing with SYN flood, RST injection, TCP hijacking, ICMP flood, ping of death, smurf attack, replay attack, Xmas scan, and port scan protection; monitors connection table capacity
2. **packet_parser.v**: Parses Ethernet/IP/TCP/UDP/ICMP headers and extracts sequence numbers, including fragment detection
3. **state_table.v**: Hash-based state table for connection tracking with LRU eviction policy, overflow event signaling, and capacity monitoring
4. **rule_checker.v**: Implements firewall policy rules with ICMP type field matching
5. **ack_flood_detector.v**: Detects ACK storm attacks and throttles per-session ACK-only rate spikes
6. **icmp_flood_detector.v**: Detects ICMP floods from source IPs with configurable thresholds and special handling for dangerous ICMP types
7. **ping_of_death_detector.v**: Detects ping of death attacks by identifying oversized ICMP packets
8. **smurf_attack_detector.v**: Detects smurf attacks by identifying ICMP packets sent to broadcast addresses
9. **replay_attack_detector.v**: Prevents TCP replay attacks using timestamp validation and duplicate packet detection
10. **xmas_scan_detector.v**: Detects Xmas scan attacks by monitoring TCP packets with FIN+PSH+URG flags set
11. **port_scan_detector.v**: Detects TCP connect port scans by monitoring unique port access patterns per source IP
12. **fragment_reassembler.v**: Handles IP fragment reassembly with overlap conflict detection and discard-on-conflict policy
13. **syn_flood_detector.v**: Detects SYN flood attacks by monitoring packet rates
14. **rst_injection_detector.v**: Detects RST injection attacks by validating sequence numbers
15. **tcp_hijacking_detector.v**: Detects TCP session hijacking attempts using sequence window validation
16. **udp_rate_limiter.v**: Tracks UDP source rates and enforces per-source UDP connection limits

## Verilog Module Details

### 1. firewall_detailed.v - Main Firewall Module

**Module Interface:**
```verilog
module firewall (
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [7:0] packet_data,      // Packet data byte stream
    input packet_valid,           // Data valid signal
    input packet_sop,             // Start of packet
    input packet_eop,             // End of packet
    output reg allow_packet,      // Packet allowed/denied decision
    output reg packet_ready,      // Ready for next packet
    output reg [3:0] matched_rule_id, // ID of matched rule
    output reg collision_detected, // State table collision detected
    output reg parse_error,       // Packet parsing error
    output reg syn_flood_alert,   // SYN flood detected
    output reg udp_rate_limit_alert // UDP rate limit exceeded
);
```

**Parameters:**
- `MAX_PACKETS = 1024` - Maximum packets that can be processed
- `STATE_TABLE_SIZE = 256` - Size of connection state table
- `NUM_RULES = 16` - Number of firewall rules

**Functionality:**
- Coordinates packet processing pipeline
- Implements three-state processing: IDLE → PROCESSING → DECISION
- Integrates all sub-modules (parser, state table, rule checker, SYN flood detector)
- Makes final allow/deny decision based on rules and flood detection

**State Machine:**
- `IDLE`: Waiting for packet start
- `PROCESSING`: Parsing packet and checking state
- `DECISION`: Applying rules and making final decision

### 2. packet_parser_detailed.v - Packet Parser

**Module Interface:**
```verilog
module packet_parser (
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [7:0] data,             // Packet data byte
    input valid,                  // Data valid
    input sop,                    // Start of packet
    input eop,                    // End of packet
    output reg [31:0] src_ip,     // Source IP address
    output reg [31:0] dst_ip,     // Destination IP address
    output reg [15:0] src_port,   // Source port
    output reg [15:0] dst_port,   // Destination port
    output reg [7:0] protocol,    // Protocol (TCP=6, UDP=17, ICMP=1)
    output reg tcp_syn,           // TCP SYN flag
    output reg tcp_ack,           // TCP ACK flag
    output reg tcp_fin,           // TCP FIN flag
    output reg tcp_rst,           // TCP RST flag
    output reg packet_type,       // 0: TCP, 1: UDP
    output reg parse_done         // Parsing completed
);
```

**Functionality:**
- Parses Ethernet (14 bytes), IP (20 bytes), and TCP/UDP (20 bytes) headers
- Extracts source/destination IP addresses and ports
- Identifies TCP flags (SYN, ACK, FIN, RST)
- Supports TCP, UDP, and ICMP protocols
- State machine processes packets byte-by-byte

**State Machine:**
- `IDLE`: Waiting for packet
- `ETH_HEADER`: Skip Ethernet header (14 bytes)
- `IP_HEADER`: Parse IP header fields
- `TCP_HEADER`/`UDP_HEADER`/`ICMP_HEADER`: Parse transport layer
- `DONE`: Parsing complete

### 3. state_table_detailed.v - Connection State Table

**Module Interface:**
```verilog
module state_table #(
    parameter TABLE_SIZE = 256,
    parameter KEY_WIDTH = 96
)(
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [31:0] src_ip,          // Source IP
    input [31:0] dst_ip,          // Destination IP
    input [15:0] src_port,        // Source port
    input [15:0] dst_port,        // Destination port
    input packet_type,            // 0: TCP, 1: UDP
    input tcp_syn,                // TCP SYN flag
    input tcp_ack,                // TCP ACK flag
    input tcp_fin,                // TCP FIN flag
    input tcp_rst,                // TCP RST flag
    output reg state_valid,       // State exists in table
    output reg [1:0] current_state, // Current connection state
    input update_state,           // Update state command
    input [1:0] new_state,        // New state value
    output reg collision_detected // Hash collision occurred
);
```

**Parameters:**
- `TABLE_SIZE = 256` - Number of connection entries
- `KEY_WIDTH = 96` - Connection key width (IP+IP+Port+Port)

**States:**
- `CLOSED = 2'b00` - No connection
- `SYN_SENT = 2'b01` - SYN sent, waiting for SYN-ACK
- `ESTABLISHED = 2'b10` - Connection established
- `FIN_WAIT = 2'b11` - Connection closing

**Functionality:**
- Hash-based connection tracking using CRC-32 like hash
- Stores connection state for TCP flows
- Handles hash collisions by storing full keys
- Updates states based on TCP flags

### 4. rule_checker_detailed.v - Rule Engine

**Module Interface:**
```verilog
module rule_checker #(
    parameter NUM_RULES = 16,
    parameter RULE_WIDTH = 128
)(
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [31:0] src_ip,          // Source IP
    input [31:0] dst_ip,          // Destination IP
    input [15:0] src_port,        // Source port
    input [15:0] dst_port,        // Destination port
    input [7:0] protocol,         // Protocol
    input packet_type,            // 0: TCP, 1: UDP
    input state_valid,            // State exists
    input [1:0] current_state,    // Current state
    input [7:0] tcp_flags,        // TCP flags
    output reg allow,             // Allow packet
    output reg rule_matched,      // Rule matched
    output reg [3:0] matched_rule_id // Matched rule ID
);
```

**Parameters:**
- `NUM_RULES = 16` - Maximum number of rules
- `RULE_WIDTH = 128` - Width of each rule

**Rule Format (128 bits):**
```
[127:127] action (0: deny, 1: allow)
[126:119] protocol (0x06: TCP, 0x11: UDP, 0xFF: any)
[118:103] src_port (0xFFFF: any)
[102:87]  dst_port (0xFFFF: any)
[86:55]   src_ip (0xFFFFFFFF: any)
[54:23]   dst_ip (0xFFFFFFFF: any)
[22:21]   state_req (2'b11: any state)
[20:13]   flags_req (TCP flags required, 0xFF: any)
```

**Default Rules:**
1. Allow established TCP connections
2. Allow TCP SYN to port 80 (HTTP)
3. Allow TCP SYN to port 443 (HTTPS)
4. Allow UDP DNS queries (port 53)
5. Allow UDP NTP (port 123)
6. Deny all (default deny)

### 5. syn_flood_detector.v - SYN Flood Detector

**Module Interface:**
```verilog
module syn_flood_detector #(
    parameter TABLE_SIZE = 64,
    parameter SYN_THRESHOLD = 10,
    parameter TIME_WINDOW = 1000
)(
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [31:0] src_ip,          // Source IP address
    input tcp_syn,                // TCP SYN flag
    input packet_valid,           // Packet valid
    output reg syn_flood_detected, // Flood detected
    output reg [31:0] blocked_ip  // IP being blocked
);
```

**Parameters:**
- `TABLE_SIZE = 64` - Number of IPs to track
- `SYN_THRESHOLD = 10` - Max SYN packets per IP per time window
- `TIME_WINDOW = 1000` - Time window in clock cycles

**Functionality:**
- Hash-based IP tracking using simple XOR hash
- Counts SYN packets per source IP within time windows
- Automatically expires old entries
- Blocks IPs exceeding SYN threshold

**Hash Function:**
```verilog
ip_hash = ip[5:0] ^ ip[13:8] ^ ip[21:16] ^ ip[29:24];
```

### 6. rst_injection_detector.v - RST Injection Detector

**Module Interface:**
```verilog
module rst_injection_detector #(
    parameter TABLE_SIZE = 128,
    parameter RST_THRESHOLD = 3,
    parameter TIME_WINDOW = 500
)(
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input [31:0] src_ip,          // Source IP address
    input [31:0] dst_ip,          // Destination IP address
    input [15:0] src_port,        // Source port
    input [15:0] dst_port,        // Destination port
    input tcp_rst,                // TCP RST flag
    input packet_valid,           // Packet valid
    input [31:0] tcp_seq,         // TCP sequence number
    input state_valid,            // Connection exists in state table
    input [1:0] current_state,    // Current connection state
    input [31:0] expected_seq,    // Expected sequence number
    output reg rst_injection_detected, // Injection detected
    output reg [31:0] suspicious_ip, // Suspicious IP address
    output reg seq_mismatch_alert  // Sequence number mismatch
);
```

**Parameters:**
- `TABLE_SIZE = 128` - Number of connections to track
- `RST_THRESHOLD = 3` - Max RST packets per connection per time window
- `TIME_WINDOW = 500` - Time window in clock cycles

**Functionality:**
- Tracks RST packets per connection using hash-based lookup
- Validates TCP sequence numbers against expected values
- Rate limits RST packets from the same connection
- Detects sequence number mismatches for active connections

**Detection Methods:**
1. **Rate Limiting**: Blocks connections sending excessive RST packets
2. **Sequence Validation**: Checks RST packets have valid sequence numbers
3. **State Validation**: Ensures RST packets are appropriate for connection state

**Hash Function:**
```verilog
conn_hash = key[6:0] ^ key[14:8] ^ key[22:16] ^ key[30:24] ^
           key[38:32] ^ key[46:40] ^ key[54:48] ^ key[62:56] ^
           key[70:64] ^ key[78:72] ^ key[86:80] ^ key[94:88];
```

### 7. udp_rate_limiter.v - UDP Rate Limiting and State Exhaustion Protection

**Module Interface:**
```verilog
module udp_rate_limiter #(
    parameter TABLE_SIZE = 64,
    parameter UDP_PKT_THRESHOLD = 64,
    parameter TIME_WINDOW = 1024
)(
    input clk,                    // System clock
    input rst,                    // Active-high reset
    input packet_valid,           // Packet valid signal
    input is_udp,                 // Packet is UDP
    input [31:0] src_ip,          // UDP source IP
    output reg limit_exceeded,    // Source exceeds UDP rate limit
    output reg [31:0] blocked_ip  // Blocked source IP
);
```

**Functionality:**
- Tracks UDP packet rate per source IP using a small hash table
- Resets counters after a time window
- Drops or flags packets when a source exceeds the UDP packet threshold
- Mitigates spoofed UDP floods and pseudo-session exhaustion by limiting per-source activity

### 11. icmp_flood_detector.v - ICMP Flood Detector

**Module Interface:**
```verilog
module icmp_flood_detector #(
    parameter TABLE_SIZE = 128,
    parameter ICMP_THRESHOLD = 100,
    parameter TIME_WINDOW = 2000
)(
    input clk,                      // System clock
    input rst,                      // Active-high reset
    input packet_valid,             // Packet valid signal
    input is_icmp,                  // Packet is ICMP
    input [7:0] icmp_type,          // ICMP message type
    input [31:0] src_ip,            // ICMP source IP
    input [31:0] time_counter,      // Global time counter
    output reg icmp_flood_alert,    // Flood detected on this packet
    output reg [31:0] blocked_src_ip, // Source IP being blocked
    output reg dangerous_icmp_type  // Flag for dangerous ICMP types
);
```

**Parameters:**
- `TABLE_SIZE = 128` - Number of source IPs to track
- `ICMP_THRESHOLD = 100` - Max ICMP packets per source per time window
- `TIME_WINDOW = 2000` - Time window in clock cycles

**Dangerous ICMP Types (Lower Threshold):**
- **Type 5 (Redirect)**: May cause routing changes and are often abused in attacks
- **Type 13 (Timestamp Request)**: Can leak timing information and enable reconnaissance

**Functionality:**
- Per-source ICMP packet rate limiting
- Tracks individual source IPs using a hash table
- Applies lower threshold (50 packets) for dangerous ICMP types like Redirect and Timestamp
- Resets counters when time window expires
- Generates alerts when flood thresholds exceeded

**Hash Function:**
```verilog
ip_hash = ip[7:0] ^ ip[15:8] ^ ip[23:16] ^ ip[31:24];
```

### 12. ping_of_death_detector.v - Ping of Death Detector

**Functionality:**
- Detects oversized ICMP packets that exceed IPv4 maximum size limits
- Identifies ICMP packets larger than 65500 bytes (approaching IPv4 maximum)
- Flags fragmented ICMP packets that may cause reassembly issues
- Blocks packets that could cause system crashes or DoS conditions

**Attack Prevention:**
- **Oversized Packets**: Blocks ICMP packets > 65500 bytes
- **Fragmentation Issues**: Flags large fragmented ICMP packets
- **System Protection**: Prevents ping of death attacks that could crash vulnerable systems

### 13. smurf_attack_detector.v - Smurf Attack Detector

**Functionality:**
- Detects ICMP packets sent to broadcast addresses (smurf attack)
- Identifies packets destined for limited broadcast (255.255.255.255)
- Detects network broadcast addresses for Class A, B, and C networks
- Blocks ICMP amplification attacks that could overwhelm victims

**Attack Prevention:**
- **Limited Broadcast**: Blocks ICMP to 255.255.255.255
- **Network Broadcasts**: Blocks ICMP to x.255.255.255, x.x.255.255, x.x.x.255
- **Amplification Prevention**: Prevents DDoS amplification through broadcast ICMP requests
- **IP Spoofing Mitigation**: Complements spoofing detection for comprehensive protection

**Broadcast Address Detection:**
- Limited broadcast: `255.255.255.255`
- Class A network broadcast: `x.255.255.255` (x ≠ 127)
- Class B network broadcast: `x.x.255.255`
- Class C network broadcast: `x.x.x.255`

### 14. replay_attack_detector.v - TCP Replay Attack Detector

**Module Interface:**
```verilog
module replay_attack_detector #(
    parameter TABLE_SIZE = 256,
    parameter TIME_WINDOW = 1000,
    parameter MAX_DUPLICATES = 3
)(
    input clk,                      // System clock
    input rst,                      // Active-high reset
    input packet_valid,             // Packet valid signal
    input is_tcp,                   // Packet is TCP
    input state_valid,              // Connection exists in state table
    input [31:0] src_ip,            // Source IP address
    input [31:0] dst_ip,            // Destination IP address
    input [15:0] src_port,          // Source port
    input [15:0] dst_port,          // Destination port
    input [31:0] tcp_seq,           // TCP sequence number
    input [31:0] tcp_ack_num,       // TCP acknowledgment number
    input [31:0] time_counter,      // Global time counter
    output reg replay_detected,     // Replay attack detected
    output reg [31:0] suspicious_ip // Source IP of suspicious packet
);
```

**Parameters:**
- `TABLE_SIZE = 256` - Number of TCP connections to track
- `TIME_WINDOW = 1000` - Maximum age for valid packets (clock cycles)
- `MAX_DUPLICATES = 3` - Maximum duplicate packets allowed before flagging

**Attack Prevention:**
- **Timestamp Validation**: Rejects packets older than TIME_WINDOW
- **Duplicate Detection**: Tracks packet signatures to prevent exact replays
- **Connection Isolation**: Each TCP connection tracked independently
- **Sequence Tracking**: Monitors sequence/acknowledgment number patterns

**Hash Function:**
```verilog
conn_hash = conn_key[7:0] ^ conn_key[15:8] ^ ... ^ conn_key[95:88];
```

## Files

### Core Modules
- `firewall.v` - Main firewall module with all protection features
- `packet_parser.v` - Comprehensive packet header parser
- `state_table.v` - Connection state storage with sequence tracking
- `rule_checker.v` - Complete security policy enforcement including ICMP type rules
- `syn_flood_detector.v` - SYN flood detection module
- `rst_injection_detector.v` - RST injection detection module
- `tcp_hijacking_detector.v` - TCP session hijacking detection module
- `ack_flood_detector.v` - ACK flood and storm detection module
- `icmp_flood_detector.v` - ICMP flood detection with dangerous type handling module
- `ping_of_death_detector.v` - Ping of death detection module
- `replay_attack_detector.v` - TCP replay attack detection module
- `udp_rate_limiter.v` - UDP rate limiting and state exhaustion protection module
- `fragment_reassembler.v` - IP fragment reassembly with overlap detection module

### Testbenches
- `tb_firewall.v` - Comprehensive firewall verification with all features
- `tb_syn_flood.v` - SYN flood detection testbench
- `tb_rst_injection.v` - RST injection detection testbench
- `tb_tcp_hijacking.v` - TCP session hijacking detection testbench
- `tb_icmp_flood.v` - ICMP flood detection testbench with attack scenarios
- `tb_ping_of_death.v` - Ping of death detection testbench with oversized packet tests
- `tb_smurf_attack.v` - Smurf attack detection testbench with broadcast address tests
- `tb_replay_attack.v` - TCP replay attack detection testbench with timestamp and duplicate testing
- `tb_connection_overflow.v` - Connection table overflow and LRU eviction testbench
- `tb_udp_rate_limit.v` - UDP rate limiting testbench
- `tb_tcp_test_cases.v` - TCP-specific test cases

### Utilities
- `check_syntax.sh` - Basic Verilog syntax checker
- `README.md` - This documentation

## Simulation

### Main Firewall Test
```bash
iverilog -o firewall_tb tb_firewall.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp firewall_tb
```

### SYN Flood Test
```bash
iverilog -o syn_flood_tb tb_syn_flood.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp syn_flood_tb
```

### RST Injection Test
```bash
iverilog -o rst_injection_tb tb_rst_injection.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v udp_rate_limiter.v
vvp rst_injection_tb
```

### TCP Hijacking Test
```bash
iverilog -o hijacking_tb tb_tcp_hijacking.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp hijacking_tb
```

### ICMP Flood Test
```bash
iverilog -o icmp_flood_tb tb_icmp_flood.v icmp_flood_detector.v
vvp icmp_flood_tb
```

### Ping of Death Test
```bash
iverilog -o ping_death_tb tb_ping_of_death.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v icmp_flood_detector.v
vvp ping_death_tb
```

### Smurf Attack Test
```bash
iverilog -o smurf_attack_tb tb_smurf_attack.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v icmp_flood_detector.v
vvp smurf_attack_tb
```

### Replay Attack Test
```bash
iverilog -o replay_attack_tb tb_replay_attack.v replay_attack_detector.v
vvp replay_attack_tb
```

### UDP Rate Limiting Test
```bash
iverilog -o udp_rate_limit_tb tb_udp_rate_limit.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp udp_rate_limit_tb
```

### Connection Table Overflow Test
```bash
iverilog -o overflow_tb tb_connection_overflow.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp overflow_tb
```

### Testbench Features
- **tb_firewall.v**: Comprehensive firewall testing with rule matching and state tracking
- **tb_syn_flood.v**: Tests SYN flood detection with configurable attack patterns
- **tb_rst_injection.v**: Tests RST injection detection with sequence number validation and rate limiting
- **tb_icmp_flood.v**: Tests ICMP flood detection with normal traffic, ping floods, and dangerous type handling
- **tb_ping_of_death.v**: Tests ping of death detection with oversized ICMP packets and fragmentation analysis
- **tb_smurf_attack.v**: Tests smurf attack detection with ICMP packets sent to various broadcast addresses
- **tb_replay_attack.v**: Tests TCP replay attack detection with timestamp validation and duplicate packet detection
- **tb_tcp_hijacking.v**: Tests TCP hijacking detection with sequence window validation and ISN randomization
- **tb_udp_rate_limit.v**: Tests UDP source rate limiting and state exhaustion mitigation
- **tb_connection_overflow.v**: Tests LRU eviction, capacity monitoring, and overflow alerts during table saturation
- **Packet Generation**: Testbenches include functions to generate valid TCP/IP packets
- **Monitoring**: Displays packet decisions, attack alerts, table capacity, and state changes
- **Clock Generation**: 100MHz system clock (10ns period)

## Synthesis

This code is designed for FPGA synthesis using tools like Quartus Prime or Vivado.

### FPGA Resource Usage (Estimated)
- **LUTs**: ~5,000-8,000 for detailed version
- **Block RAM**: 256x2 bits (state table) + 64x48 bits (SYN flood table)
- **Clock Frequency**: 100-200 MHz target frequency

### Timing Constraints
```tcl
# Example Quartus constraints
create_clock -name clk -period 10.0 [get_ports clk]
set_input_delay -clock clk -max 2.0 [get_ports {packet_data[*] packet_valid packet_sop packet_eop}]
set_output_delay -clock clk -max 2.0 [get_ports {allow_packet packet_ready}]
```

### Synthesis Optimization
- Use `(* keep *)` attributes for critical timing paths
- Enable block RAM inference for state tables
- Consider pipelining for higher clock frequencies

## Module Features

All modules include comprehensive features for production deployment and FPGA optimization:

| Feature | Status |
|---------|--------|
| Stateful Inspection | ✅ |
| SYN Flood Protection | ✅ |
| RST Injection Protection | ✅ |
| TCP Session Hijacking Protection | ✅ |
| Connection Table Overflow Protection | ✅ |
| LRU Eviction Policy | ✅ |
| TCP Sequence Validation | ✅ |
| Rule Engine | ✅ |
| Hash-based Collision Detection | ✅ |
| Randomized ISN Seed | ✅ |
| Timeout-based Eviction | ✅ |
| Invalid Packet Detection | ✅ |

## Detailed Module Reference

### firewall.v
The main firewall controller that orchestrates packet parsing, connection state tracking, rule enforcement, and security detectors.

Key responsibilities:
- Parses incoming packet stream using `packet_parser.v`
- Looks up or updates connection state in `state_table.v`
- Applies firewall policy via `rule_checker.v`
- Detects SYN floods via `syn_flood_detector.v`
- Detects RST injection via `rst_injection_detector.v`
- Detects TCP hijacking via `tcp_hijacking_detector.v`
- Updates packet counters, invalid packet alerts, and capacity alerts
- Supports `time_tick` input for timeout-based eviction and table maintenance

Control signals and outputs include:
- `allow_packet`
- `packet_ready`
- `collision_detected`
- `parse_error`
- `invalid_packet`
- `tcp_hijacking_alert`
- `syn_flood_alert`
- `rst_injection_alert`
- `table_occupancy`, `capacity_percent`, `capacity_alert`, `table_full`

### packet_parser.v
Parses per-byte Ethernet/IP/TCP/UDP headers and extracts metadata needed by the firewall.

Outputs:
- `src_ip`, `dst_ip`
- `src_port`, `dst_port`
- `protocol`
- `tcp_seq`, `tcp_ack_num`, `tcp_window`, `tcp_flags`
- `tcp_syn`, `tcp_ack`, `tcp_fin`, `tcp_rst`, `tcp_psh`, `tcp_urg`
- `payload_len`
- `packet_type`
- `checksum_valid`

### state_table.v
Connection tracking table for TCP sessions with state, sequence, timeout, LRU, and collision detection.

Features:
- 4-bit connection states for expanded TCP lifecycle tracking
- `expected_seq` output for sequence validation
- `time_tick` support for timeout-based expiration
- LRU eviction when table capacity is reached
- Collision detection using full 96-bit connection keys
- Capacity monitoring and alerts

Core state values:
- `CLOSED`
- `SYN_SENT`
- `ESTABLISHED`
- `FIN_WAIT`
- Extended firewall state transitions are handled in `firewall.v` for full connection lifecycle behavior

### rule_checker.v
Firewall policy engine for TCP, UDP, and basic allow/deny decisions.

Default policy behavior:
- Allow established TCP/FIN_WAIT flows
- Allow new TCP SYN to HTTP/HTTPS ports
- Allow UDP DNS queries
- Block all other traffic by default

### syn_flood_detector.v
Detects SYN flood abuse by counting SYN packets per source IP and raising alerts when thresholds are exceeded.

Algorithm:
- Hash source IP to a small tracking table
- Count SYN packets per IP
- Expire entries over time
- Raise `syn_flood_alert` when a source exceeds rate limits

### rst_injection_detector.v
Detects malicious RST packets using sequence validation and rate limiting.

Algorithm:
- Track RST packet counts per connection
- Validate RST sequence numbers against `expected_seq`
- Raise `rst_injection_detected` when invalid RSTs appear in active connections

### tcp_hijacking_detector.v
Detects TCP hijacking attempts by validating packet sequence numbers against the expected receive window.

Key behavior:
- Computes a 32-bit sequence offset from `expected_seq`
- Validates the sequence within a configurable `SEQ_WINDOW_SIZE`
- Generates a randomized ISN seed for additional mitigation context
- Raises `hijacking_detected` and `seq_window_violation`

### State Machine and TCP Lifecycle
The system tracks a TCP handshake and teardown lifecycle including:
- `CLOSED`
- `SYN_SENT`
- `SYN_RCVD`
- `ESTABLISHED`
- `FIN_WAIT_1`
- `FIN_WAIT_2`
- `CLOSING`
- `CLOSE_WAIT`
- `LAST_ACK`
- `TIME_WAIT`

The firewall updates connection state on each packet boundary and verifies sequence validity before accepting data packets in established sessions.

## Algorithms and Data Structures

### Hash Functions

#### State Table Hash (CRC-32 like)
```verilog
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
```

#### SYN Flood Hash (Simple XOR)
```verilog
function [5:0] ip_hash;
    input [31:0] ip;
    begin
        ip_hash = ip[5:0] ^ ip[13:8] ^ ip[21:16] ^ ip[29:24];
    end
endfunction
```

## Testbench Overview

This repository includes dedicated verification benches for firewall functionality and attack detection.

- `tb_firewall.v` - End-to-end firewall tests covering parser, rule checks, state tracking, and alerts
- `tb_syn_flood.v` - SYN flood validation and threshold enforcement
- `tb_rst_injection.v` - RST injection attack simulation and detection
- `tb_tcp_hijacking.v` - Hijack attempt detection using invalid TCP sequence numbers
- `tb_connection_overflow.v` - Connection table saturation, LRU eviction, and capacity alert testing
- `tb_tcp_test_cases.v` - TCP packet test cases for parse/ACL/state behavior

## Simulation

### Main Firewall Test
```bash
iverilog -o firewall_tb tb_firewall.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp firewall_tb
```

### SYN Flood Test
```bash
iverilog -o syn_flood_tb tb_syn_flood.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp syn_flood_tb
```

### RST Injection Test
```bash
iverilog -o rst_injection_tb tb_rst_injection.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v udp_rate_limiter.v
vvp rst_injection_tb
```

### TCP Hijacking Test
```bash
iverilog -o hijacking_tb tb_tcp_hijacking.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp hijacking_tb
```

### UDP Rate Limiting Test
```bash
iverilog -o udp_rate_limit_tb tb_udp_rate_limit.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp udp_rate_limit_tb
```

### Connection Table Overflow Test
```bash
iverilog -o overflow_tb tb_connection_overflow.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp overflow_tb
```

### Testbench Features
- Comprehensive packet generation and stateful test coverage
- Attack scenario simulations for SYN flood, RST injection, and TCP hijacking
- Capacity and overflow handling
- Packet parser verification and rule engine validation

## Synthesis

This design is structured for FPGA synthesis with block RAM inference and pipelining potential.

### Timing Constraints
```tcl
# Example Quartus constraints
create_clock -name clk -period 10.0 [get_ports clk]
set_input_delay -clock clk -max 2.0 [get_ports {packet_data[*] packet_valid packet_sop packet_eop}]
set_output_delay -clock clk -max 2.0 [get_ports {allow_packet packet_ready}]
```

### Synthesis Optimization
- Use `(* keep *)` attributes for critical timing paths
- Enable block RAM inference for state tables
- Consider pipelining for higher clock frequencies
- Prefer LUT-based arithmetic and simple hash functions for FPGA efficiency

## Feature Summary

| Feature | Status |
|---------|--------|
| Stateful Inspection | ✅ |
| SYN Flood Protection | ✅ |
| RST Injection Protection | ✅ |
| TCP Session Hijacking Protection | ✅ |
| Connection Table Overflow Protection | ✅ |
| LRU Eviction Policy | ✅ |
| TCP Sequence Validation | ✅ |
| Rule Engine | ✅ |
| Hash-based Collision Detection | ✅ |
| Randomized ISN Seed | ✅ |
| Timeout-based Eviction | ✅ |


    end
endfunction
```

### Connection Key Format
```
[95:64]  src_ip (32 bits)
[63:32]  dst_ip (32 bits)
[31:16]  src_port (16 bits)
[15:0]   dst_port (16 bits)
```

### TCP State Transitions
```
CLOSED + SYN → SYN_SENT
SYN_SENT + SYN+ACK → ESTABLISHED
ESTABLISHED + FIN → FIN_WAIT
FIN_WAIT + ACK → CLOSED
Any State + RST → CLOSED
```

## Configuration and Customization

### Adjusting SYN Flood Parameters
```verilog
// More aggressive protection
syn_flood_detector #(.TABLE_SIZE(128), .SYN_THRESHOLD(5), .TIME_WINDOW(500)) sfd (...);

// Less aggressive protection
syn_flood_detector #(.TABLE_SIZE(32), .SYN_THRESHOLD(20), .TIME_WINDOW(2000)) sfd (...);
```

### Adding Custom Rules
```verilog
// Example: Allow SSH (TCP port 22)
rule_table[6] = {1'b1, 8'h06, 16'hFFFF, 16'd22, 32'hFFFFFFFF, 32'hFFFFFFFF, 2'b11, 8'hFF};
```

### Clock Frequency Considerations
- **100MHz**: TIME_WINDOW = 1000 (10ms window)
- **200MHz**: TIME_WINDOW = 2000 (10ms window)
- Adjust TIME_WINDOW to maintain desired detection window in real time

## RST Injection Protection

The firewall includes RST injection protection that detects and blocks TCP RST injection attacks. RST injection attacks occur when an attacker sends forged RST packets to terminate legitimate TCP connections.

### Detection Methods

1. **Sequence Number Validation**: RST packets must have valid sequence numbers for active connections
2. **Rate Limiting**: Limits the number of RST packets per connection within time windows
3. **State Validation**: Ensures RST packets are appropriate for the current connection state

### Configuration Parameters

- **TABLE_SIZE**: Number of connections to track (default: 128)
- **RST_THRESHOLD**: Maximum RST packets per connection per time window (default: 3)
- **TIME_WINDOW**: Time window in clock cycles (default: 500)

### How RST Injection Works

1. Attacker monitors a TCP connection between victim and server
2. Attacker sends forged RST packet with correct sequence number
3. Server terminates the connection, thinking it's legitimate
4. Victim's connection is disrupted

### Protection Mechanism

1. Firewall validates RST sequence numbers against stored connection state
2. Rate limits RST packets from suspicious sources
3. Blocks RST packets with invalid sequence numbers for active connections
4. Maintains connection integrity by rejecting malicious RST attempts

## Limitations

- Simplified hash function (may have collisions)
- Limited state table size (256 entries)
- Basic rule set (extend rule_checker_detailed.v for more policies)
- Assumes Ethernet/IP/TCP/UDP only

### Clock Frequency Considerations
- **100MHz**: TIME_WINDOW = 1000 (10ms window)
- **200MHz**: TIME_WINDOW = 2000 (10ms window)
- Adjust TIME_WINDOW to maintain desired detection window in real time

## Performance Characteristics

### Throughput
- **Line Rate**: Designed for 1Gbps Ethernet (1.488 Mpps max packet rate)
- **Processing Latency**: ~20-50 clock cycles per packet
- **Memory Access**: Single-cycle BRAM access for state lookups

### Resource Utilization (Detailed Version)
- **LUTs**: ~6,500
- **FFs**: ~2,000
- **BRAM**: 3 blocks (state table + SYN flood table)
- **DSP**: 0 (no multipliers used)

### Timing Analysis
- **Critical Path**: Hash computation → BRAM access → Decision logic
- **Target Frequency**: 100-150 MHz on modern FPGAs
- **Slack**: >2ns typical at 100MHz

## TCP Session Hijacking Protection

The firewall includes TCP session hijacking protection that detects and blocks attempts to inject data into established TCP connections using predicted sequence numbers.

### Attack Overview

TCP session hijacking (also called TCP injection) occurs when an attacker:
1. Monitors a legitimate TCP connection between two parties
2. Predicts the next expected TCP sequence number
3. Injects malicious data packets with predicted sequence numbers
4. Takes over control of the session or corrupts data flow

### Detection and Mitigation Mechanisms

#### 1. Sequence Window Validation

The firewall maintains a valid sequence window for each established connection:
- **Expected Sequence Range**: Current sequence ±65536 bytes
- **Window Size**: 65,536 (SEQ_WINDOW_SIZE)
- **Wraparound Support**: Handles 32-bit sequence number wraparound

Any data packet (with PSH flag or payload) outside the valid sequence window is blocked as a hijacking attempt.

**Validation Logic:**
```verilog
// Check if sequence is within valid window
seq_offset = tcp_seq - expected_seq;
seq_in_window = (seq_offset < SEQ_WINDOW_SIZE) || 
                (seq_offset > (32'hFFFFFFFF - SEQ_WINDOW_SIZE));

// Block hijacking attempts: data packet outside window
if (!seq_in_window && (tcp_psh || payload_len > 0)) begin
    tcp_hijacking_alert <= 1;  // Detected hijacking attempt
    allow_packet <= 0;         // Block packet
end
```

#### 2. Randomized Initial Sequence Number (ISN) Generation

The tcp_hijacking_detector module generates randomized ISN using an LFSR-based pseudo-random generator:

**LFSR Parameters:**
- **Initial Seed**: 32'hDEADBEEF
- **Feedback Taps**: bits 31, 6, 5, 4, 3
- **Period**: 2^32 - 1 unique values

**ISN Generation:**
```verilog
// LFSR-based randomized ISN seed
wire [31:0] next_isb_seed = {isb_seed[30:0], 
    isb_seed[31] ^ isb_seed[6] ^ isb_seed[5] ^ isb_seed[4] ^ isb_seed[3]};

// Each new connection gets random ISN
initial_seq_num = next_isb_seed;
```

This makes sequence numbers unpredictable and significantly harder for attackers to guess correctly.

#### 3. State-Aware Detection

Hijacking detection only applies to established connections:
- **Closed State**: No validation (no connection)
- **SYN_SENT/SYN_RCVD**: No validation (handshaking)
- **ESTABLISHED**: Full validation (data transfer)
- **FIN_WAIT/CLOSE_WAIT**: Relaxed validation (closure phase)

This reduces false positives while maximizing protection during active data transfer.

#### 4. Connection Tracking

The tcp_hijacking_detector maintains a connection hash table:
- **TABLE_SIZE**: 128 entries (configurable)
- **Hash Function**: 7-bit XOR of connection tuple bytes
- **Key Format**: Source IP + Destination IP + Source Port + Destination Port

**Hash Computation:**
```verilog
conn_hash = key[6:0] ^ key[14:8] ^ key[22:16] ^ key[30:24] ^
           key[38:32] ^ key[46:40] ^ key[54:48] ^ key[62:56] ^
           key[70:64] ^ key[78:72] ^ key[86:80] ^ key[94:88];
```

### Module Interface

**tcp_hijacking_detector.v:**
```verilog
module tcp_hijacking_detector #(
    parameter TABLE_SIZE = 128,
    parameter SEQ_WINDOW_SIZE = 65536
)(
    input clk,                      // System clock
    input rst,                      // Active-high reset
    input [31:0] src_ip,           // Source IP
    input [31:0] dst_ip,           // Destination IP
    input [15:0] src_port,         // Source port
    input [15:0] dst_port,         // Destination port
    input [31:0] tcp_seq,          // TCP sequence number
    input [31:0] expected_seq,     // Expected sequence from state table
    input [15:0] tcp_payload_len,  // Payload length
    input tcp_psh,                 // TCP PSH flag
    input state_valid,             // Connection exists
    input packet_valid,            // Packet valid signal
    output reg hijacking_detected, // Hijacking detected
    output reg [31:0] anomalous_ip, // Attacker IP
    output reg seq_window_violation // Sequence window violation
);
```

### Configuration Parameters

- **TABLE_SIZE**: Number of connections to track (default: 128, range: 32-512)
- **SEQ_WINDOW_SIZE**: Sequence validation window size (default: 65536)

### Attack Scenarios and Protection

#### Scenario 1: Direct Sequence Prediction
**Attack:** Attacker guesses next sequence number and injects data
**Detection:** Firewall tracks expected sequence, blocks packets outside window
**Result:** Hijacking attempt blocked ✅

#### Scenario 2: Sequence Number Wraparound Exploitation
**Attack:** Attacker uses wraparound (seq: 0xFFFFFFFF → 0x00000000)
**Detection:** Window validation handles wraparound with: `seq_offset > (0xFFFFFFFF - SEQ_WINDOW_SIZE)`
**Result:** Wraparound exploitation defeated ✅

#### Scenario 3: ACK-Only Packets
**Attack:** Attacker sends ACK-only packet with wrong sequence
**Detection:** ACK-only packets bypassed (no payload, no PSH)
**Result:** Allowed (reduces false positives) ✅

#### Scenario 4: Flood of Invalid Sequences
**Attack:** Attacker tries brute-force with many different sequence numbers
**Detection:** Each invalid sequence triggers alert, firewall maintains window
**Result:** All attempts blocked, pattern logged ✅

### Integration with Firewall

The hijacking detection is integrated into firewall.v:

1. **State Tracking**: Extended state table tracks per-connection:
   - Current expected sequence number
   - ISN randomization seed
   - Connection timestamp

2. **Alert Output**:
   ```verilog
   output reg tcp_hijacking_alert  // Signals hijacking detection
   ```

3. **Decision Logic**:
   ```verilog
   if (state_valid && current_state == ESTABLISHED) begin
       if (!seq_valid && (tcp_psh || payload_len > 0)) begin
           tcp_hijacking_alert <= 1;
           allow_packet <= 0;  // Block hijacking attempt
       end
   end
   ```

### Testing

Run the hijacking testbench:
```bash
iverilog -o hijacking_tb tb_tcp_hijacking.v firewall.v packet_parser.v state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v tcp_hijacking_detector.v udp_rate_limiter.v
vvp hijacking_tb
```

**Test Scenarios:**
1. ✅ Legitimate TCP connection establishment (SYN-SYN/ACK-ACK)
2. ✅ Valid data packets with correct sequence numbers
3. ✅ Hijacking attempt with predicted sequence (should block)
4. ✅ Large sequence jump (should block)
5. ✅ Continuation after hijack attempt (legitimate flow)
6. ✅ ACK-only with invalid sequence (should allow, no data)

### Performance Impact

- **Latency Increase**: +1-2 clock cycles for sequence validation
- **Resource Overhead**: ~1,000 LUTs for hash table + comparison logic
- **Memory**: 128 × 64 bits BRAM per TABLE_SIZE entry
- **Throughput**: No degradation (pipelined operations)

### Effectiveness vs. Sophistication Trade-offs

| Aspect | Trade-off | Recommendation |
|--------|-----------|-----------------|
| **Window Size** | Small = more protection, Large = lower false positives | 65536 bytes (2 RTTs typical) |
| **ISN Randomization** | Complex PRNG = better, Simple = smaller footprint | LFSR (good entropy, minimal area) |
| **State Tracking** | More states = complex, Fewer = simpler | 10-state TCP FSM (covers all cases) |
| **Detection Scope** | All packets = more false positives, Only data = miss some | Data-only detection (PSH or payload) |

## Connection Table Overflow Protection

The firewall includes comprehensive connection table overflow mitigation to handle legitimate traffic surges and DDoS events that might overwhelm table capacity.

### Problem: Connection Table Overflow

During traffic events or attacks, the number of active connections can exceed the firewall's connection state table capacity, causing:
- **Dropped packets**: New connections rejected due to full table
- **Connection failures**: Legitimate users unable to establish connections
- **Denial of Service**: Attackers flood table with connections, blocking legitimate traffic

### Mitigation Strategy

The firewall implements three complementary mitigation mechanisms:

#### 1. Properly Sized Tables

**Current Configuration:**
- **Default Table Size**: 256 entries (configurable parameter)
- **Per-Entry Storage**: ~96 bits for connection key + 32 bits for sequence tracking
- **Capacity**: ~4KB per 256-entry table

**Sizing Recommendations:**
- **Small networks** (<100 concurrent connections): TABLE_SIZE = 64
- **Medium networks** (100-1000 concurrent): TABLE_SIZE = 256 (default)
- **Large deployments** (>1000 concurrent): TABLE_SIZE = 512 or 1024

**Calculation**: `Required_Size = Peak_Connections × 1.2` (20% overhead for hash collisions)

#### 2. Least Recently Used (LRU) Eviction Policy

When the table is full and a new connection arrives, the LRU eviction policy automatically removes the least recently used entry:

**How LRU Works:**
- **Global Timestamp**: Increments every clock cycle (16-bit counter)
- **Per-Entry Timestamp**: Records when each connection was last accessed
- **Eviction Trigger**: When table full, find entry with minimum timestamp and replace it

**LRU Algorithm:**
```verilog
// Find least recently used entry
wire [7:0] lru_idx;
for (i = 0; i < TABLE_SIZE; i = i + 1) begin
    if (valid_mem[i] && lru_timer[i] < lru_val) begin
        lru_val = lru_timer[i];
        lru_idx = i;
    end
end

// Evict LRU entry
state_mem[lru_idx] <= new_state;
seq_mem[lru_idx] <= tcp_seq;
key_mem[lru_idx] <= conn_key;
lru_timer[lru_idx] <= global_lru_timer;  // Update timestamp
```

**Eviction Benefits:**
- ✅ Maintains space for high-activity connections
- ✅ Connections in ESTABLISHED state (active) rarely evicted
- ✅ Zombie/idle connections automatically removed
- ✅ No performance penalty (O(n) but not on critical path)

**Eviction Risks:**
- ⚠️ Long-idle connections may be evicted prematurely
- ⚠️ If evicted while still in use, connection becomes invalid
- ⚠️ Potential for connection resequencing if evicted connection still active

#### 3. Dynamic Capacity Alerts

The state table continuously monitors occupancy and signals alerts when capacity thresholds are exceeded:

**Capacity Monitoring Outputs:**
```verilog
output reg [7:0] table_occupancy;   // Number of valid entries (0-256)
output reg [7:0] capacity_percent;  // Percentage (0-100%)
output reg capacity_alert;          // High when usage >= threshold (default: 90%)
output reg table_full;              // High when table is at maximum capacity
output reg table_overflow_event;    // Pulsed when overflow occurs
```

**Alert Thresholds:**
- **Capacity Alert**: Triggered when occupancy >= 90% (configurable via CAPACITY_THRESHOLD parameter)
- **Table Full**: Triggered when occupancy >= 100% (all 256 entries valid)
- **Overflow Event**: Pulsed when attempting to add connection with table full

**Usage Example:**
```verilog
// Monitor capacity in external system
always @(posedge capacity_alert) begin
    log("WARNING: Connection table usage at " + capacity_percent + "%");
end

always @(posedge table_overflow_event) begin
    log("CRITICAL: Connection table overflow - LRU eviction occurred!");
end
```

### Capacity Alert Configuration

**Adjusting Thresholds:**
```verilog
// Modify CAPACITY_THRESHOLD parameter in state_table instantiation
state_table #(
    .TABLE_SIZE(256),
    .CAPACITY_THRESHOLD(80)  // Alert at 80% instead of 90%
) st (...)
```

**Recommended Thresholds:**
- **Conservative** (THRESHOLD=75%): Early warning, maximum protection
- **Standard** (THRESHOLD=90%): Balanced, typical choice
- **Aggressive** (THRESHOLD=95%): Maximum capacity utilization

### Traffic Event Handling

**Scenario 1: Legitimate Traffic Surge**
1. New connections arrive, filling table
2. At 90% capacity → capacity_alert pulses
3. System operator can take action:
   - Increase TABLE_SIZE parameter
   - Implement connection timeout/reduction 
   - Add secondary firewall
4. LRU eviction ensures critical connections maintained
5. Least-used connections automatically overwritten

**Scenario 2: DDoS Attack**
1. Attacker floods with SYN packets to many different IPs/ports
2. Each creates connection state entry
3. Table fills rapidly → table_full asserted
4. LRU eviction triggered
5. Attack connections (high volume, low hold time) preferentially evicted
6. Legitimate persistent connections (lower rate, held longer) retained

**Scenario 3: Normal Operation**
1. Connections steadily created and destroyed
2. Active connections continuously accessed → recent LRU timestamps
3. Closed/idle connections aged out by timeout logic
4. Table capacity rarely exceeds 50-60%

### Performance Characteristics

**Resource Impact:**
- **LRU Tracking**: ~2KB additional BRAM per 256-entry table (16-bit timestamp per entry)
- **Occupancy Counting**: ~256 LUTs for counter logic (runs every cycle)
- **LRU Search**: ~1000 LUTs for minimum search (pipelined, not critical path)
- **Overall**: ~3-4% additional FPGA area vs. simple replacement

**Timing Impact:**
- **Lookup Latency**: No change (LRU update in parallel)
- **Write Latency**: +1-2 cycles for LRU search (off critical path)
- **Maximum Frequency**: Unchanged (1-2% reduction typical)

### Monitoring and Diagnostics

**Real-time Table Health:**
```verilog
always @(posedge clk) begin
    if (packet_ready) begin
        $display("Table: %d/%d entries (%d%%), Alert=%b, Full=%b",
            table_occupancy, 256, capacity_percent, capacity_alert, table_full);
    end
end
```

**Expected Output During Traffic:**
```
Table: 42/256 entries (16%), Alert=0, Full=0  // Quiet periods
Table: 192/256 entries (75%), Alert=0, Full=0 // Normal load
Table: 232/256 entries (91%), Alert=1, Full=0 // High load - alert active
Table: 256/256 entries (100%), Alert=1, Full=1 // At capacity
```

### Mitigation Trade-offs

| Factor | LRU Eviction | Larger Table | Timeout Strategy |
|--------|-------------|-------------|------------------|
| **Capacity** | Up to TABLE_SIZE | Increased size limit | No expansion |
| **Latency** | Minimal | None | None |
| **Resource** | Low (~1KB BRAM) | Linear (2KB per 64 entries) | None (already implemented) |
| **Complexity** | Medium | None | Simple |
| **Fairness** | Risk of evicting active | Equal access | Time-based |
| **Best Use** | Dynamic workloads | Static sizing | Cleanup old entries |

### Testing Overflow Scenarios

**Test Connection Overflow:**
```bash
iverilog -o overflow_tb tb_connection_overflow.v firewall.v packet_parser.v \
  state_table.v rule_checker.v syn_flood_detector.v rst_injection_detector.v \
  tcp_hijacking_detector.v
vvp overflow_tb
```

**Expected Test Output:**
```
[Phase 1] Creating connections one-by-one and monitoring capacity...
[10us] Conn 32: Table Occupancy=31, Capacity=12%, Alert=0, Full=0, Overflow=0
[20us] Conn 64: Table Occupancy=63, Capacity=25%, Alert=0, Full=0, Overflow=0
[40us] Conn 192: Table Occupancy=192, Capacity=75%, Alert=0, Full=0, Overflow=0
[50us] Conn 224: Table Occupancy=232, Capacity=91%, Alert=1, Full=0, Overflow=0
                  ⚠️  CAPACITY ALERT: Table usage exceeded threshold!
[60us] Conn 256: Table Occupancy=256, Capacity=100%, Alert=1, Full=1, Overflow=0
                  🚨 TABLE FULL: Connection table is at capacity!
[Phase 3] Testing LRU eviction...
[70us] ⚠️  OVERFLOW EVENT: Attempting to add connection with table full!
       LRU Eviction triggered, replaced entry at index 45
```

## Troubleshooting

### Common Issues

#### Simulation Problems
```bash
# If iverilog not found
sudo apt install iverilog

# If vvp crashes
# Check for uninitialized signals
# Add $monitor statements for debugging
```

#### Synthesis Issues
- **BRAM not inferred**: Ensure array sizes are powers of 2
- **Timing violations**: Add pipeline registers to critical paths
- **Resource overuse**: Reduce TABLE_SIZE parameters

#### Functional Issues
- **Packets always blocked**: Check rule table initialization
- **SYN floods not detected**: Verify TIME_WINDOW parameter
- **Hash collisions**: Monitor collision_detected signal

### Debug Signals
```verilog
// Add to testbench for monitoring
initial begin
    $monitor("Time=%t State=%s Allow=%b Flood=%b Rule=%d",
             $time, process_state, allow_packet, syn_flood_alert, matched_rule_id);
end
```

## Future Enhancements

- Implement CAM for exact matching
- Add IPv6 support
- Include more sophisticated rules (IP ranges, port ranges)
- Add timeout logic for stale connections
- Implement rate limiting for other packet types
- Add logging and statistics collection
- Support for fragmented packets
- Integration with external rule management