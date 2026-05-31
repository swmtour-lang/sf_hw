# 512-bit Firewall Integration for 100G Ethernet MAC

## Overview
The firewall has been redesigned to accept 512-bit (64-byte) input directly from a 100G Ethernet MAC, enabling parallel packet header processing and minimal latency.

## Architecture Changes

### 1. Main Firewall Module (`firewall.v`)

#### Port Changes
```verilog
// OLD: 8-bit byte-serial input
input [7:0] packet_data

// NEW: 512-bit parallel input
input [511:0] packet_data        // 512-bit data from 100G Ethernet MAC  
input [5:0] packet_byte_count   // Number of valid bytes (1-64)
```

#### Benefits
- Processes 64 bytes per clock cycle (vs. 1 byte in legacy design)
- Packet header extraction can complete in 1-2 cycles
- Significant reduction in processing latency
- Better throughput for 100G line rate

#### Data Flow
```
100G Ethernet MAC
       ↓
   [512-bit data]
       ↓
   firewall.v (top module)
       ├─→ packet_parser (512-bit parallel)
       ├─→ fragment_reassembler (512-bit input)
       ├─→ Detector modules
       ├─→ Rule checker
       └─→ State table
```

### 2. Packet Parser (`packet_parser.v`) - Complete Redesign

#### Key Improvements
- **Combinational header extraction**: All packet fields extracted in parallel from 512-bit input
- **Single-cycle parsing**: TCP/UDP/ICMP headers parsed in one clock cycle
- **Helper functions**: Byte and word extraction from arbitrary offsets

#### Extraction Logic
```verilog
// Ethernet header (bytes 0-13)
eth_dest, eth_src, eth_type

// IP header (bytes 14-33)
ip_version, ip_header_len, ip_total_len, ip_ident
ip_src, ip_dst, ip_proto, ip_checksum
ip_flags, ip_frag_offset, ip_more_fragments

// TCP header (bytes 34-53 for standard IP)
tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack_num
tcp_flags (SYN, ACK, FIN, RST, PSH, URG)
tcp_window, tcp_checksum, tcp_urgent_ptr

// UDP header (bytes 34-41)
udp_src_port, udp_dst_port, udp_length, udp_checksum

// ICMP header (bytes 34-41)
icmp_type, icmp_code, icmp_checksum
icmp_id, icmp_sequence
```

#### Performance
- Latency: 1 cycle (vs. ~54 cycles for 8-bit byte serial)
- Throughput: 512 bits/cycle = 51.2 Gbps capacity

### 3. Fragment Reassembler (`fragment_reassembler.v`)

#### Changes
- Updated interface to accept 512-bit input
- Added `packet_byte_count` signal for variable word sizes
- Internal byte-stream deserializer extracts bytes from 512-bit words
- Maintains compatibility with existing reassembly logic

#### Note
The reassembler maintains byte-level processing internally while accepting 512-bit input words. A future optimization would parallelize fragment buffer insertion.

### 4. Timing and Clock Cycles

#### Packet Processing Pipeline

**Minimum latency for TCP packet (complete in one cycle)**
```
Cycle 1:
├─ Ethernet header: bytes 0-13
├─ IP header: bytes 14-33  
├─ TCP header: bytes 34-53
├─ Extract: src_ip, dst_ip, ports, flags, sequence
└─ Output: Valid packet data to state table

Cycle 2:
├─ State table lookup/update
├─ Attack detection
└─ Decision: Allow/Block
```

### 5. Compatibility Notes

#### Legacy Interfaces
- Detector modules (SYN flood, RST injection, etc.) operate unchanged
- State table operates unchanged
- Rule checker operates unchanged

#### What Changed
- Only firewall.v port and internal data paths
- Only packet_parser.v (complete rewrite for parallelism)
- Fragment reassembler interface updated (internal logic adapts)

### 6. Integration with 100G Ethernet MAC

#### Expected Input Format
```
100G Ethernet MAC Output (per 100G DataSheet)
├─ packet_data[511:0]     // 512-bit data (64 bytes)
├─ packet_byte_count[5:0] // 1-64 valid bytes in this cycle
├─ packet_valid           // Data valid signal
├─ packet_sop            // Start of packet
├─ packet_eop            // End of packet
└─ clk                    // Typically 322 MHz or 406 MHz for 100G
```

#### Connection Example
```verilog
// From 100G Ethernet MAC to firewall
firewall inst_fw (
    .clk(mac_clk),
    .rst(mac_rst),
    .packet_data(mac_tx_data[511:0]),
    .packet_byte_count(mac_tx_valid_bytes[5:0]),
    .packet_valid(mac_tx_valid),
    .packet_sop(mac_tx_sop),
    .packet_eop(mac_tx_eop),
    // ... other signals
);
```

## Implementation Details

### Byte Extraction Macro (packet_parser.v)

```verilog
// Extract byte at index N from 512-bit data
// Assumption: Ethernet frames use big-endian ordering
// Byte 0 is at bits [511:504], Byte 1 at [503:496], etc.

function [7:0] get_byte(input [511:0] data, input [5:0] byte_idx);
    get_byte = data[(511 - (byte_idx << 3)) -: 8];
endfunction

// Usage:
eth_type = get_byte(data, 12)     // EtherType high byte
protocol = get_byte(data, 23)     // IP protocol field
```

### Packet Type Identification

The parser identify packets in a single cycle:

```verilog
wire is_ipv4 = (ip_version == 4'h4);
wire is_valid_eth_frame = (byte_count >= 6'd14);
wire is_valid_ip_header = is_ipv4 && is_valid_eth_frame && (eth_type == 16'h0800);
wire is_tcp = (ip_proto == 8'h06) && is_valid_ip_header;
wire is_udp = (ip_proto == 8'h11) && is_valid_ip_header;
wire is_icmp = (ip_proto == 8'h01) && is_valid_ip_header;
```

## Testing Considerations

### New Testbenches Needed
1. Verify 512-bit packet parsing correctness
2. Test variable packet_byte_count (1-64 bytes)
3. Test packet boundaries within 512-bit words
4. Verify compatibility with detector modules

### Regression Testing
- Existing attack detection logic should work unchanged
- State machine behavior preserved
- Output signals unchanged

## Future Optimizations

1. **Fragment Buffer Parallel Insert**: Parallelize fragment insertion into buffer
2. **Pipelined Processing**: Add pipeline stage for throughput
3. **Multiple Packet Processing**: Process multiple small packets per cycle
4. **Checksum Offloading**: Implement hardware checksum validation

## Performance Metrics

| Metric | 8-bit (Old) | 512-bit (New) | Improvement |
|--------|------------|--------------|-------------|
| Parse Latency | ~54 cycles | 1-2 cycles | 27-54x faster |
| Throughput (bits/cycle) | 8 | 512 | 64x higher |
| Hardware packets/sec | Low | High | ~6.4M @ 100G |
| Packet header latency | 54 cycles | 1 cycle | 54x |

## Glossary

- **MAC**: Ethernet Media Access Control
- **100G**: 100 Gigabit Ethernet
- **SOP**: Start of Packet
- **EOP**: End of Packet  
- **TCP**: Transmission Control Protocol
- **UDP**: User Datagram Protocol
- **ICMP**: Internet Control Message Protocol
