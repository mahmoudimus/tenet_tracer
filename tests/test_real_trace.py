#!/usr/bin/env python3
"""
Test the SQLite parser with real trace data from Pin.
"""

import json
import os
import sqlite3
import tempfile

# Real trace data from Pin run
REAL_TRACE = """
rsp=0xdaf4efefd8,rip=0x7ff9339627a0,mr=0x7ff93481aa18:a0279633f97f0000,mw=0xdaf4efefd8:1b5c7b34f97f0000
rsp=0xdaf4efefa0,rip=0x7ff9339627a4
rip=0x7ff9339627a9,mw=0xdaf4efefc0:20867c34f97f0000
rdx=0x7ff9339b1730,rip=0x7ff9339627b0
rip=0x7ff9339627b5,mw=0xdaf4efefc8:0000000000000000
r8=0xdaf4efefc0,rip=0x7ff9339627ba
rsp=0xdaf4efefa0,rip=0x7ff9339627c1,mr=0xdaf4efef98:c1279633f97f0000
rip=0x7ff9339627c6
rcx=0x0,rip=0x7ff9339627c8
rip=0x7ff9339627ca
rcx=0x1,rip=0x7ff9339627cd
rax=0x1,rip=0x7ff9339627cf
rsp=0xdaf4efefd8,rip=0x7ff9339627d3
rsp=0xdaf4efe648,rip=0x7ff9339627a0,mr=0x7ff93481aa18:a0279633f97f0000,mw=0xdaf4efe648:1b5c7b34f97f0000
""".strip()


def parse_trace_line(line):
    """Parse a trace line into structured components."""
    result = {
        'registers': {},
        'pc': None,
        'mem_reads': [],
        'mem_writes': []
    }
    
    parts = line.strip().split(',')
    for part in parts:
        if not part:
            continue
        
        if '=' not in part:
            continue
        
        key, value = part.split('=', 1)
        
        if key in ('rip', 'eip'):
            result['pc'] = value
        elif key == 'mr':
            # Memory read: mr=0xaddr:hexbytes
            if ':' in value:
                addr, data = value.split(':', 1)
                result['mem_reads'].append({'addr': addr, 'data': data})
        elif key == 'mw':
            # Memory write: mw=0xaddr:hexbytes
            if ':' in value:
                addr, data = value.split(':', 1)
                result['mem_writes'].append({'addr': addr, 'data': data})
        else:
            # Regular register
            result['registers'][key] = value
    
    return result


def format_trace_from_structured(parsed):
    """Format structured data back to trace line."""
    parts = []
    
    # Registers (maintain order from original if possible)
    for reg_name, reg_value in parsed['registers'].items():
        parts.append(f"{reg_name}={reg_value}")
    
    # PC
    if parsed['pc']:
        parts.append(f"rip={parsed['pc']}")
    
    # Memory reads
    for mem_op in parsed['mem_reads']:
        parts.append(f"mr={mem_op['addr']}:{mem_op['data']}")
    
    # Memory writes
    for mem_op in parsed['mem_writes']:
        parts.append(f"mw={mem_op['addr']}:{mem_op['data']}")
    
    return ','.join(parts)


def test_real_trace():
    """Test with real Pin trace data."""
    print("Testing Real Pin Trace Data")
    print("=" * 80)
    
    lines = [l.strip() for l in REAL_TRACE.split('\n') if l.strip()]
    
    # Create temp database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create table
        cursor.execute("""
            CREATE TABLE trace_trace (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                tid INTEGER,
                pc INTEGER,
                registers TEXT,
                mem_reads TEXT,
                mem_writes TEXT
            )
        """)
        
        # Insert all entries
        tid = 1234
        timestamp = 1234567890
        
        print(f"\nProcessing {len(lines)} trace entries...\n")
        
        for i, line in enumerate(lines, 1):
            parsed = parse_trace_line(line)
            
            pc_int = 0
            if parsed['pc']:
                pc_int = int(parsed['pc'], 16)
            
            cursor.execute("""
                INSERT INTO trace_trace (timestamp, tid, pc, registers, mem_reads, mem_writes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                timestamp + i,
                tid,
                pc_int,
                json.dumps(parsed['registers']),
                json.dumps(parsed['mem_reads']),
                json.dumps(parsed['mem_writes'])
            ))
        
        conn.commit()
        
        # Verify storage
        cursor.execute("SELECT COUNT(*) FROM trace_trace")
        count = cursor.fetchone()[0]
        print(f"* Stored {count} entries in database\n")
        
        # Show some statistics
        cursor.execute("SELECT COUNT(DISTINCT pc) FROM trace_trace")
        unique_pcs = cursor.fetchone()[0]
        print(f"Statistics:")
        print(f"  Unique PC values: {unique_pcs}")
        
        cursor.execute("SELECT COUNT(*) FROM trace_trace WHERE registers != '{}'")
        with_regs = cursor.fetchone()[0]
        print(f"  Entries with register changes: {with_regs}")
        
        cursor.execute("SELECT COUNT(*) FROM trace_trace WHERE mem_reads != '[]'")
        with_reads = cursor.fetchone()[0]
        print(f"  Entries with memory reads: {with_reads}")
        
        cursor.execute("SELECT COUNT(*) FROM trace_trace WHERE mem_writes != '[]'")
        with_writes = cursor.fetchone()[0]
        print(f"  Entries with memory writes: {with_writes}")
        
        # Test round-trip
        print(f"\n" + "=" * 80)
        print("Testing Round-Trip Conversion:")
        print("=" * 80 + "\n")
        
        all_match = True
        cursor.execute("SELECT * FROM trace_trace ORDER BY id")
        
        for idx, row in enumerate(cursor.fetchall()):
            original_line = lines[idx]
            
            # Reconstruct from DB
            _, timestamp, tid, pc, registers_json, mem_reads_json, mem_writes_json = row
            
            reconstructed_parsed = {
                'registers': json.loads(registers_json),
                'pc': hex(pc) if pc else None,
                'mem_reads': json.loads(mem_reads_json),
                'mem_writes': json.loads(mem_writes_json)
            }
            
            reconstructed_line = format_trace_from_structured(reconstructed_parsed)
            
            # Compare
            if reconstructed_line == original_line:
                status = "*"
            else:
                status = "*"
                all_match = False
            
            print(f"{status} Entry {idx + 1}:")
            print(f"    Original:      {original_line}")
            print(f"    Reconstructed: {reconstructed_line}")
            
            if status == "*":
                # Show what's different
                orig_parsed = parse_trace_line(original_line)
                print(f"    PC match: {orig_parsed['pc'] == reconstructed_parsed['pc']}")
                print(f"    Registers match: {orig_parsed['registers'] == reconstructed_parsed['registers']}")
                print(f"    Mem reads match: {orig_parsed['mem_reads'] == reconstructed_parsed['mem_reads']}")
                print(f"    Mem writes match: {orig_parsed['mem_writes'] == reconstructed_parsed['mem_writes']}")
            print()
        
        # Query examples
        print("=" * 80)
        print("Example Queries:")
        print("=" * 80 + "\n")
        
        # Most common PC
        print("Top 3 most executed PCs:")
        cursor.execute("""
            SELECT printf('0x%016X', pc) as pc_hex, COUNT(*) as cnt 
            FROM trace_trace 
            GROUP BY pc 
            ORDER BY cnt DESC 
            LIMIT 3
        """)
        for pc_hex, cnt in cursor.fetchall():
            print(f"  {pc_hex}: {cnt} times")
        
        # Show one complex entry
        print("\nMost complex entry (most data):")
        cursor.execute("""
            SELECT 
                printf('0x%016X', pc) as pc_hex,
                registers,
                mem_reads,
                mem_writes
            FROM trace_trace
            ORDER BY 
                (LENGTH(registers) + LENGTH(mem_reads) + LENGTH(mem_writes)) DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        if row:
            pc_hex, regs, reads, writes = row
            print(f"  PC: {pc_hex}")
            print(f"  Registers: {regs}")
            print(f"  Mem reads: {reads}")
            print(f"  Mem writes: {writes}")
        
        conn.close()
        
        print("\n" + "=" * 80)
        if all_match:
            print("* SUCCESS: All entries round-trip correctly!")
        else:
            print("*  WARNING: Some entries differ (this may be OK)")
        print("=" * 80)
        
        return all_match
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


if __name__ == '__main__':
    success = test_real_trace()
    exit(0 if success else 1)

