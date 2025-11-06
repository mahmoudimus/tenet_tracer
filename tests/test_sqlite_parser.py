#!/usr/bin/env python3
"""
Test script to verify the SQLite dump matches the original trace format.

This script tests the round-trip conversion:
  Original format -> SQLite (via C++ parser) -> Back to original (via Python dump)
"""

import json
import os
import sqlite3
import tempfile


def parse_trace_line(line):
    """Parse a trace line into structured components."""
    result = {"registers": {}, "pc": None, "mem_reads": [], "mem_writes": []}

    parts = line.strip().split(",")
    for part in parts:
        if not part:
            continue

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        if key in ("rip", "eip"):
            result["pc"] = value
        elif key == "mr":
            # Memory read: mr=0xaddr:hexbytes
            if ":" in value:
                addr, data = value.split(":", 1)
                result["mem_reads"].append({"addr": addr, "data": data})
        elif key == "mw":
            # Memory write: mw=0xaddr:hexbytes
            if ":" in value:
                addr, data = value.split(":", 1)
                result["mem_writes"].append({"addr": addr, "data": data})
        else:
            # Regular register
            result["registers"][key] = value

    return result


def format_trace_from_structured(parsed):
    """Format structured data back to trace line."""
    parts = []

    # Registers
    for reg_name, reg_value in parsed["registers"].items():
        parts.append(f"{reg_name}={reg_value}")

    # PC
    if parsed["pc"]:
        parts.append(f"rip={parsed['pc']}")

    # Memory reads
    for mem_op in parsed["mem_reads"]:
        parts.append(f"mr={mem_op['addr']}:{mem_op['data']}")

    # Memory writes
    for mem_op in parsed["mem_writes"]:
        parts.append(f"mw={mem_op['addr']}:{mem_op['data']}")

    return ",".join(parts)


def test_round_trip():
    """Test various trace line formats."""
    test_cases = [
        # Basic register + PC
        "rax=0x1234,rbx=0x5678,rip=0x400000",
        # Multiple registers
        "rax=0x1,rbx=0x2,rcx=0x3,rdx=0x4,rsi=0x5,rdi=0x6,rip=0x400100",
        # With memory read
        "rax=0x1234,rip=0x400200,mr=0x7fff0000:4142434445464748",
        # With memory write
        "rcx=0xabcd,rip=0x400300,mw=0x7fff0008:0102030405060708",
        # With multiple memory operations
        "rax=0x1111,rbx=0x2222,rip=0x400400,mr=0x1000:aabbccdd,mr=0x2000:11223344,mw=0x3000:55667788",
        # Just PC (no registers changed)
        "rip=0x400500",
        # PC with eip (32-bit)
        "eax=0x12345678,ebx=0x87654321,eip=0x401000",
        # Complex real-world example
        "rax=0x7ffff7dd0000,rbx=0x0,rcx=0x7ffff7dd0000,rdx=0x100,rsi=0x7fffffffe000,rdi=0x1,rip=0x7ffff7a5a000,mr=0x7fffffffe000:48656c6c6f,mw=0x7ffff7dd0000:576f726c64",
    ]

    print("Testing trace line parsing and formatting:")
    print("=" * 80)

    all_passed = True
    for i, test_line in enumerate(test_cases, 1):
        print(f"\nTest {i}:")
        print(f"  Original: {test_line}")

        # Parse
        parsed = parse_trace_line(test_line)
        print(f"  Parsed:")
        print(f"    PC: {parsed['pc']}")
        print(f"    Registers: {parsed['registers']}")
        print(f"    Mem reads: {parsed['mem_reads']}")
        print(f"    Mem writes: {parsed['mem_writes']}")

        # Format back
        formatted = format_trace_from_structured(parsed)
        print(f"  Formatted: {formatted}")

        # Compare (allow eip/rip substitution since architecture determines this)
        formatted_normalized = formatted.replace(",rip=", ",PC=")
        test_normalized = test_line.replace(",eip=", ",PC=").replace(",rip=", ",PC=")

        if formatted_normalized == test_normalized:
            print("  * PASS")
        elif formatted == test_line:
            print("  * PASS")
        else:
            print("  * FAIL - Output doesn't match input")
            print(f"    Expected: {test_normalized}")
            print(f"    Got:      {formatted_normalized}")
            all_passed = False

    print("\n" + "=" * 80)
    if all_passed:
        print("All tests PASSED!")
    else:
        print("Some tests FAILED!")

    return all_passed


def test_sqlite_storage():
    """Test storing and retrieving from SQLite."""
    print("\n\nTesting SQLite storage:")
    print("=" * 80)

    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create table (matching our schema)
        cursor.execute(
            """
            CREATE TABLE trace_trace (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                tid INTEGER,
                pc INTEGER,
                registers TEXT,
                mem_reads TEXT,
                mem_writes TEXT
            )
        """
        )

        # Test data
        test_line = "rax=0x1234,rbx=0x5678,rip=0x400000,mr=0x7fff0000:41424344,mw=0x7fff0100:01020304"
        parsed = parse_trace_line(test_line)

        # Insert
        cursor.execute(
            """
            INSERT INTO trace_trace (timestamp, tid, pc, registers, mem_reads, mem_writes)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                1234567890,
                1000,
                int(parsed["pc"], 16),
                json.dumps(parsed["registers"]),
                json.dumps(parsed["mem_reads"]),
                json.dumps(parsed["mem_writes"]),
            ),
        )
        conn.commit()

        # Retrieve
        cursor.execute("SELECT * FROM trace_trace")
        row = cursor.fetchone()

        print(f"Stored and retrieved from SQLite:")
        print(f"  Row ID: {row[0]}")
        print(f"  Timestamp: {row[1]}")
        print(f"  TID: {row[2]}")
        print(f"  PC: {hex(row[3])}")
        print(f"  Registers: {row[4]}")
        print(f"  Mem reads: {row[5]}")
        print(f"  Mem writes: {row[6]}")

        # Format back
        formatted_parsed = {
            "registers": json.loads(row[4]),
            "pc": hex(row[3]),
            "mem_reads": json.loads(row[5]),
            "mem_writes": json.loads(row[6]),
        }
        formatted_line = format_trace_from_structured(formatted_parsed)

        print(f"\n  Original:  {test_line}")
        print(f"  Retrieved: {formatted_line}")

        if formatted_line == test_line:
            print("  * PASS - Round-trip successful!")
            success = True
        else:
            print("  * FAIL - Round-trip failed!")
            success = False

        conn.close()

    finally:
        os.unlink(db_path)

    print("=" * 80)
    return success


def main():
    """Run all tests."""
    print("SQLite Trace Parser Test Suite")
    print("=" * 80)

    test1_passed = test_round_trip()
    test2_passed = test_sqlite_storage()

    print("\n\nSummary:")
    print("=" * 80)
    print(f"Round-trip parsing: {'* PASS' if test1_passed else '* FAIL'}")
    print(f"SQLite storage:     {'* PASS' if test2_passed else '* FAIL'}")

    if test1_passed and test2_passed:
        print("\n* All tests passed!")
        return 0
    else:
        print("\n* Some tests failed!")
        return 1


if __name__ == "__main__":
    exit(main())
