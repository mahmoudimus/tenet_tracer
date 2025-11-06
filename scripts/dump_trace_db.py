#!/usr/bin/env python3
"""
Dump SQLite trace database back to raw text format.

Usage:
    python dump_trace_db.py <database.db> [--table TABLE_NAME] [--tid TID] [--output OUTPUT_FILE]
"""

import argparse
import json
import sqlite3
import sys
from typing import Optional, TextIO


def format_trace_entry(row: tuple) -> str:
    """
    Convert a database row back to the original trace format.

    Row format: (id, timestamp, tid, pc, registers, mem_reads, mem_writes)
    Output format: reg=0xval,reg=0xval,rip=0xval,mr=0xaddr:bytes,mw=0xaddr:bytes
    """
    _, timestamp, tid, pc, registers_json, mem_reads_json, mem_writes_json = row

    parts = []

    # Parse and format registers
    try:
        registers = json.loads(registers_json)
        for reg_name, reg_value in registers.items():
            parts.append(f"{reg_name}={reg_value}")
    except (json.JSONDecodeError, AttributeError):
        pass

    # Add PC
    if pc:
        parts.append(f"rip={hex(pc)}")

    # Parse and format memory reads
    try:
        mem_reads = json.loads(mem_reads_json)
        for mem_op in mem_reads:
            addr = mem_op.get("addr", "0x0")
            data = mem_op.get("data", "")
            parts.append(f"mr={addr}:{data}")
    except (json.JSONDecodeError, AttributeError):
        pass

    # Parse and format memory writes
    try:
        mem_writes = json.loads(mem_writes_json)
        for mem_op in mem_writes:
            addr = mem_op.get("addr", "0x0")
            data = mem_op.get("data", "")
            parts.append(f"mw={addr}:{data}")
    except (json.JSONDecodeError, AttributeError):
        pass

    return ",".join(parts)


def dump_trace_table(
    db_path: str,
    table_name: str = "trace",
    tid: Optional[int] = None,
    output_file: Optional[str] = None,
):
    """
    Dump trace entries from database to text format.

    Args:
        db_path: Path to SQLite database
        table_name: Base table name (without _trace suffix)
        tid: Optional thread ID to filter by
        output_file: Optional output file path (default: stdout)
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Determine which table to query
    if tid is not None:
        full_table_name = f"{table_name}_trace_{tid}"
    else:
        full_table_name = f"{table_name}_trace"

    # Check if table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (full_table_name,),
    )
    if not cursor.fetchone():
        print(
            f"Error: Table '{full_table_name}' not found in database", file=sys.stderr
        )
        print(f"Available tables:", file=sys.stderr)
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        for (tbl_name,) in cursor.fetchall():
            print(f"  - {tbl_name}", file=sys.stderr)
        conn.close()
        return

    # Build query
    query = f"SELECT * FROM {full_table_name} ORDER BY timestamp, id"

    cursor.execute(query)

    # Open output file or use stdout
    out_file: TextIO
    if output_file:
        out_file = open(output_file, "w")
    else:
        out_file = sys.stdout

    try:
        row_count = 0
        for row in cursor:
            trace_line = format_trace_entry(row)
            out_file.write(trace_line + "\n")
            row_count += 1

        if output_file:
            print(f"Dumped {row_count} trace entries to {output_file}", file=sys.stderr)
        else:
            print(f"# Dumped {row_count} trace entries", file=sys.stderr)
    finally:
        if output_file:
            out_file.close()

    conn.close()


def list_tables(db_path: str):
    """List all trace tables in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT name, 
               (SELECT COUNT(*) FROM sqlite_master AS sm2 
                WHERE sm2.type='table' AND sm2.name=sqlite_master.name)
        FROM sqlite_master 
        WHERE type='table' AND name LIKE '%trace%'
        ORDER BY name
    """
    )

    print("Available trace tables:")
    for (table_name,) in cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%trace%' ORDER BY name"
    ):
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"  - {table_name} ({count} entries)")

    conn.close()


def get_stats(db_path: str, table_name: str = "trace"):
    """Print statistics about the trace database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    full_table_name = f"{table_name}_trace"

    # Check if table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (full_table_name,),
    )
    if not cursor.fetchone():
        print(f"Error: Table '{full_table_name}' not found", file=sys.stderr)
        conn.close()
        return

    print(f"Statistics for {full_table_name}:")

    # Total entries
    cursor.execute(f"SELECT COUNT(*) FROM {full_table_name}")
    total = cursor.fetchone()[0]
    print(f"  Total entries: {total}")

    # Entries per thread
    cursor.execute(
        f"SELECT tid, COUNT(*) FROM {full_table_name} GROUP BY tid ORDER BY tid"
    )
    print("  Entries per thread:")
    for tid, count in cursor.fetchall():
        print(f"    TID {tid}: {count}")

    # Time range
    cursor.execute(f"SELECT MIN(timestamp), MAX(timestamp) FROM {full_table_name}")
    min_ts, max_ts = cursor.fetchone()
    if min_ts and max_ts:
        print(f"  Time range: {min_ts} to {max_ts} (duration: {max_ts - min_ts}s)")

    # Unique PC values
    cursor.execute(f"SELECT COUNT(DISTINCT pc) FROM {full_table_name}")
    unique_pcs = cursor.fetchone()[0]
    print(f"  Unique PC values: {unique_pcs}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Dump SQLite trace database to raw text format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dump entire trace table to stdout
  python dump_trace_db.py trace.db
  
  # Dump specific thread to file
  python dump_trace_db.py trace.db --tid 1234 --output thread_1234.log
  
  # List available tables
  python dump_trace_db.py trace.db --list
  
  # Show statistics
  python dump_trace_db.py trace.db --stats
        """,
    )

    parser.add_argument("database", help="Path to SQLite database file")
    parser.add_argument(
        "--table", "-t", default="trace", help="Base table name (default: trace)"
    )
    parser.add_argument("--tid", type=int, help="Thread ID to filter by")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument(
        "--list", "-l", action="store_true", help="List available tables"
    )
    parser.add_argument("--stats", "-s", action="store_true", help="Show statistics")

    args = parser.parse_args()

    if args.list:
        list_tables(args.database)
    elif args.stats:
        get_stats(args.database, args.table)
    else:
        dump_trace_table(args.database, args.table, args.tid, args.output)


if __name__ == "__main__":
    main()
