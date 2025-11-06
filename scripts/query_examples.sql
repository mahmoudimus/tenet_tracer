-- Example SQL queries for the structured trace database
-- Database schema:
--   trace_trace: (id, timestamp, tid, pc, registers, mem_reads, mem_writes)
--   trace_trace_<TID>: same schema, per-thread tables

-- =============================================================================
-- Basic Queries
-- =============================================================================

-- Get total number of trace entries
SELECT COUNT(*) FROM trace_trace;

-- Get entries per thread
SELECT tid, COUNT(*) as count 
FROM trace_trace 
GROUP BY tid 
ORDER BY count DESC;

-- Get time range of trace
SELECT 
    MIN(timestamp) as start_time,
    MAX(timestamp) as end_time,
    MAX(timestamp) - MIN(timestamp) as duration_seconds
FROM trace_trace;

-- =============================================================================
-- Program Counter (PC) Analysis
-- =============================================================================

-- Find most frequently executed instructions
SELECT 
    printf('0x%016X', pc) as pc_hex,
    COUNT(*) as execution_count
FROM trace_trace
GROUP BY pc
ORDER BY execution_count DESC
LIMIT 20;

-- Find unique PCs executed by each thread
SELECT 
    tid,
    COUNT(DISTINCT pc) as unique_instructions
FROM trace_trace
GROUP BY tid;

-- Find execution hotspots (PC ranges)
SELECT 
    printf('0x%016X', (pc / 4096) * 4096) as page_base,
    COUNT(*) as executions
FROM trace_trace
GROUP BY (pc / 4096)
ORDER BY executions DESC
LIMIT 10;

-- =============================================================================
-- Register Analysis
-- =============================================================================

-- Find entries where specific register was modified
-- (requires JSON extraction, SQLite 3.38+)
SELECT id, timestamp, tid, printf('0x%016X', pc) as pc, registers
FROM trace_trace
WHERE json_extract(registers, '$.rax') IS NOT NULL
LIMIT 100;

-- Count how often each register appears in traces
-- Note: This is approximate, just checks if register name is in JSON
SELECT 
    CASE 
        WHEN registers LIKE '%"rax"%' THEN 'rax'
        WHEN registers LIKE '%"rbx"%' THEN 'rbx'
        WHEN registers LIKE '%"rcx"%' THEN 'rcx'
        WHEN registers LIKE '%"rdx"%' THEN 'rdx'
        -- Add more registers as needed
    END as register,
    COUNT(*) as count
FROM trace_trace
WHERE registers != '{}'
GROUP BY register
ORDER BY count DESC;

-- =============================================================================
-- Memory Operation Analysis
-- =============================================================================

-- Count memory operations
SELECT 
    CASE 
        WHEN mem_reads != '[]' AND mem_writes != '[]' THEN 'read+write'
        WHEN mem_reads != '[]' THEN 'read_only'
        WHEN mem_writes != '[]' THEN 'write_only'
        ELSE 'none'
    END as mem_op_type,
    COUNT(*) as count
FROM trace_trace
GROUP BY mem_op_type;

-- Find all memory writes
SELECT 
    id,
    timestamp,
    tid,
    printf('0x%016X', pc) as pc,
    mem_writes
FROM trace_trace
WHERE mem_writes != '[]'
ORDER BY timestamp
LIMIT 100;

-- Find instructions that both read and write memory
SELECT 
    printf('0x%016X', pc) as pc,
    COUNT(*) as count
FROM trace_trace
WHERE mem_reads != '[]' AND mem_writes != '[]'
GROUP BY pc
ORDER BY count DESC
LIMIT 20;

-- =============================================================================
-- Time-based Analysis
-- =============================================================================

-- Get trace entries in a specific time window
SELECT 
    printf('0x%016X', pc) as pc,
    registers,
    mem_reads,
    mem_writes
FROM trace_trace
WHERE timestamp BETWEEN 1234567890 AND 1234567900
ORDER BY timestamp;

-- Sample every Nth entry (for large traces)
SELECT 
    printf('0x%016X', pc) as pc,
    registers
FROM trace_trace
WHERE id % 1000 = 0
ORDER BY id;

-- =============================================================================
-- Thread-specific Analysis
-- =============================================================================

-- Get execution timeline for a specific thread
SELECT 
    timestamp,
    printf('0x%016X', pc) as pc,
    registers,
    mem_reads,
    mem_writes
FROM trace_trace
WHERE tid = 1234
ORDER BY timestamp
LIMIT 1000;

-- Find code paths unique to each thread
SELECT 
    tid,
    printf('0x%016X', pc) as pc,
    COUNT(*) as count
FROM trace_trace
GROUP BY tid, pc
HAVING COUNT(DISTINCT tid) = 1
ORDER BY count DESC;

-- =============================================================================
-- Advanced Analysis
-- =============================================================================

-- Find potential loops (same PC executed multiple times consecutively)
WITH numbered_trace AS (
    SELECT 
        id,
        pc,
        LAG(pc) OVER (ORDER BY id) as prev_pc,
        LAG(pc, 2) OVER (ORDER BY id) as prev_pc2
    FROM trace_trace
    WHERE tid = 1234  -- specify thread
)
SELECT 
    printf('0x%016X', pc) as potential_loop_pc,
    COUNT(*) as occurrences
FROM numbered_trace
WHERE pc = prev_pc OR pc = prev_pc2
GROUP BY pc
ORDER BY occurrences DESC
LIMIT 20;

-- Execution gaps (large time jumps between entries)
WITH time_deltas AS (
    SELECT 
        id,
        timestamp,
        tid,
        printf('0x%016X', pc) as pc,
        timestamp - LAG(timestamp) OVER (PARTITION BY tid ORDER BY timestamp) as delta
    FROM trace_trace
)
SELECT *
FROM time_deltas
WHERE delta > 10  -- more than 10 second gap
ORDER BY delta DESC;

-- =============================================================================
-- Export Queries
-- =============================================================================

-- Export specific thread to CSV
.mode csv
.headers on
.output thread_1234_export.csv
SELECT 
    timestamp,
    printf('0x%016X', pc) as pc,
    registers,
    mem_reads,
    mem_writes
FROM trace_trace
WHERE tid = 1234
ORDER BY timestamp;
.output stdout

-- Export just PC trace (for basic block analysis)
.mode list
.output pc_trace.txt
SELECT printf('0x%016X', pc)
FROM trace_trace
ORDER BY timestamp;
.output stdout

