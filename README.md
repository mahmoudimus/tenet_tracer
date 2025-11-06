# tenet_tracer

A Pin Tool for tracing instructions specifically for [tenet](https://github.com/gaasedelen/tenet/).

A special thank you to [hasherezade](https://github.com/hasherezade)'s [tiny_tracer](https://github.com/hasherezade/tiny_tracer) of which this tool is generously built on.

## TRACE FORMAT

Input:  `reg=0xval,reg=0xval,rip=0xpc,mr=0xaddr:hexbytes,mw=0xaddr:hexbytes`
Stored: `timestamp(int), tid(int), pc(int), registers(json), mem_reads(json), mem_writes(json)`
Output: Same as input (via [`scripts/dump_trace_db.py`](./scripts/dump_trace_db.py))

### Real Trace Example

```csv
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
```

### SQLite Trace Logging: Design and Features

Structured Schema:

- Trace data is stored in dedicated, queryable columns:
  - `timestamp` (INTEGER): Unix epoch seconds
  - `tid` (INTEGER): Thread ID
  - `pc` (INTEGER): Program counter
  - `registers` (TEXT): JSON-encoded register deltas, e.g. `{"rax":"0x1234"}`
  - `mem_reads` (TEXT): JSON array of memory reads, e.g. `[{"addr":"0xaddr","data":"hexbytes"}]`
  - `mem_writes` (TEXT): JSON array of memory writes

- Table layout:
  - `<prefix>_trace`: Main trace for all threads
  - `<prefix>_trace_<tid>`: Per-thread tables for parallel/filtered analysis

- Indexing:
  - `idx_<prefix>_trace_tid_ts` on `(tid, timestamp)` for fast time/range queries

Optimized Insertion:

- Uses **prepared statements** (`sqlite3_prepare_v2`, `sqlite3_bind_*`) for all inserts:
  - Prevents SQL injection
  - Avoids quote/escape handling
  - Boosts performance through statement reuse

- **Batch commits**: Entries are accumulated (default batch size: 100), then written in a single transaction:
  - Wraps inserts in `BEGIN ... COMMIT`
  - Massively reduces I/O overhead

- **WAL mode** is enabled for safe concurrent read access and improved durability:
  - `PRAGMA journal_mode=WAL`
  - `PRAGMA synchronous=NORMAL`

---

#### Example Database Schema

```sql
CREATE TABLE trace_trace (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,      -- Unix epoch seconds
    tid INTEGER,            -- Thread ID
    pc INTEGER,             -- Program counter
    registers TEXT,         -- JSON: register deltas (i.e. {"rax":"0x1234"})
    mem_reads TEXT,         -- JSON: memory reads 
                            --       (i.e. [{"addr":"0x...", "data":"..."}])
    mem_writes TEXT         -- JSON: memory writes
                            --       (i.e. [{"addr":"0x...", "data":"..."}])
);


CREATE INDEX idx_trace_trace_tid_ts ON trace_trace(tid, timestamp);
```

## COMMON COMMANDS

### View Stats

```bash
python3 dump_trace_db.py trace.db --stats
```

### List Tables

```bash
python3 dump_trace_db.py trace.db --list
```

### Dump to File

```bash
python3 dump_trace_db.py trace.db --output trace.log
python3 dump_trace_db.py trace.db --tid 1234 --output thread_1234.log
```

### Entry Count

```bash
sqlite3 trace.db "SELECT COUNT(*) FROM trace_trace;"
```

### Threads

```bash
sqlite3 trace.db "SELECT tid, COUNT(*) FROM trace_trace GROUP BY tid;"
```

### Hot Instructions (Top 10)

```bash
sqlite3 trace.db "SELECT printf('0x%X', pc), COUNT(*) as cnt FROM trace_trace GROUP BY pc ORDER BY cnt DESC LIMIT 10;"
```

### Time Range

```bash
sqlite3 trace.db "SELECT MIN(timestamp), MAX(timestamp), MAX(timestamp)-MIN(timestamp) as duration FROM trace_trace;"
```

### Memory Writes

```bash
sqlite3 trace.db "SELECT * FROM trace_trace WHERE mem_writes != '[]' LIMIT 10;"
```

### Specific PC Range

```bash
sqlite3 trace.db "SELECT * FROM trace_trace WHERE pc >= 0x400000 AND pc < 0x500000;"
```

### Export to CSV

```bash
sqlite3 -csv -header trace.db "SELECT timestamp, printf('0x%X',pc) as pc, registers FROM trace_trace" > trace.csv
```

### JSON QUERIES (SQLite 3.38+)

Find RAX changes

```bash
sqlite3 trace.db "SELECT * FROM trace_trace WHERE json_extract(registers, '$.rax') IS NOT NULL LIMIT 10;"
```

Extract register value

```bash
sqlite3 trace.db "SELECT json_extract(registers, '$.rax') FROM trace_trace WHERE json_extract(registers, '$.rax') IS NOT NULL LIMIT 5;"
```

## PERFORMANCE TIPS

- Use per-thread tables (trace_trace_`<tid>`) for better parallelism
- Query with tid in WHERE clause to use index
- Batch size 100-500 optimal for most cases
- Use LIMIT when exploring large traces
- Sample with "WHERE id % N = 0" for overview

## INTEGRATION CODE

```c++
# ifdef USE_SQLITE3
sqlite3* db = nullptr;
sqlite3_open("trace.db", &db);
auto logger = tenet_tracer::LoggerBuilder()
    .addHandler(std::make_unique<tenet_tracer::SqliteLogHandler>(db, "trace", 100))
    .build();
logger->setThreadId(tid);
logger->log("rax=0x1234,rip=0x400000");
logger->close();
sqlite3_close(db);
# endif
```

## TROUBLESHOOTING

- **Trace entries not appearing?**
  - Batches may not be flushed yet. Call `logger->close()` or ensure program shutdown triggers a flush.

- **"Database locked" errors?**
  - WAL mode is enabled by default; if you encounter lock errors, double-check your SQLite configuration.

- **Slow queries?**
  - Use the `tid, timestamp` index. Add further indexes based on query needs.

- **Want even faster write performance?**
  - Increase batch size (e.g. 500–1000). For maximum speed at the risk of corruption, try `PRAGMA synchronous=OFF`.

- **Format compatibility concerns?**
  - Use [`dump_trace_db.py`](./scripts/dump_trace_db.py) to convert SQLite data back to the original text format. Note: PC field (`rip`/`eip`) may differ by architecture, but both refer to the program counter.

- **"Database locked" errors?**
  - WAL mode is enabled by default; double-check for multi-process access or database handles left open.

- **Empty query results?**
  - Entries may still be in the queue. Call `logger->close()` or let the program fully exit to flush all data.

- **Slow queries?**
  - Use `LIMIT`, filter by `tid`, and make sure indexes exist for your queries.

- **Wrong output format?**
  - Use [`dump_trace_db.py`](./scripts/dump_trace_db.py) to convert SQLite data back to the original format.

- **High memory usage?**
  - Lower the `batch_size` argument in the handler constructor to reduce queue growth.

## 🚧 How to build

### On Windows

**This project will not work if you use `Windows* (MSVC)`. This is CRITICALLY IMPORTANT!**

To compile the prepared project you need to use [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/). 

It was tested with [Intel Pin 3.31](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html#inpage-nav-undefined-1)'s `Windows* (LLVM clang-cl)`.

Why?

Because Intel Pin Tools for LLVM's clang-cl support all of C++11 and some extras support some of C++14. This allows us to write Pin code in MODERN C++.

Now, just clone this repo into `\source\tools` that is inside your Pin root directory. Open the project in Visual Studio and build.

## WARNINGS

- In order for Pin to work correctly, Kernel Debugging must be **DISABLED**.
- In [`install32_64`](./install32_64) you can find a utility that checks if Kernel Debugger is disabled (`kdb_check.exe`, [source](https://github.com/hasherezade/pe_utils/tree/master/kdb_check)), and it is used by the Tenet Tracer's `.bat` scripts. This utilty sometimes gets flagged as a malware by Windows Defender (it is a known false positive). If you encounter this issue, you may need to [exclude](https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26) the installation directory from Windows Defender scans.

### Potential Future Enhancements

- Normalize registers and memory to separate tables
- Store memory data in binary (not hex)
- Compress JSON columns for storage savings
- Periodically `VACUUM` to reclaim space
- Support live analysis via a read-only DB while tracing is active
- Streaming analytics (aggregations) during trace capture
