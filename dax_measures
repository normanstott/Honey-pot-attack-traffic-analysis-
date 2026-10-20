# DAX Measures and Calculated Columns

Reference for the Power BI model behind the honeypot dashboard. Formulas are laid out for readability; in Power BI, create each one separately with New measure or New column.

## Model

- **`cowrie_json_only`:** one row per log event (about 483,000 rows). Key columns: `eventid`, `session`, `src_ip`, `dst_port`, `protocol`, `username`, `password`, `input`, `url`, `outfile`, `shasum`, `duration`, `timestamp`.
- **`Distinct_IPs`:** one row per distinct source IP, with `src_ip` and `Country` (from the GeoLite2 range match), plus the calculated columns `Subnet` and `IP Label` below.
- **Relationship:** `Distinct_IPs[src_ip]` (one) to `cowrie_json_only[src_ip]` (many), single direction. Country and subnet filters flow from the lookup table to the events.
- **`Funnel Stages`:** a small disconnected table used only by the funnel chart.
- **Time zone:** all times are UTC.
- **Event names used:** `cowrie.session.connect`, `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, `cowrie.session.file_upload`. A connection is a `cowrie.session.connect` event, one per session.

## Calculated columns on `cowrie_json_only`

```DAX
-- Power Query converted the UTC timestamps to local time on load (UTC-6).
-- The whole collection window falls inside daylight time, so a constant +6 hours restores UTC.
Timestamp UTC = cowrie_json_only[timestamp] + TIME(6, 0, 0)
```

```DAX
Date =
DATE(
    YEAR(cowrie_json_only[Timestamp UTC]),
    MONTH(cowrie_json_only[Timestamp UTC]),
    DAY(cowrie_json_only[Timestamp UTC])
)
```

```DAX
Hour = HOUR(cowrie_json_only[Timestamp UTC])
```

```DAX
-- Each event rounded down to its hour, for hour-by-hour charts across specific days
Date Hour = cowrie_json_only[Date] + TIME(HOUR(cowrie_json_only[Timestamp UTC]), 0, 0)
```

```DAX
-- First 70 characters of each command, so long scripts group and display cleanly
Command Start = LEFT(cowrie_json_only[input], 70)
```

## Calculated columns on `Distinct_IPs`

```DAX
-- First three octets plus .0/24, for example a.b.c.0/24
Subnet =
VAR p1 = FIND(".", Distinct_IPs[src_ip])
VAR p2 = FIND(".", Distinct_IPs[src_ip], p1 + 1)
VAR p3 = FIND(".", Distinct_IPs[src_ip], p2 + 1)
RETURN LEFT(Distinct_IPs[src_ip], p3 - 1) & ".0/24"
```

```DAX
-- Masked label: first three octets, "xxx", and a place number within the block.
-- The number is the IP's position (alphabetical text order) among the IPs seen in its /24 block.
-- It is not the real last octet; it only keeps several IPs from one block on separate rows.
IP Label =
VAR p1 = FIND(".", Distinct_IPs[src_ip])
VAR p2 = FIND(".", Distinct_IPs[src_ip], p1 + 1)
VAR p3 = FIND(".", Distinct_IPs[src_ip], p2 + 1)
VAR blk = Distinct_IPs[Subnet]
VAR cur = Distinct_IPs[src_ip]
VAR idx =
    COUNTROWS(
        FILTER(Distinct_IPs, Distinct_IPs[Subnet] = blk && Distinct_IPs[src_ip] <= cur)
    )
RETURN LEFT(cur, p3) & "xxx (" & idx & ")"
```

## Volume and breadth

```DAX
-- One connection event per session
Connection Count =
CALCULATE(
    COUNTROWS(cowrie_json_only),
    cowrie_json_only[eventid] = "cowrie.session.connect"
)
```

```DAX
Unique Attackers =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[src_ip]),
    cowrie_json_only[eventid] = "cowrie.session.connect"
)
```

```DAX
-- An average: always read next to Top IP Share
Connections per IP = DIVIDE([Connection Count], [Unique Attackers])
```

```DAX
-- Distinct UTC days on which the IP (or group) made at least one connection
Active Days =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[Date]),
    cowrie_json_only[eventid] = "cowrie.session.connect"
)
```

```DAX
Connections per Active Day = DIVIDE([Connection Count], [Active Days])
```

## Concentration

```DAX
-- Connections made by the single busiest IP in the current group (a day, a country, a block)
Top IP Connections = MAXX(VALUES(cowrie_json_only[src_ip]), [Connection Count])
```

```DAX
Top IP Share = DIVIDE([Top IP Connections], [Connection Count])
```

```DAX
-- The busiest IP's address (ties are listed together)
Top IP =
CONCATENATEX(
    TOPN(1, VALUES(cowrie_json_only[src_ip]), [Connection Count], DESC),
    cowrie_json_only[src_ip],
    ", "
)
```

```DAX
-- A country's share of all connections (all-country denominator)
Share of Connections =
DIVIDE(
    [Connection Count],
    CALCULATE([Connection Count], ALL(Distinct_IPs[Country]))
)
```

```DAX
-- A country's share of all distinct IPs
Share of Unique IPs =
DIVIDE(
    [Unique Attackers],
    CALCULATE([Unique Attackers], ALL(Distinct_IPs[Country]))
)
```

```DAX
-- Safe at the IP or subnet level: clears every Distinct_IPs filter (country, IP and subnet)
Share of All Connections =
DIVIDE(
    [Connection Count],
    CALCULATE([Connection Count], ALL(Distinct_IPs))
)
```

```DAX
-- The /24 block with the most connections
Top Subnet =
CONCATENATEX(
    TOPN(1, VALUES(Distinct_IPs[Subnet]), [Connection Count], DESC),
    Distinct_IPs[Subnet],
    ", "
)
```

```DAX
Top Subnet Share =
DIVIDE(
    MAXX(VALUES(Distinct_IPs[Subnet]), [Connection Count]),
    CALCULATE([Connection Count], ALL(Distinct_IPs))
)
```

```DAX
-- Distinct IPs inside the largest block
Top Subnet IPs =
VAR topBlock = [Top Subnet]
RETURN CALCULATE([Unique Attackers], Distinct_IPs[Subnet] = topBlock)
```

## Credentials

Usernames and passwords exist only on login events, so these measures filter on the login event names instead of reusing the connection measures (which would return blanks).

```DAX
Login Attempts =
CALCULATE(
    COUNTROWS(cowrie_json_only),
    cowrie_json_only[eventid] IN {"cowrie.login.failed", "cowrie.login.success"}
)
```

```DAX
Login IPs =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[src_ip]),
    cowrie_json_only[eventid] IN {"cowrie.login.failed", "cowrie.login.success"}
)
```

```DAX
Share of Login Attempts =
DIVIDE(
    [Login Attempts],
    CALCULATE(
        [Login Attempts],
        REMOVEFILTERS(cowrie_json_only[username], cowrie_json_only[password])
    )
)
```

```DAX
Successful Logins =
CALCULATE(
    COUNTROWS(cowrie_json_only),
    cowrie_json_only[eventid] = "cowrie.login.success"
)
```

```DAX
-- Per login attempt (the funnel shows the per-session rate, which is higher)
Login Success Rate = DIVIDE([Successful Logins], [Login Attempts])
```

## Protocol

```DAX
SSH Share =
DIVIDE(
    CALCULATE([Connection Count], cowrie_json_only[protocol] = "ssh"),
    [Connection Count]
)
```

```DAX
Telnet Share =
DIVIDE(
    CALCULATE([Connection Count], cowrie_json_only[protocol] = "telnet"),
    [Connection Count]
)
```

## Post-compromise and funnel

```DAX
Sessions Tried Login =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[session]),
    cowrie_json_only[eventid] IN {"cowrie.login.failed", "cowrie.login.success"}
)
```

```DAX
Sessions Logged In =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[session]),
    cowrie_json_only[eventid] = "cowrie.login.success"
)
```

```DAX
Sessions with Commands =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[session]),
    cowrie_json_only[eventid] = "cowrie.command.input"
)
```

Captured files come only from download and upload events. The `shasum` column also holds hashes of recorded terminal sessions (on `cowrie.log.closed` events), which must be excluded.

```DAX
Payload Hashes =
CALCULATE(
    DISTINCTCOUNTNOBLANK(cowrie_json_only[shasum]),
    cowrie_json_only[eventid] IN {"cowrie.session.file_download", "cowrie.session.file_upload"}
)
```

```DAX
Payload Sessions =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[session]),
    cowrie_json_only[eventid] IN {"cowrie.session.file_download", "cowrie.session.file_upload"}
)
```

```DAX
Payload IPs =
CALCULATE(
    DISTINCTCOUNT(cowrie_json_only[src_ip]),
    cowrie_json_only[eventid] IN {"cowrie.session.file_download", "cowrie.session.file_upload"}
)
```

```DAX
-- One label per file hash: Download, Upload, or Both
Captured Via =
VAR d = CALCULATE(COUNTROWS(cowrie_json_only), cowrie_json_only[eventid] = "cowrie.session.file_download")
VAR u = CALCULATE(COUNTROWS(cowrie_json_only), cowrie_json_only[eventid] = "cowrie.session.file_upload")
RETURN
    SWITCH(
        TRUE(),
        d > 0 && u > 0, "Both",
        d > 0, "Download",
        u > 0, "Upload",
        BLANK()
    )
```

The funnel chart uses a small calculated table of stage names and one switch measure:

```DAX
Funnel Stages =
DATATABLE(
    "Stage", STRING,
    "Order", INTEGER,
    {
        {"1. Connected", 1},
        {"2. Tried a login", 2},
        {"3. Logged in", 3},
        {"4. Ran commands", 4},
        {"5. Captured a file", 5}
    }
)
-- Set the Stage column to Sort by column: Order. Leave the table disconnected.
```

```DAX
Funnel Sessions =
SWITCH(
    SELECTEDVALUE('Funnel Stages'[Order]),
    1, [Connection Count],
    2, [Sessions Tried Login],
    3, [Sessions Logged In],
    4, [Sessions with Commands],
    5, [Payload Sessions]
)
```

Optional: a Top N visual filter keeps every row tied at the cutoff, so a "top 10" can return more rows. This measure breaks ties alphabetically; filter the visual to Is Top 10 Command = 1.

```DAX
Is Top 10 Command =
VAR top10 =
    TOPN(
        10,
        ALL(cowrie_json_only[Command Start]),
        [Sessions with Commands], DESC,
        cowrie_json_only[Command Start], ASC
    )
RETURN IF(MAX(cowrie_json_only[Command Start]) IN top10, 1, 0)
```

## Retired measures and settings (and why)

- **`Distinct Payloads`** = `DISTINCTCOUNTNOBLANK(cowrie_json_only[shasum])` across all events. It returned 1,689, but 1,629 of those hashes belong to recorded terminal sessions, not files. Replaced by `Payload Hashes` (61 real files).
- **"Show value as: Percent of grand total"** on the connection and IP counts. It divides by the visible rows only, so Bulgaria read 36% of connections instead of 27.4%. Replaced by `Share of Connections` and `Share of Unique IPs`, which divide by all countries.
- **Averages without a concentration measure.** `Connections per IP` for Poland (389) was one IP. Every average on the dashboard now sits beside `Top IP Share`.
