# Honey-pot-attack-traffic-analysis-
*Reading a Month of Attack Traffic*

A Power BI analysis of 148,580 connections to an SSH/Telnet honeypot (31 days, Sept 3 to Oct 3, 2026)

I turned about 483,000 raw log events from a Cowrie honeypot into a four-page Power BI dashboard and a written report. The question behind it: who is attacking, when, from where, and what do they do once they get in? I did not set out to judge the sensor or its security. The goal was to find meaningful trends in a large, messy, real-world dataset and to document every decision on the way.

*Key findings*

- Volume comes from a few sources, not many. The sensor logged 148,580 connections from 7,103 distinct IPs. The biggest daily spike (Sept 6) was a single address making 51% of that day's connections at a steady rate for about four hours.

- Two address blocks make 38% of all connections. One /24 block (256 addresses) in Bulgaria made 26.2% from 79 IPs, and one in the US made 11.8% from 43 IPs. Together that is 122 IPs, 1.7% of all sources.

- Few sessions get in, and those that do follow a script. 77% of connections try a login and 4.3% of those succeed. Of the 4,901 successful logins, 72% run commands (system recon plus what looks like an SSH-key installation routine). Only 61 distinct files were captured, and one file accounts for 79% of file-capture sessions.

- Usernames are concentrated, passwords are not. The username root is 38% of login attempts; the ten most common passwords together are 16%.
Protocol varies by country. Traffic from Pakistan is 92% Telnet, while traffic from Bulgaria, Poland and Romania is more than 99.7% SSH.

*How I built it*

- Power Query: combined 31 gzip-compressed JSON Lines files with a folder combine, and filtered to the needed events early. A load that hung for over an hour completed once the nested SSH-fingerprint events were dropped.

- Data modeling: an events table plus a small lookup of distinct IPs, joined by a relationship instead of a merge, which removed repeated hour-long waits.

- Geolocation: matched address ranges from the free GeoLite2 country data against the distinct IPs only (thousands of rows, not hundreds of thousands).

- DAX: measures for volume vs. breadth, concentration (top IP share, subnet share), credentials, protocol mix and the session funnel. See code/dax_measures.md.

- Validation: every number is reconciled against another view. This caught a six-hour timestamp shift (fixed by converting to UTC), a hash column that mixed two meanings (1,689 apparent payloads became 61 real files), and a chart that divided by visible rows only (Bulgaria showed 36% instead of 27.4%).

- Design rule: always show volume next to the number of distinct sources, so one heavy IP cannot pass for a trend.

*Data, privacy and ethics*

- Not included: the raw logs and the Power BI file. They contain third parties' IP addresses, and the data belongs to the friend who ran the sensor.

- IPs are masked. Single addresses show the last number as xxx, and ranges appear as /24 blocks. The dashboard's only IP-level table is masked.

- Safe handling. The archive was verified against its SHA-256 checksum and treated as potentially hostile. Nothing was executed, no links were opened, and captured files were analyzed only by hash and count.

- Attribution: this product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.

*Limitations*

- One sensor, one honeypot type, one month. The patterns may reflect where this sensor sits and should not be generalized to the internet.

- Country reflects where an address is registered or located, not where an attacker is, and a /24 block is not necessarily one actor.

- A sensor outage on Sept 18 (about 21 hours) and a partial last day (Oct 3) understate those dates.
