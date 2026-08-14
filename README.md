# Tenable Scan Calendar

Syncs your Tenable Vulnerability Management (VM) scheduled scans into Google Calendar.

## What it does

Finds Tenable VM scans that have an active recurring schedule and are due to run in the next 7 days, then creates one calendar event per scan. Each event's description includes the finding counts (by severity — critical/high/medium/low/informational) from that scan's most recent **completed** run, so you can see at a glance both when the next scan fires and how bad things looked last time.

Scans that are disabled, broken/orphaned, or were only ever run once by hand are filtered out — only scans that are actually scheduled to run again get an event.

## Prerequisites

- Claude Cowork (or another compatible platform) with the Tenable MCP server connected, and access to a Google Calendar MCP connector.
- Read access to the Tenable VM container whose scans you want tracked.

## How to run it

Invoke the skill (`tenable-scan-calendar`) and ask something like "What Tenable scans are coming up this week? Put them on my calendar along with their last severity counts." The skill will:

1. List all scans and confirm which ones have an enabled schedule.
2. Infer each scan's cadence from its run history and project the next occurrence within a rolling 7-day window.
3. Pull severity counts from the most recent **completed** run of each qualifying scan.
4. Create a calendar event per scan with the projected run time and severity breakdown.

## Output

One Google Calendar event per actively-scheduled scan whose next run falls in the next 7 days, marked as "free" so it doesn't block your calendar. Each event description includes the scan ID, owner, inferred cadence, and severity breakdown from the last completed run.

## Known limitations

- Tenable's API doesn't expose a scan's schedule rrule directly, so the next-run time is *inferred* from recent run history rather than read authoritatively. If a scan's history is irregular (fewer than 3 runs, or inconsistent gaps), the event is still created but flagged as an estimate.
- Only Tenable VM is supported (not Tenable.sc or Nessus standalone).
- The skill only reads from Tenable and creates calendar events — it never modifies scan configuration.
