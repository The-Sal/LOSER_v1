# ic_audit

A low-latency, anti-fragile audit logging system designed for trading systems and multi-project environments.

## Overview

ic_audit is a lightweight audit logging package that provides centralized logging capabilities across multiple trading systems and projects. It's designed to be simple, fast, and resilient - gracefully handling network failures without disrupting your main application.

## Key Features

- **Low Latency**: Asynchronous, threaded logging that doesn't block your main application
- **Anti-Fragile**: Fails silently when the audit server is unavailable, ensuring your trading systems never stop
- **Centralized**: Single audit server collects logs from all your projects
- **Easy Integration**: Drop-in logging that can be injected at the top of any project
- **Trading-Focused**: Built-in event types for common trading operations
- **Persistent Storage**: Audit trails are saved to disk and survive server restarts

## Architecture

The system consists of two main components:

1. **AuditNotifier** (Client): Lightweight client that sends audit events
2. **AuditServer**: Centralized server running on `localhost:9324` that collects and stores events

## Quick Start

### 1. Start the Audit Server

```bash
python main.py
```

The server will start on `localhost:9324` and load any existing audit trails.

### 2. Basic Usage in Your Project

```python
from ic_audit import AuditNotifier, ProjectEvents, ProjectPrivileges

# Initialize the audit notifier
auditor = AuditNotifier(
    project_name="MyTradingBot",
    project_market="FOREX",
    project_description="Automated EURUSD trading system",
    project_privileges=ProjectPrivileges.EXECUTE_TRADE
)

# Log trading events
auditor.send(ProjectEvents.TRADE_OPENED, "Opened long EURUSD", 
             symbol="EURUSD", price=1.0850, quantity=10000)

auditor.send(ProjectEvents.TRADE_CLOSED, "Closed EURUSD position", 
             symbol="EURUSD", exit_price=1.0875, profit=250)

# Log errors
auditor.send(ProjectEvents.ERROR, "Connection timeout to broker", 
             error_code="CONN_TIMEOUT")
```

### 3. One-Line Quick Audit

For simple notifications:

```python
from ic_audit import fast_audit

fast_audit("ScriptName", "Crypto", "Bitcoin price monitor started")
```

## Event Types

Pre-defined event types in `ProjectEvents`:

- `BOOT`: System startup
- `ERROR`: Error conditions  
- `TRADE_OPENED`: New trade executed
- `TRADE_CLOSED`: Trade position closed
- `UNCLASSIFIED_EVENT`: General purpose events

You can also define any custom events as `ProjectEvents` is just a mask for string constants.

## Project Privileges

Define what your project is authorized to do:

- `EXECUTE_TRADE`: Can execute actual trades
- `POST_MORTEM_ANALYSIS`: Analysis and reporting
- `LIVE_MONITORING`: Real-time monitoring
- `UTILITIES`: Support utilities

Just like events, privileges are defined in `ProjectPrivileges` and can be extended as needed.

## Audit Trail Management

### Dump Today's Audit Trails

```python
from ic_audit import trigger_audit_dumping

trigger_audit_dumping()
```

This creates `dumped_audit_trails.json` with all events from the last 30 hours, organized by project.

### Manual Server Control

```bash
# Interactive mode - press Enter to dump trails
python main.py

# Build standalone executable
python main.py -build
```

## Anti-Fragile Design

The system is designed to never break your main application:

- **Threaded Operations**: All network calls run in separate threads
- **Graceful Failures**: Uses `@redundancy` decorator to catch and ignore socket errors
- **No Dependencies**: Minimal external dependencies
- **Automatic Recovery**: Reconnects automatically when server becomes available

## Data Persistence

- Audit trails are automatically saved to `~/.cellar/loser_audit.pickle`
- Data persists across server restarts
- JSON exports available for analysis and reporting

## Example Output

```json
{
  "MyTradingBot": [
    {
      "event_type": "boot",
      "event_description": "Project was booted.",
      "timestamp": 1692345600.123,
      "project_name": "MyTradingBot",
      "project_market": "FOREX",
      "project_description": "Automated EURUSD trading system",
      "project_privileges": ["execute_trade"]
    },
    {
      "event_type": "trade_opened",
      "event_description": "Opened long EURUSD",
      "timestamp": 1692345660.456,
      "symbol": "EURUSD",
      "price": 1.0850,
      "quantity": 10000
    }
  ]
}
```

## Use Cases

- **Multi-System Trading**: Track activities across multiple trading bots
- **Compliance**: Maintain audit trails for regulatory requirements  
- **Debugging**: Centralized logging for troubleshooting
- **Performance Analysis**: Track system performance and trade outcomes
- **Risk Management**: Monitor system behaviors and errors



## Requirements

- Python 3.6+
- `utils3` package (for threading and redundancy decorators) 

## License

Version 0.3 - Built for IC