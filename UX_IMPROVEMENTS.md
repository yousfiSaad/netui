# NetUI - UI/UX Improvement Proposals

**Date:** November 15, 2025
**Scope:** Comprehensive UI/UX review with focus on own device indication
**Status:** Proposal for implementation

---

## Executive Summary

This document presents a comprehensive UI/UX improvement plan for NetUI, with special emphasis on making the user's own network interface more visually prominent. The current implementation uses a subtle " (*)" suffix that is easily overlooked. This proposal includes immediate wins, medium-term enhancements, and long-term features to improve usability, visual hierarchy, and user experience.

**Key Problems Identified:**
1. ⚠️ **CRITICAL**: Own device indication is nearly invisible (single asterisk)
2. Missing hostname column despite data availability
3. No visual feedback for user actions
4. Limited use of color to convey information
5. No status indicators for host activity
6. Verbose time format consuming space

**Impact:** Users frequently miss which device is their own interface, leading to confusion during network analysis.

---

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [Priority 1: Own Device Indication](#priority-1-own-device-indication)
3. [Priority 2: Information Hierarchy](#priority-2-information-hierarchy)
4. [Priority 3: Visual Feedback](#priority-3-visual-feedback)
5. [Priority 4: Advanced Features](#priority-4-advanced-features)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Code Examples](#code-examples)

---

## Current State Analysis

### What Works Well ✅

- **Clean table layout** with good use of space
- **Vim-style navigation** familiar to power users
- **Responsive help system** with F1/?
- **Real-time updates** for bandwidth statistics
- **CSV export** for data persistence
- **Tailwind color palette** provides professional appearance
- **Scrollbar** for large host lists

### Critical Pain Points 🔴

#### 1. Own Device Indication (CRITICAL)
**Current:** MAC address shows " (*)" suffix
**Location:** `src/hosts_table.rs:136-141`

```rust
{
    if host.is_my_device_mac {
        host.mac.to_string() + " (*)"
    } else {
        host.mac.to_string()
    }
}
```

**Problems:**
- Single asterisk is easy to miss
- No color differentiation
- No legend explaining the asterisk
- Users must scan the entire MAC column to find it
- When selected, the asterisk gets reversed and becomes even less visible

**User Impact:**
- Users frequently ask "Which one is my device?"
- Confusion when analyzing traffic patterns
- Accidentally cleaning/removing own device entry

#### 2. Missing Hostname Display
**Current:** Hostname data exists in `Host` struct but not shown
**Impact:** Users see only IPs, making device identification difficult

#### 3. No Visual Bandwidth Indicators
**Current:** Speed shown as text only (e.g., "1.23 Mib/s")
**Impact:** Hard to quickly identify high-bandwidth hosts

#### 4. Limited User Feedback
**Current:** No confirmation when exporting, cleaning, or scanning
**Impact:** Users unsure if actions succeeded

#### 5. Verbose Time Format
**Current:** "X min Y sec ago" consumes significant space
**Better:** Relative time formats (5m ago, 2h ago)

---

## Priority 1: Own Device Indication

### 🎯 Goal
Make the user's own device **immediately visible** at a glance, even in a list of 100+ hosts.

### Proposed Solutions (Implement Multiple)

#### Solution 1A: Dedicated Visual Icon (RECOMMENDED)
Replace asterisk with prominent Unicode icons:

```
Before: aa:bb:cc:dd:ee:ff (*)
After:  🖥️  aa:bb:cc:dd:ee:ff
  or:  ◉ aa:bb:cc:dd:ee:ff
  or:  ⬤ aa:bb:cc:dd:ee:ff
  or:  ✦ aa:bb:cc:dd:ee:ff
  or:  ▶ aa:bb:cc:dd:ee:ff
```

**Implementation:**
```rust
// In hosts_table.rs, replace line 136-141:
{
    if host.is_my_device_mac {
        format!("🖥️  {}", host.mac)  // Computer icon + MAC
    } else {
        format!("   {}", host.mac)  // Align with padding
    }
}
```

**Pros:**
- Immediately visible
- Universal recognition (computer = local)
- No text to translate
- Works in all terminals

**Cons:**
- Some old terminals may not render emoji
- Alternative: Use `▶` or `●` for broader compatibility

---

#### Solution 1B: Distinct Background Color (HIGHLY RECOMMENDED)
Highlight entire row with unique background color:

**Implementation:**
```rust
// In hosts_table.rs, modify row rendering (line 128-172):
let rows = self.items.iter().enumerate().map(|(i, host)| {
    let color = if host.is_my_device_mac {
        // Own device gets distinct color
        tailwind::TEAL.c900  // or EMERALD, GREEN, CYAN
    } else {
        // Regular alternating colors
        match i % 2 {
            0 => self.colors.normal_row_color,
            _ => self.colors.alt_row_color,
        }
    };
    // ... rest of row creation
    .style(Style::new().fg(self.colors.row_fg).bg(color))
});
```

**Color Suggestions:**
- **Teal/Cyan background** - distinct from blue selection
- **Green tint** - positive association (your device)
- **Slightly brighter** than alternating rows
- **Avoid red** - implies error/warning

**Pros:**
- Impossible to miss
- Works in all terminals
- Clear visual hierarchy
- No text changes needed

**Cons:**
- May clash with selection color (solution: adjust selection style)

---

#### Solution 1C: Dedicated Status Column (RECOMMENDED)
Add a narrow "Type" or "Status" column:

```
┌─────┬──────────────────┬───────────────────┬──────────┬──────────┬──────────┐
│Type │ IP Address       │ MAC Address       │ Speed ↓  │ Speed ↑  │ Time     │
├─────┼──────────────────┼───────────────────┼──────────┼──────────┼──────────┤
│ YOU │ 192.168.1.100    │ aa:bb:cc:dd:ee:ff │ 2.5 Mib/s│ 1.2 Mib/s│ 5m ago   │
│     │ 192.168.1.1      │ ff:ee:dd:cc:bb:aa │ 0.5 Mib/s│ 0.1 Mib/s│ 2m ago   │
│     │ 192.168.1.50     │ 11:22:33:44:55:66 │ 10 Kib/s │ 5 Kib/s  │ 1h ago   │
└─────┴──────────────────┴───────────────────┴──────────┴──────────┴──────────┘
```

**Implementation:**
```rust
// Modify header (hosts_table.rs:122):
let header = ["Type", "IP Address", "Mac Address", "Speed ↓", "Speed ↑", "Time"]
    .into_iter()
    .map(Cell::from)
    .collect::<Row>()
    .style(header_style)
    .height(1);

// Add status to row data (line 133):
let row = [
    if host.is_my_device_mac { "YOU" } else { "" },  // NEW
    host.ipv4.to_string(),
    host.mac.to_string(),
    // ... rest
];

// Update constraints (line 176):
[
    Constraint::Length(4),  // Type column - NEW
    Constraint::Length(self.longest_item_lens.0 + 1),
    // ... rest
]
```

**Alternatives for "Type" column:**
- `"YOU"` / `""` (simple text)
- `"●"` / `" "` (dot indicator)
- `"▶"` / `" "` (arrow indicator)
- `"LOCAL"` / `"REMOTE"` (more descriptive)

**Pros:**
- Very clear and explicit
- Scannable at a glance
- Can expand to show other statuses later (gateway, DNS server, etc.)
- Professional appearance

**Cons:**
- Takes horizontal space
- Adds column complexity

---

#### Solution 1D: Styled Label in Hostname Column
Show device name/label prominently:

```
192.168.1.100  │  aa:bb:cc:dd:ee:ff  │  [THIS DEVICE]  │  2.5 Mib/s
```

**Implementation:**
```rust
// Add hostname column between MAC and Speed
// If is_my_device_mac, show styled label instead of hostname
let hostname_display = if host.is_my_device_mac {
    "[THIS DEVICE]".to_string()
} else {
    host.hostname.as_deref().unwrap_or("").to_string()
};
```

---

#### Solution 1E: Border/Frame Highlighting
Draw a border or box around the own device row:

```
192.168.1.50     │ 11:22:33:44:55:66 │ 10 Kib/s  │ 5 Kib/s   │ 1h ago
╔════════════════════════════════════════════════════════════════════╗
║ 192.168.1.100  │ aa:bb:cc:dd:ee:ff │ 2.5 Mib/s │ 1.2 Mib/s │ 5m ago ║
╚════════════════════════════════════════════════════════════════════╝
192.168.1.1      │ ff:ee:dd:cc:bb:aa │ 0.5 Mib/s │ 0.1 Mib/s │ 2m ago
```

**Note:** Complex to implement with Ratatui's table widget. Consider custom rendering.

---

### 🏆 Recommended Combination

**Implement 1A + 1B + 1C** for maximum visibility:
1. **Icon** (🖥️ or ▶) in the MAC address
2. **Background color** (teal/cyan tint) for entire row
3. **Status column** showing "YOU" or "LOCAL"

This triple-reinforcement ensures the own device is **impossible to miss** while maintaining professional appearance.

---

## Priority 2: Information Hierarchy

### Issue: Missing Hostname Display

**Current:** Hostname exists in data but not shown
**Impact:** Users must memorize IPs or use external tools

#### Solution 2A: Add Hostname Column

```
┌──────────────────┬───────────────────┬────────────────┬──────────┬──────────┬──────────┐
│ IP Address       │ MAC Address       │ Hostname       │ Speed ↓  │ Speed ↑  │ Time     │
├──────────────────┼───────────────────┼────────────────┼──────────┼──────────┼──────────┤
│ 192.168.1.100    │ aa:bb:cc:dd:ee:ff │ my-laptop      │ 2.5 Mib/s│ 1.2 Mib/s│ 5m ago   │
│ 192.168.1.1      │ ff:ee:dd:cc:bb:aa │ router.local   │ 0.5 Mib/s│ 0.1 Mib/s│ 2m ago   │
│ 192.168.1.50     │ 11:22:33:44:55:66 │ unknown        │ 10 Kib/s │ 5 Kib/s  │ 1h ago   │
└──────────────────┴───────────────────┴────────────────┴──────────┴──────────┴──────────┘
```

**Implementation:**
```rust
// hosts_table.rs:122 - Update header
let header = ["IP Address", "MAC Address", "Hostname", "Speed ↓", "Speed ↑", "Time"]

// Line 133 - Add hostname to row
let row = [
    host.ipv4.to_string(),
    host.mac.to_string(),
    host.hostname.as_deref().unwrap_or("-").to_string(),  // NEW
    // ... speeds and time
];

// Update constraints and constraint calculator
```

**Note:** Currently hostname is always `None`. To populate:
- Add reverse DNS lookup (async)
- Parse from DHCP if available
- Allow manual labeling via config file

---

### Issue: Verbose Time Format

**Current:** "X min Y sec ago" (e.g., " 2 min 34 sec ago")
**Better:** Compact relative format

#### Solution 2B: Smart Time Formatting

```rust
fn format_relative_time(host_time: DateTime<Local>) -> String {
    let diff_secs = (Local::now() - host_time).num_seconds();

    match diff_secs {
        0..=59 => format!("{}s ago", diff_secs),           // "45s ago"
        60..=3599 => format!("{}m ago", diff_secs / 60),   // "5m ago"
        3600..=86399 => format!("{}h ago", diff_secs / 3600), // "2h ago"
        _ => format!("{}d ago", diff_secs / 86400),        // "3d ago"
    }
}
```

**Alternative:** Show exact time for old entries:
```rust
if diff_secs < 3600 {
    format!("{}m ago", diff_secs / 60)
} else {
    host_time.format("%H:%M:%S").to_string()  // "14:23:45"
}
```

**Benefit:** Saves ~10 characters per row, improves scannability

---

## Priority 3: Visual Feedback

### Issue: No User Action Feedback

**Current:** Actions (export, scan, clean) provide no visual confirmation
**Impact:** Users unsure if action succeeded

#### Solution 3A: Status Bar Messages

Add a message area in footer or above table:

```
┌────────────────────────────────────────────────────────────────────┐
│ ✓ Exported 23 hosts to netui_scan_20251115_143022.csv             │
└────────────────────────────────────────────────────────────────────┘
```

**Implementation:**
```rust
// Add to App struct (app.rs):
pub struct App {
    // ... existing fields
    pub status_message: Option<StatusMessage>,
}

pub struct StatusMessage {
    pub text: String,
    pub level: MessageLevel,  // Info, Success, Warning, Error
    pub timestamp: DateTime<Local>,
}

pub enum MessageLevel {
    Info,    // Blue
    Success, // Green
    Warning, // Yellow
    Error,   // Red
}

// Auto-clear after 5 seconds
impl App {
    pub fn set_status(&mut self, text: String, level: MessageLevel) {
        self.status_message = Some(StatusMessage {
            text,
            level,
            timestamp: Local::now(),
        });
    }

    pub fn tick(&mut self) {
        // Clear old messages
        if let Some(msg) = &self.status_message {
            if (Local::now() - msg.timestamp).num_seconds() > 5 {
                self.status_message = None;
            }
        }
    }
}

// Usage in export_hosts():
pub fn export_hosts(&mut self) -> AppResult<()> {
    // ... export logic
    self.set_status(
        format!("✓ Exported {} hosts to {}", self.hosts.len(), filename),
        MessageLevel::Success
    );
    Ok(())
}
```

**Render in ui.rs:**
```rust
if let Some(msg) = &app.status_message {
    let color = match msg.level {
        MessageLevel::Success => tailwind::GREEN.c400,
        MessageLevel::Info => tailwind::BLUE.c400,
        MessageLevel::Warning => tailwind::YELLOW.c400,
        MessageLevel::Error => tailwind::RED.c400,
    };

    let status_bar = Paragraph::new(&msg.text)
        .style(Style::default().fg(color))
        .block(Block::bordered());

    frame.render_widget(status_bar, status_area);
}
```

**Messages to show:**
- `"✓ Exported 23 hosts to file.csv"` (success)
- `"⟳ Scanning network..."` (info)
- `"✓ Scan complete: 15 hosts found"` (success)
- `"🗑 Cleaned 8 old hosts"` (info)
- `"⚠ No hosts to export"` (warning)
- `"✗ Export failed: permission denied"` (error)

---

#### Solution 3B: Visual Scan Progress

Show scanning progress more prominently:

**Current:** Footer shows "State: Sending ARPs"
**Better:** Progress indicator with animation

```
┌────────────────────────────────────────────────────────────────────┐
│ Scanning 192.168.1.0/24... [▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░] 45/256 hosts     │
└────────────────────────────────────────────────────────────────────┘
```

Or spinner:
```
⟳ Scanning network... (5s)
```

---

#### Solution 3C: Color-Coded Bandwidth

Use background color intensity to show bandwidth usage:

```rust
// In hosts_table.rs row creation:
let bg_color = if let Some(speed) = host.speed {
    let total_bandwidth = speed.input + speed.output;

    // Color scale based on bandwidth
    match total_bandwidth {
        0..=100_000 => self.colors.normal_row_color,         // <100 Kib/s
        100_001..=1_000_000 => tailwind::BLUE.c950,          // 100Kib - 1Mib
        1_000_001..=10_000_000 => tailwind::BLUE.c900,       // 1-10 Mib
        _ => tailwind::BLUE.c800,                            // >10 Mib
    }
} else {
    self.colors.normal_row_color
};
```

**Alternative:** Add visual bars:
```
Speed ↓: ▓▓▓▓▓░░░░░ 2.5 Mib/s
Speed ↑: ▓▓░░░░░░░░ 0.5 Mib/s
```

---

## Priority 4: Advanced Features

### Feature 4A: Sorting

Allow sorting by column (IP, MAC, Speed, Time):

**Keybindings:**
- `Shift+H` - Sort by current column
- `1-5` - Sort by column number
- `r` - Reverse sort order

**Implementation:**
```rust
pub struct App {
    // ... existing
    pub sort_column: SortColumn,
    pub sort_reverse: bool,
}

pub enum SortColumn {
    Ip,
    Mac,
    SpeedDown,
    SpeedUp,
    Time,
}

impl App {
    pub fn sort_hosts(&mut self) {
        self.hosts.sort_by(|a, b| {
            let cmp = match self.sort_column {
                SortColumn::Ip => a.ipv4.cmp(&b.ipv4),
                SortColumn::Mac => a.mac.cmp(&b.mac),
                SortColumn::SpeedDown => {
                    let a_speed = a.speed.map(|s| s.input).unwrap_or(0);
                    let b_speed = b.speed.map(|s| s.input).unwrap_or(0);
                    a_speed.cmp(&b_speed)
                }
                SortColumn::Time => a.time.cmp(&b.time),
                // ...
            };
            if self.sort_reverse { cmp.reverse() } else { cmp }
        });
    }
}
```

**Visual indicator in header:**
```
┌──────────────────┬───────────────────┬──────────↓────┬──────────┬──────────┐
│ IP Address       │ MAC Address       │ Speed ↓ ▼     │ Speed ↑  │ Time     │
└──────────────────┴───────────────────┴───────────────┴──────────┴──────────┘
                                                    ▲ (sorted, descending)
```

---

### Feature 4B: Filtering

Filter hosts by criteria:

**Keybindings:**
- `/` - Enter filter mode
- `f` - Toggle filter presets (own device only, active only, high bandwidth)

**Filter ideas:**
- Show only own device
- Show only active hosts (traffic in last 60s)
- Show only high bandwidth (>1 Mib/s)
- Search by IP/MAC substring

---

### Feature 4C: Host Details Pane

Show detailed information for selected host in side panel:

```
┌─────────────────────────────────┬──────────────────────────┐
│ Hosts (15)                      │ Selected Host Details    │
├─────────────────────────────────┼──────────────────────────┤
│ 192.168.1.100  │ aa:bb:cc:..    │ IP: 192.168.1.100       │
│ 192.168.1.1    │ ff:ee:dd:..    │ MAC: aa:bb:cc:dd:ee:ff  │
│ 192.168.1.50   │ 11:22:33:..    │ Hostname: my-laptop      │
│                                  │ First seen: 14:23:12     │
│                                  │ Last seen: 14:45:30      │
│                                  │                          │
│                                  │ Bandwidth:               │
│                                  │   Download: 2.5 Mib/s    │
│                                  │   Upload: 1.2 Mib/s      │
│                                  │   Total: 3.7 Mib/s       │
│                                  │                          │
│                                  │ Connections: 12 active   │
│                                  │   443: HTTPS (TLS)       │
│                                  │   80: HTTP               │
│                                  │   22: SSH                │
└─────────────────────────────────┴──────────────────────────┘
```

**Toggle with:** `Tab` or `d` (details)

---

### Feature 4D: Activity Indicators

Show real-time activity with symbols:

```
┌────┬──────────────────┬───────────────────┬──────────┬──────────┐
│ ⬤  │ 192.168.1.100    │ aa:bb:cc:dd:ee:ff │ 2.5 Mib/s│ 1.2 Mib/s│  Active
│ ◌  │ 192.168.1.50     │ 11:22:33:44:55:66 │ 0 Bit/s  │ 0 Bit/s  │  Idle
│ ⬤  │ 192.168.1.1      │ ff:ee:dd:cc:bb:aa │ 0.5 Mib/s│ 0.1 Mib/s│  Active
└────┴──────────────────┴───────────────────┴──────────┴──────────┘
```

**Rules:**
- `⬤` (filled) - Traffic in last 5 seconds
- `◌` (empty) - No recent traffic
- Blink animation on new packets

---

### Feature 4E: Theme/Color Customization

Allow users to choose color themes:

**Themes:**
- **Default** (Blue)
- **Dark** (Minimal colors, high contrast)
- **Matrix** (Green on black)
- **Nord** (Pastel blues)
- **Dracula** (Purple theme)

**Toggle:** `t` key cycles through themes

---

## Implementation Roadmap

### Phase 1: Critical Fixes (Week 1)
**Goal:** Make own device impossible to miss

- [ ] Implement icon prefix (Solution 1A)
- [ ] Add background color for own device row (Solution 1B)
- [ ] Update help screen with new indicators
- [ ] Test in various terminal emulators

**Estimated effort:** 4-6 hours
**Files to modify:** `src/hosts_table.rs`, `src/ui.rs`

---

### Phase 2: Information Enhancement (Week 2)
**Goal:** Show all available data clearly

- [ ] Add Hostname column (Solution 2A)
- [ ] Implement compact time format (Solution 2B)
- [ ] Add status column option (Solution 1C)
- [ ] Add legend/key at bottom of table

**Estimated effort:** 6-8 hours
**Files to modify:** `src/hosts_table.rs`, `src/app.rs`, `src/scanner.rs` (for DNS lookup)

---

### Phase 3: User Feedback (Week 3)
**Goal:** Confirm user actions

- [ ] Implement status message system (Solution 3A)
- [ ] Add success/error messages for all actions
- [ ] Add visual scan progress indicator (Solution 3B)
- [ ] Improve footer information display

**Estimated effort:** 8-10 hours
**Files to modify:** `src/app.rs`, `src/ui.rs`

---

### Phase 4: Advanced Features (Month 2)
**Goal:** Power user features

- [ ] Implement column sorting (Feature 4A)
- [ ] Add filtering capabilities (Feature 4B)
- [ ] Create host details pane (Feature 4C)
- [ ] Add activity indicators (Feature 4D)

**Estimated effort:** 20-30 hours
**Files to modify:** Multiple, significant refactoring

---

## Code Examples

### Complete Example: Enhanced Own Device Row

**File:** `src/hosts_table.rs`

```rust
// Around line 128, replace row creation:
let rows = self.items.iter().enumerate().map(|(i, host)| {
    // ENHANCEMENT 1: Background color for own device
    let color = if host.is_my_device_mac {
        tailwind::TEAL.c900  // Distinct teal background
    } else {
        match i % 2 {
            0 => self.colors.normal_row_color,
            _ => self.colors.alt_row_color,
        }
    };

    let row = [
        host.ipv4.to_string(),
        {
            // ENHANCEMENT 2: Icon prefix for own device
            if host.is_my_device_mac {
                format!("🖥️  {}", host.mac)  // Computer icon
            } else {
                format!("   {}", host.mac)  // Alignment padding
            }
        },
        {
            if let Some(speed) = host.speed {
                speed.to_string_input()
            } else {
                String::from("")
            }
        },
        {
            if let Some(speed) = host.speed {
                speed.to_string_output()
            } else {
                String::from("")
            }
        },
        {
            // ENHANCEMENT 3: Compact time format
            let diff_secs = (Local::now() - host.time).num_seconds();
            match diff_secs {
                0..=59 => format!("{}s ago", diff_secs),
                60..=3599 => format!("{}m ago", diff_secs / 60),
                3600..=86399 => format!("{}h ago", diff_secs / 3600),
                _ => format!("{}d ago", diff_secs / 86400),
            }
        },
    ];

    row.into_iter()
        .map(|content| Cell::from(Text::from(content)))
        .collect::<Row>()
        .style(Style::new().fg(self.colors.row_fg).bg(color))
        .height(1)
});
```

---

### Complete Example: Status Message System

**File:** `src/app.rs`

```rust
use chrono::{DateTime, Local};

// Add to App struct:
pub struct App {
    // ... existing fields
    pub status_message: Option<StatusMessage>,
}

#[derive(Clone, Debug)]
pub struct StatusMessage {
    pub text: String,
    pub level: MessageLevel,
    pub timestamp: DateTime<Local>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MessageLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl App {
    pub fn new(scanner: Scanner) -> AppResult<Self> {
        Ok(Self {
            // ... existing fields
            status_message: None,
        })
    }

    pub fn set_status(&mut self, text: String, level: MessageLevel) {
        self.status_message = Some(StatusMessage {
            text,
            level,
            timestamp: Local::now(),
        });
        tracing::info!("Status: {}", text);
    }

    pub fn tick(&mut self) {
        // Auto-clear status messages after 5 seconds
        if let Some(msg) = &self.status_message {
            if (Local::now() - msg.timestamp).num_seconds() > 5 {
                self.status_message = None;
            }
        }
    }

    // Update export_hosts to show feedback:
    pub fn export_hosts(&mut self) -> AppResult<()> {
        if self.hosts.is_empty() {
            self.set_status(
                "⚠ No hosts to export".to_string(),
                MessageLevel::Warning
            );
            return Err("No hosts to export".into());
        }

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("netui_scan_{}.csv", timestamp);

        let mut file = File::create(&filename)?;
        writeln!(file, "Timestamp,IP Address,MAC Address,Hostname,Download Speed,Upload Speed")?;

        for host in &self.hosts {
            let hostname = host.hostname.as_deref().unwrap_or("N/A");
            let (download, upload) = if let Some(speed) = &host.speed {
                (speed.to_string_input(), speed.to_string_output())
            } else {
                ("N/A".to_string(), "N/A".to_string())
            };
            writeln!(file, "{},{},{},{},{},{}",
                host.time.format("%Y-%m-%d %H:%M:%S"),
                host.ipv4, host.mac, hostname, download, upload)?;
        }

        // SUCCESS FEEDBACK
        self.set_status(
            format!("✓ Exported {} hosts to {}", self.hosts.len(), filename),
            MessageLevel::Success
        );

        tracing::info!("Exported {} hosts to {}", self.hosts.len(), filename);
        Ok(())
    }

    // Update handle_worker_events for scan feedback:
    pub fn handle_worker_events(&mut self, worker_event: ScannerEvent) -> AppResult<()> {
        match worker_event {
            ScannerEvent::BeginScan => {
                self.sending_arps = true;
                self.set_status(
                    "⟳ Scanning network...".to_string(),
                    MessageLevel::Info
                );
            }
            ScannerEvent::Complete => {
                self.sending_arps = false;
                self.set_status(
                    format!("✓ Scan complete: {} hosts found", self.hosts.len()),
                    MessageLevel::Success
                );
            }
            // ... rest of event handling
        }
        Ok(())
    }
}
```

**File:** `src/ui.rs`

```rust
pub fn render(app: &mut App, frame: &mut Frame) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![
            Constraint::Length(1),        // Status message - NEW
            Constraint::Fill(1),          // Table
            Constraint::Length(3)         // Footer
        ]);

    if let [status_area, table_area, footer_area] = *layout.split(frame.area()) {
        // Render status message if present
        render_status_message(frame, status_area, app);

        render_hosts_table(frame, table_area, app);
        render_footer(frame, footer_area, app);

        if app.show_help {
            render_help(frame);
        }
    }
}

fn render_status_message(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(msg) = &app.status_message {
        let (symbol, color) = match msg.level {
            MessageLevel::Success => ("✓", tailwind::GREEN.c400),
            MessageLevel::Info => ("ℹ", tailwind::BLUE.c400),
            MessageLevel::Warning => ("⚠", tailwind::YELLOW.c400),
            MessageLevel::Error => ("✗", tailwind::RED.c400),
        };

        let text = format!("{} {}", symbol, msg.text);
        let style = Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD);

        let paragraph = Paragraph::new(text)
            .style(style)
            .alignment(Alignment::Center);

        frame.render_widget(paragraph, area);
    } else {
        // Render empty space
        frame.render_widget(Paragraph::new(""), area);
    }
}
```

---

## Visual Mockups

### Before (Current State)
```
┌────────────────────────────────────────────────────────────────────────────┐
│ IP Address       │ Mac Address          │ Speed ↓       │ Speed ↑      │...│
├────────────────────────────────────────────────────────────────────────────┤
│ 192.168.1.100    │ aa:bb:cc:dd:ee:ff (*) │ 2.50 Mib/s   │ 1.20 Mib/s  │...│
│ 192.168.1.1      │ ff:ee:dd:cc:bb:aa    │ 512.00 Kib/s  │ 128.00 Kib/s│...│
│ 192.168.1.50     │ 11:22:33:44:55:66    │ 10.00 Kib/s   │ 5.00 Kib/s  │...│
└────────────────────────────────────────────────────────────────────────────┘
```
**Problem:** Easy to miss the (*) indicator

---

### After (Recommended Implementation)
```
┌────────────────────────────────────────────────────────────────────────────┐
│ ✓ Scan complete: 15 hosts found                                           │
├────────────────────────────────────────────────────────────────────────────┤
│ IP Address       │ MAC Address          │ Speed ↓    │ Speed ↑    │ Time  │
├────────────────────────────────────────────────────────────────────────────┤
│ 192.168.1.100    │ 🖥️  aa:bb:cc:dd:ee:ff│ 2.5 Mib/s  │ 1.2 Mib/s  │ 5m ago│ <-- TEAL BG
│ 192.168.1.1      │    ff:ee:dd:cc:bb:aa │ 512 Kib/s  │ 128 Kib/s  │ 2m ago│
│ 192.168.1.50     │    11:22:33:44:55:66 │ 10 Kib/s   │ 5 Kib/s    │ 1h ago│
└────────────────────────────────────────────────────────────────────────────┘
│ State: Idle  │ Hosts: 15  │ Interface: eth0  │ Speed: ↓ 3.0 Mib/s ↑ 1.5.. │
└────────────────────────────────────────────────────────────────────────────┘
```
**Improvements:**
- ✅ Status message at top
- ✅ Computer icon (🖥️) on own device
- ✅ Teal background highlighting entire row
- ✅ Compact time format (5m ago vs 5 min 0 sec ago)
- ✅ Cleaner speed format (2.5 vs 2.50)

---

### Alternative: Status Column Version
```
┌──────────────────────────────────────────────────────────────────────────┐
│Type│ IP Address       │ MAC Address          │ Speed ↓    │ Speed ↑    │...│
├──────────────────────────────────────────────────────────────────────────┤
│YOU │ 192.168.1.100    │ aa:bb:cc:dd:ee:ff    │ 2.5 Mib/s  │ 1.2 Mib/s  │...│
│    │ 192.168.1.1      │ ff:ee:dd:cc:bb:aa    │ 512 Kib/s  │ 128 Kib/s  │...│
│    │ 192.168.1.50     │ 11:22:33:44:55:66    │ 10 Kib/s   │ 5 Kib/s    │...│
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Testing Checklist

### Visual Regression Testing
- [ ] Test with 0 hosts (empty table)
- [ ] Test with 1 host (own device only)
- [ ] Test with 100+ hosts (scrolling)
- [ ] Test with very long hostnames
- [ ] Test with very high bandwidth numbers
- [ ] Test in small terminal (80x24)
- [ ] Test in large terminal (200x60)

### Terminal Compatibility
- [ ] iTerm2 (macOS)
- [ ] Terminal.app (macOS)
- [ ] Alacritty
- [ ] Kitty
- [ ] GNOME Terminal
- [ ] Konsole (KDE)
- [ ] Windows Terminal
- [ ] PuTTY/SSH sessions
- [ ] tmux/screen

### Color Blind Accessibility
- [ ] Test with deuteranopia simulation (red-green)
- [ ] Test with protanopia simulation
- [ ] Test with tritanopia simulation (blue-yellow)
- [ ] Ensure icons/symbols work without color

### Keyboard Navigation
- [ ] All features accessible via keyboard
- [ ] Help screen documents all keybindings
- [ ] No conflicts with terminal shortcuts

---

## Accessibility Considerations

1. **Color Independence:** Don't rely solely on color
   - Use icons + color (not just color)
   - Provide text labels where possible

2. **Screen Reader Support:**
   - TUIs are inherently difficult for screen readers
   - Consider adding a text-only mode (`--no-ui` flag)

3. **Keyboard Only:**
   - All features must work without mouse
   - Current vim-style navigation is excellent

4. **High Contrast Mode:**
   - Consider adding a high-contrast theme
   - Test with terminal high-contrast settings

---

## Performance Considerations

1. **Large Host Lists:**
   - Current implementation should handle 1000+ hosts
   - Consider pagination if >10,000 hosts
   - Virtual scrolling already handled by Ratatui

2. **Update Frequency:**
   - Current 1-second stat ticks are good
   - Consider throttling UI updates if >100 hosts

3. **Memory Usage:**
   - Status messages auto-clear (no memory leak)
   - Ring buffers already limit history

---

## Future Enhancements (Beyond Scope)

- **Export to JSON/YAML** (in addition to CSV)
- **Configuration file** for colors, keybindings, defaults
- **Named profiles** for different networks
- **Alerts** for new devices or high bandwidth
- **Graphs/charts** for bandwidth over time
- **Port scanning** integration
- **Geo-IP lookup** for external IPs
- **MAC vendor lookup** (OUI database)
- **Network diagram** visualization
- **Multi-interface monitoring** (split view)

---

## Conclusion

The proposed improvements, especially the own device indication enhancements, will dramatically improve NetUI's usability. The recommended implementation combines:

1. **🖥️ Icon prefix** - Visual marker
2. **🎨 Background color** - Impossible to miss
3. **✓ Status messages** - User feedback
4. **⏱️ Compact time** - Better space usage

These changes can be implemented incrementally, with Phase 1 (own device indication) providing immediate value with minimal code changes.

**Priority Order:**
1. Own device indication (Solutions 1A + 1B) - **4-6 hours**
2. Status messages (Solution 3A) - **6-8 hours**
3. Compact time format (Solution 2B) - **2 hours**
4. Hostname column (Solution 2A) - **4-6 hours**

**Total for critical improvements: ~20 hours of development**

---

**Next Steps:**
1. Review and prioritize improvements
2. Create GitHub issues for each enhancement
3. Implement Phase 1 (own device indication)
4. Gather user feedback
5. Iterate on design

---

*Document prepared: November 15, 2025*
*Version: 1.0*
*Contact: Open GitHub issue for feedback*
