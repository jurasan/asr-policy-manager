use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, Write},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use serde::Deserialize;

const EVENT_LOG: &str = "Microsoft-Windows-Windows Defender/Operational";

#[derive(Debug, Deserialize)]
struct RawEvent {
    time: String,
    path: Option<String>,
    process: Option<String>,
    rule: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ExclusionSettings {
    #[serde(default)]
    local: Vec<String>,
    #[serde(default)]
    policy: Vec<String>,
    #[serde(default)]
    policy_enabled: bool,
}

#[derive(Debug, Clone)]
struct BlockedItem {
    time: String,
    path: String,
    process: String,
    rule: String,
    occurrences: usize,
    excluded_now: bool,
    /// The normalized exclusion entry (file or folder) that currently covers
    /// this path, when one does.
    excluded_by: Option<String>,
    /// How many trailing path components are dropped to form the exclusion
    /// target: 0 = the file itself, 1 = its folder, 2 = the parent of that, ...
    scope: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Browse,
    ConfirmApply,
}

struct App {
    items: Vec<BlockedItem>,
    selected: usize,
    checked: HashSet<String>,
    policy_enabled: bool,
    status: String,
    mode: Mode,
}

impl App {
    fn load() -> Result<Self> {
        let settings = load_exclusions()?;
        let exclusions = settings
            .local
            .iter()
            .chain(settings.policy.iter())
            .map(|value| normalize_path(value))
            .collect::<Vec<_>>();

        let mut grouped = BTreeMap::<String, BlockedItem>::new();
        for event in load_events()? {
            let path = event.path.unwrap_or_default().trim().to_owned();
            if path.is_empty() {
                continue;
            }

            let excluded_by = matching_exclusion(&path, &exclusions);
            let item = BlockedItem {
                time: event.time,
                path: path.clone(),
                process: event.process.unwrap_or_else(|| "<not recorded>".to_owned()),
                rule: event.rule.unwrap_or_else(|| "<not recorded>".to_owned()),
                occurrences: 1,
                excluded_now: excluded_by.is_some(),
                excluded_by,
                scope: 0,
            };

            match grouped.get_mut(&path) {
                Some(existing) => {
                    existing.occurrences += 1;
                    if item.time > existing.time {
                        *existing = BlockedItem {
                            occurrences: existing.occurrences,
                            ..item
                        };
                    }
                }
                None => {
                    grouped.insert(path, item);
                }
            }
        }

        let mut items = grouped.into_values().collect::<Vec<_>>();
        items.sort_by(|left, right| right.time.cmp(&left.time));
        let status = if items.is_empty() {
            "No recent ASR block events were found.".to_owned()
        } else {
            format!(
                "{} unique blocked paths. Space selects; Left/Right widen/narrow to a folder; Enter applies; r refreshes; q quits.",
                items.len()
            )
        };

        Ok(Self {
            items,
            selected: 0,
            checked: HashSet::new(),
            policy_enabled: settings.policy_enabled,
            status,
            mode: Mode::Browse,
        })
    }

    fn selected_item(&self) -> Option<&BlockedItem> {
        self.items.get(self.selected)
    }

    fn toggle_selected(&mut self) {
        let Some(item) = self.selected_item() else {
            return;
        };
        if item.excluded_now {
            self.status = "That path is already excluded.".to_owned();
            return;
        }

        let path = item.path.clone();
        let target = exclusion_target(&path, item.scope);
        if self.checked.insert(path.clone()) {
            self.status = format!("Selected. Will exclude {target}");
        } else {
            self.checked.remove(&path);
            self.status = "Selection cleared.".to_owned();
        }
    }

    /// Moves the exclusion target of the highlighted row up the folder tree
    /// (positive `delta`) or back down towards the file (negative `delta`).
    fn adjust_scope(&mut self, delta: isize) {
        let Some(item) = self.items.get_mut(self.selected) else {
            return;
        };
        if item.excluded_now {
            self.status = "That path is already excluded.".to_owned();
            return;
        }

        let max = max_scope(&item.path) as isize;
        let new_scope = (item.scope as isize + delta).clamp(0, max) as usize;
        if new_scope == item.scope {
            self.status = if delta > 0 {
                "Cannot widen further: the drive root is never offered as an exclusion.".to_owned()
            } else {
                "Already at the exact file.".to_owned()
            };
            return;
        }

        item.scope = new_scope;
        let target = exclusion_target(&item.path, item.scope);
        let is_checked = self.checked.contains(&item.path);
        self.status = if is_checked {
            format!("Selected. Will exclude {target}")
        } else {
            format!("Will exclude {target} (press Space to select)")
        };
    }

    /// The distinct paths that would be added, honoring each row's scope.
    /// Several rows widened to the same folder collapse into one entry.
    fn selected_paths(&self) -> Vec<String> {
        let mut targets = self
            .items
            .iter()
            .filter(|item| self.checked.contains(&item.path))
            .map(|item| exclusion_target(&item.path, item.scope))
            .collect::<Vec<_>>();
        targets.sort_by_key(|target| target.to_ascii_lowercase());
        targets.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        targets
    }

    fn refresh(&mut self) -> Result<()> {
        let previously_checked = self.checked.clone();
        let previous_scopes = self
            .items
            .iter()
            .map(|item| (item.path.clone(), item.scope))
            .collect::<HashMap<_, _>>();

        let refreshed = Self::load()?;
        self.items = refreshed.items;
        self.policy_enabled = refreshed.policy_enabled;
        self.selected = self.selected.min(self.items.len().saturating_sub(1));
        for item in &mut self.items {
            if let Some(scope) = previous_scopes.get(&item.path) {
                item.scope = (*scope).min(max_scope(&item.path));
            }
        }
        self.checked = previously_checked
            .into_iter()
            .filter(|path| self.items.iter().any(|item| &item.path == path && !item.excluded_now))
            .collect();
        self.status = "Refreshed Defender ASR history and exclusions.".to_owned();
        Ok(())
    }
}

const ELEVATED_FLAG: &str = "--elevated";

fn main() {
    let relaunched = std::env::args().skip(1).any(|arg| arg == ELEVATED_FLAG);

    if !elevation::is_elevated() {
        match elevation::relaunch_elevated() {
            Ok(()) => return,
            Err(error) => {
                eprintln!("Could not request administrator rights: {error:#}");
                eprintln!("Start this program from an elevated terminal instead.");
                pause_if(relaunched);
                std::process::exit(1);
            }
        }
    }

    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        // When the UAC relaunch gave us our own console, keep the window open
        // long enough for the message to be read.
        pause_if(relaunched);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut app = App::load().context("Could not load Defender ASR data")?;
    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    result
}

fn pause_if(condition: bool) {
    if !condition {
        return;
    }
    eprintln!();
    eprintln!("Press Enter to close this window.");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

#[cfg(windows)]
mod elevation {
    use std::{ffi::OsStr, iter::once, mem, os::windows::ffi::OsStrExt, ptr};

    use anyhow::{bail, Context, Result};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
    };

    /// Returns true when the current process token is elevated (running as administrator).
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Re-launches this executable through the UAC "runas" verb, forwarding the
    /// original arguments plus a marker so the elevated copy knows it owns its console.
    pub fn relaunch_elevated() -> Result<()> {
        let exe = std::env::current_exe().context("Could not locate this executable")?;
        let mut params = std::env::args()
            .skip(1)
            .filter(|arg| arg != super::ELEVATED_FLAG)
            .map(quote_arg)
            .collect::<Vec<_>>();
        params.push(super::ELEVATED_FLAG.to_owned());
        let params = params.join(" ");
        let working_dir = exe.parent().map(|dir| dir.to_owned()).unwrap_or_default();

        let verb = wide("runas");
        let file = wide(exe.as_os_str());
        let params = wide(&params);
        let dir = wide(working_dir.as_os_str());

        let result = unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                dir.as_ptr(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns a pseudo-HINSTANCE; values <= 32 are error codes.
        let code = result as usize;
        if code <= 32 {
            if code == 5 {
                bail!("the UAC prompt was declined");
            }
            bail!("ShellExecuteW failed with code {code}");
        }
        Ok(())
    }

    fn quote_arg(arg: String) -> String {
        if arg.is_empty() || arg.contains([' ', '\t', '"']) {
            format!("\"{}\"", arg.replace('"', "\\\""))
        } else {
            arg
        }
    }

    fn wide<S: AsRef<OsStr> + ?Sized>(value: &S) -> Vec<u16> {
        value.as_ref().encode_wide().chain(once(0)).collect()
    }
}

#[cfg(not(windows))]
mod elevation {
    use anyhow::{bail, Result};

    pub fn is_elevated() -> bool {
        true
    }

    pub fn relaunch_elevated() -> Result<()> {
        bail!("elevation is only supported on Windows")
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| render(frame, app))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match app.mode {
            Mode::Browse => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => {
                    app.selected = (app.selected + 1).min(app.items.len().saturating_sub(1));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.selected = app.selected.saturating_sub(1);
                }
                KeyCode::Char(' ') => app.toggle_selected(),
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('-') => app.adjust_scope(1),
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('+') => app.adjust_scope(-1),
                KeyCode::Char('r') => {
                    if let Err(error) = app.refresh() {
                        app.status = format!("Refresh failed: {error:#}");
                    }
                }
                KeyCode::Enter | KeyCode::Char('a') => {
                    if app.checked.is_empty() {
                        app.status = "Select at least one red [X] item first.".to_owned();
                    } else {
                        // Always confirm: the dialog lists the exact paths, which
                        // matters once rows have been widened to folders.
                        app.mode = Mode::ConfirmApply;
                    }
                }
                _ => {}
            },
            Mode::ConfirmApply => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    app.mode = Mode::Browse;
                    apply_with_status(app);
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    app.mode = Mode::Browse;
                    app.status = "No changes were made.".to_owned();
                }
                _ => {}
            },
        }
    }
}

/// Applies the selection and reports the outcome in the status bar instead of
/// ending the app on failure.
fn apply_with_status(app: &mut App) {
    if let Err(error) = apply_and_refresh(app) {
        app.status = format!("Apply failed: {error:#}");
    }
}

fn apply_and_refresh(app: &mut App) -> Result<()> {
    let paths = app.selected_paths();
    let write_policy = app.policy_enabled;
    add_exclusions(&paths, write_policy)?;
    let count = paths.len();
    app.refresh()?;
    app.status = if write_policy {
        format!("Added {count} path(s) to the Group Policy ASR exclusion list and to local preferences.")
    } else {
        format!("Added {count} ASR exclusion(s), then refreshed the list.")
    };
    Ok(())
}

fn render(frame: &mut ratatui::Frame, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(4)])
        .split(frame.area());

    let header = Row::new(["Pick", "Status", "Latest block", "Blocked path", "Process", "Count"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows = app.items.iter().map(|item| {
        let selected = app.checked.contains(&item.path);
        let status = if item.excluded_now { "[OK] Excluded" } else { "[X] Blocked" };
        let color = if item.excluded_now { Color::Green } else { Color::Red };

        // The scope marker only matters while the row can still be selected.
        let pick = match (selected, item.scope, item.excluded_now) {
            (true, 0, _) | (true, _, true) => "[x]".to_owned(),
            (true, scope, false) => format!("[x] ^{scope}"),
            (false, 0, _) | (false, _, true) => "[ ]".to_owned(),
            (false, scope, false) => format!("[ ] ^{scope}"),
        };

        // Split the path so the part that is (or will be) the exclusion is
        // underlined and the remainder dimmed. For blocked rows that is the
        // chosen scope; for excluded rows it is the folder entry covering them.
        let split_at = if item.excluded_now {
            item.excluded_by
                .as_deref()
                .and_then(|entry| covered_prefix_len(&item.path, entry))
        } else if item.scope > 0 {
            Some(exclusion_target(&item.path, item.scope).len())
        } else {
            None
        };
        let path_cell = match split_at {
            Some(at) if at < item.path.len() => Cell::from(Line::from(vec![
                Span::styled(
                    item.path[..at].to_owned(),
                    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
                Span::styled(item.path[at..].to_owned(), Style::default().fg(Color::DarkGray)),
            ])),
            _ => Cell::from(item.path.clone()),
        };

        Row::new(vec![
            Cell::from(pick),
            Cell::from(status),
            Cell::from(item.time.clone()),
            path_cell,
            Cell::from(item.process.clone()),
            Cell::from(item.occurrences.to_string()),
        ])
        .style(Style::default().fg(color))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(15),
            Constraint::Length(21),
            Constraint::Percentage(48),
            Constraint::Percentage(38),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" ASR Policy Manager "))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

    let mut table_state = TableState::default();
    if !app.items.is_empty() {
        table_state.select(Some(app.selected));
    }
    frame.render_stateful_widget(table, layout[0], &mut table_state);

    let mut lines = vec![Line::from(Span::styled(
        app.status.clone(),
        Style::default().fg(Color::Yellow),
    ))];
    if let Some(item) = app.selected_item() {
        let (label, target) = match item.excluded_by.as_deref() {
            Some(entry) => {
                // Show the covering entry in the path's own casing when possible.
                let shown = match covered_prefix_len(&item.path, entry) {
                    Some(at) => item.path[..at].to_owned(),
                    None if normalize_path(&item.path) == entry => item.path.clone(),
                    None => entry.to_owned(),
                };
                ("  Excluded by ".to_owned(), shown)
            }
            None => {
                let scope_label = match item.scope {
                    0 => "file".to_owned(),
                    1 => "folder".to_owned(),
                    n => format!("folder, {n} levels up"),
                };
                (format!("  Exclude ({scope_label}) "), exclusion_target(&item.path, item.scope))
            }
        };
        lines.push(Line::from(vec![
            Span::styled("Rule ", Style::default().fg(Color::DarkGray)),
            Span::raw(item.rule.clone()),
            Span::styled(label, Style::default().fg(Color::DarkGray)),
            Span::styled(target, Style::default().add_modifier(Modifier::BOLD)),
        ]));
    }
    let status = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Status "))
        .wrap(Wrap { trim: true });
    frame.render_widget(status, layout[1]);

    if app.mode == Mode::ConfirmApply {
        let popup = centered_rect(80, 60, frame.area());
        frame.render_widget(Clear, popup);

        const MAX_LISTED: usize = 10;
        let targets = app.selected_paths();
        let mut message = String::new();
        if app.policy_enabled {
            message.push_str(
                "Group Policy currently manages ASR exclusions on this computer. The paths below will be added to that policy list (the same registry location gpedit writes) and to local Defender preferences. A domain or Intune policy refresh may remove them again.\n\n",
            );
        }
        message.push_str(&format!("{} path(s) will be excluded from ASR:\n", targets.len()));
        for target in targets.iter().take(MAX_LISTED) {
            message.push_str("  ");
            message.push_str(target);
            message.push('\n');
        }
        if targets.len() > MAX_LISTED {
            message.push_str(&format!("  ... and {} more\n", targets.len() - MAX_LISTED));
        }
        message.push_str("\nEnter/Y = apply    Esc/N = cancel");

        let title = if app.policy_enabled { " Confirm policy override " } else { " Confirm exclusions " };
        let dialog = Paragraph::new(message)
            .block(Block::default().borders(Borders::ALL).title(title))
            .style(Style::default().fg(Color::Yellow).bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(dialog, popup);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn load_events() -> Result<Vec<RawEvent>> {
    let script = format!(
        r#"
$items = @(Get-WinEvent -FilterHashtable @{{ LogName = '{EVENT_LOG}'; Id = 1121 }} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {{
    [xml] $xml = $_.ToXml()
    $fields = @{{}}
    foreach ($field in @($xml.Event.EventData.Data)) {{ $fields[$field.Name] = [string] $field.InnerText }}
    [pscustomobject]@{{
        time = $_.TimeCreated.ToUniversalTime().ToString('o')
        path = $fields['Path']
        process = $fields['Process Name']
        rule = $fields['ID']
    }}
}})
$items | ConvertTo-Json -Compress
"#
    );
    parse_json_array(&run_powershell(&script)?)
}

fn load_exclusions() -> Result<ExclusionSettings> {
    let script = r#"
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
$listKey = "$policyKey\ASROnlyExclusions"
$local = try { @((Get-MpPreference).AttackSurfaceReductionOnlyExclusions) } catch { @() }
$policy = try { if (Test-Path -LiteralPath $listKey) { @((Get-Item -LiteralPath $listKey).Property) } else { @() } } catch { @() }
$policyEnabled = try { (Get-ItemProperty -LiteralPath $policyKey -ErrorAction Stop).ExploitGuard_ASR_ASROnlyExclusions -eq 1 } catch { $false }
[pscustomobject]@{ local = $local; policy = $policy; policy_enabled = $policyEnabled } | ConvertTo-Json -Compress
"#;
    let output = run_powershell(script)?;
    serde_json::from_str(&output).context("Defender exclusion data was not valid JSON")
}

/// Adds the paths as ASR-only exclusions.
///
/// When `write_policy` is set, the paths are also written into the Group Policy
/// list at `...\Windows Defender Exploit Guard\ASR\ASROnlyExclusions` (the same
/// registry location the gpedit setting uses). While that policy is enabled,
/// Defender ignores the local preference list, so without this the additions
/// would never show up as effective exclusions.
fn add_exclusions(paths: &[String], write_policy: bool) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    // One path per line. Windows paths cannot contain newlines, and this avoids
    // the nested-array shape that ConvertFrom-Json produces in Windows PowerShell 5.1.
    let encoded_paths = STANDARD.encode(paths.join("\n").as_bytes());
    let write_policy = if write_policy { "$true" } else { "$false" };
    let script = format!(
        r#"
$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_paths}'))
[string[]] $paths = @($text -split "`n" | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }})
if ({write_policy}) {{
    $listKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions'
    if (-not (Test-Path -LiteralPath $listKey)) {{ New-Item -Path $listKey -Force | Out-Null }}
    foreach ($path in $paths) {{
        New-ItemProperty -LiteralPath $listKey -Name $path -Value '0' -PropertyType String -Force | Out-Null
    }}
}}
Add-MpPreference -AttackSurfaceReductionOnlyExclusions $paths
"#
    );
    run_powershell(&script)?;
    Ok(())
}

fn parse_json_array<T>(json: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let value: serde_json::Value = serde_json::from_str(json).context("PowerShell did not return JSON")?;
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::Array(_) => Ok(serde_json::from_value(value)?),
        _ => Ok(vec![serde_json::from_value(value)?]),
    }
}

fn run_powershell(script: &str) -> Result<String> {
    // Wrap the script so any failure becomes a terminating error whose message is
    // written to stderr as plain text. Without this, powershell.exe serializes
    // redirected error records as CLIXML, which is unreadable.
    let wrapped = format!(
        r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {{
{script}
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"#
    );
    // The script is passed on standard input rather than as an encoded command
    // line. Defender's "suspicious command line" heuristic (CMD_HSTR) flags
    // powershell.exe -EncodedCommand / -ExecutionPolicy Bypass, so keep the
    // command line plain. Commands read from stdin are not subject to the
    // script execution policy.
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Could not start Windows PowerShell")?;
    {
        let mut stdin = child.stdin.take().context("Could not open PowerShell stdin")?;
        // With "-Command -", Windows PowerShell treats stdin like typed input: a
        // multi-line block only runs once a blank line follows it. The whole
        // script sits inside one try block, so a trailing blank line completes it.
        stdin
            .write_all(wrapped.as_bytes())
            .and_then(|()| stdin.write_all(b"\n\n"))
            .context("Could not send script to PowerShell")?;
        // Dropping stdin closes it so PowerShell exits after running the input.
    }
    let output = child.wait_with_output().context("Windows PowerShell did not finish")?;
    if !output.status.success() {
        let error = clean_powershell_error(&String::from_utf8_lossy(&output.stderr));
        bail!("Windows PowerShell failed: {error}");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Turns PowerShell stderr into a readable message, unwrapping CLIXML if it
/// slipped through (for example from a parse error outside the try block).
fn clean_powershell_error(stderr: &str) -> String {
    let stderr = stderr.trim();
    if !stderr.starts_with("#< CLIXML") {
        return stderr.to_owned();
    }
    let mut parts = Vec::new();
    let mut rest = stderr;
    while let Some(start) = rest.find(r#"<S S="Error">"#) {
        let body = &rest[start + r#"<S S="Error">"#.len()..];
        let Some(end) = body.find("</S>") else {
            break;
        };
        let text = body[..end]
            .replace("_x000D__x000A_", "\n")
            .replace("_x000A_", "\n")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&");
        parts.push(text);
        rest = &body[end + "</S>".len()..];
    }
    let joined = parts.concat();
    let joined = joined.trim();
    if joined.is_empty() {
        stderr.to_owned()
    } else {
        joined.to_owned()
    }
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Returns the normalized exclusion entry that covers `path`, preferring the
/// most specific (longest) match when several apply.
fn matching_exclusion(path: &str, exclusions: &[String]) -> Option<String> {
    let path = normalize_path(path);
    exclusions
        .iter()
        .filter(|entry| !entry.is_empty())
        .filter(|entry| path == **entry || path.starts_with(&format!("{entry}\\")))
        .max_by_key(|entry| entry.len())
        .cloned()
}

/// Byte length of the leading part of `path` that a folder exclusion covers,
/// including the separator after the folder. `None` when the entry is the file
/// itself or the prefix cannot be mapped back onto the displayed path.
fn covered_prefix_len(path: &str, entry: &str) -> Option<usize> {
    let normalized = normalize_path(path);
    if normalized == entry || normalized.len() != path.trim().len() {
        return None;
    }
    let len = entry.len() + 1;
    (len < path.len() && path.is_char_boundary(len)).then_some(len)
}

/// How far the exclusion target may move up from the file. The drive (or UNC
/// server and share) plus at least one folder always remain, so `C:\` itself is
/// never offered as an exclusion.
fn max_scope(path: &str) -> usize {
    let components = path.split(['\\', '/']).filter(|part| !part.is_empty()).count();
    let reserved = if path.starts_with("\\\\") { 3 } else { 2 };
    components.saturating_sub(reserved)
}

/// The path that will actually be excluded: the file itself for scope 0, its
/// folder for scope 1, that folder's parent for scope 2, and so on.
///
/// Folder targets end with a backslash. Defender treats an ASR exclusion
/// without one as a file name, so `C:\Tools` would not cover `C:\Tools\x.exe`
/// while `C:\Tools\` does.
fn exclusion_target(path: &str, scope: usize) -> String {
    if scope == 0 {
        return path.to_owned();
    }
    let trimmed = path.trim_end_matches(['\\', '/']);
    let mut end = trimmed.len();
    for _ in 0..scope {
        match trimmed[..end].rfind(['\\', '/']) {
            Some(index) if index > 0 => end = index,
            _ => break,
        }
    }
    format!("{}\\", &trimmed[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_walks_up_but_never_reaches_drive_root() {
        let path = r"C:\Users\me\Tools\grove\grove.exe";
        assert_eq!(max_scope(path), 4);
        assert_eq!(exclusion_target(path, 0), path);
        assert_eq!(exclusion_target(path, 1), r"C:\Users\me\Tools\grove\");
        assert_eq!(exclusion_target(path, 4), r"C:\Users\");
    }

    #[test]
    fn short_paths_cannot_widen() {
        assert_eq!(max_scope(r"C:\Scripts\grove.exe"), 1);
        assert_eq!(exclusion_target(r"C:\Scripts\grove.exe", 1), r"C:\Scripts\");
        assert_eq!(max_scope(r"C:\grove.exe"), 0);
    }

    #[test]
    fn unc_paths_keep_server_and_share() {
        let path = r"\\server\share\apps\tool.exe";
        assert_eq!(max_scope(path), 1);
        assert_eq!(exclusion_target(path, 1), r"\\server\share\apps\");
    }

    #[test]
    fn covering_folder_is_found_and_mapped_back_onto_the_path() {
        let path = r"C:\Users\JURIKR~1\AppData\Local\Programs\grove\grove.exe";
        let exclusions = vec![
            normalize_path(r"C:\Other\"),
            normalize_path(r"C:\Users\JURIKR~1\AppData\Local\Programs\grove\"),
        ];
        let entry = matching_exclusion(path, &exclusions).expect("folder should cover the file");
        let at = covered_prefix_len(path, &entry).expect("prefix should map onto path");
        assert_eq!(&path[..at], r"C:\Users\JURIKR~1\AppData\Local\Programs\grove\");
        assert_eq!(&path[at..], "grove.exe");
    }

    #[test]
    fn exact_file_exclusion_has_no_folder_prefix() {
        let path = r"C:\Tools\x.exe";
        let exclusions = vec![normalize_path(path)];
        let entry = matching_exclusion(path, &exclusions).unwrap();
        assert_eq!(covered_prefix_len(path, &entry), None);
        assert_eq!(matching_exclusion(r"C:\Tools\y.exe", &exclusions), None);
    }

    #[test]
    fn folder_targets_end_with_backslash_and_files_do_not() {
        let path = r"C:\Tools\x.exe";
        assert!(!exclusion_target(path, 0).ends_with('\\'));
        assert!(exclusion_target(path, 1).ends_with('\\'));
    }
}
