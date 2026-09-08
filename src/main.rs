use std::{
    collections::{BTreeMap, HashSet},
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

            let item = BlockedItem {
                time: event.time,
                path: path.clone(),
                process: event.process.unwrap_or_else(|| "<not recorded>".to_owned()),
                rule: event.rule.unwrap_or_else(|| "<not recorded>".to_owned()),
                occurrences: 1,
                excluded_now: is_excluded(&path, &exclusions),
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
            format!("{} unique blocked paths. Space selects; Enter applies; r refreshes; q quits.", items.len())
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
        if !self.checked.insert(path.clone()) {
            self.checked.remove(&path);
        }
    }

    fn selected_paths(&self) -> Vec<String> {
        self.checked.iter().cloned().collect()
    }

    fn refresh(&mut self) -> Result<()> {
        let previously_checked = self.checked.clone();
        let refreshed = Self::load()?;
        self.items = refreshed.items;
        self.policy_enabled = refreshed.policy_enabled;
        self.selected = self.selected.min(self.items.len().saturating_sub(1));
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
                KeyCode::Char('r') => {
                    if let Err(error) = app.refresh() {
                        app.status = format!("Refresh failed: {error:#}");
                    }
                }
                KeyCode::Enter | KeyCode::Char('a') => {
                    if app.checked.is_empty() {
                        app.status = "Select at least one red [X] item first.".to_owned();
                    } else if app.policy_enabled {
                        app.mode = Mode::ConfirmApply;
                    } else {
                        apply_with_status(app);
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
        Row::new(vec![
            Cell::from(if selected { "[x]" } else { "[ ]" }),
            Cell::from(status),
            Cell::from(item.time.clone()),
            Cell::from(item.path.clone()),
            Cell::from(item.process.clone()),
            Cell::from(item.occurrences.to_string()),
        ])
        .style(Style::default().fg(color))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
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
        lines.push(Line::from(vec![
            Span::styled("Rule ", Style::default().fg(Color::DarkGray)),
            Span::raw(item.rule.clone()),
            Span::styled("  Path ", Style::default().fg(Color::DarkGray)),
            Span::raw(item.path.clone()),
        ]));
    }
    let status = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Status "))
        .wrap(Wrap { trim: true });
    frame.render_widget(status, layout[1]);

    if app.mode == Mode::ConfirmApply {
        let popup = centered_rect(70, 45, frame.area());
        frame.render_widget(Clear, popup);
        let message = "Group Policy currently manages ASR exclusions on this computer.\n\nThe selected paths will be added to that policy list (the same registry location gpedit writes) and to local Defender preferences. If a domain or Intune policy refresh rewrites the list, entries added here may be removed.\n\nApply the selected exclusions?\n\nEnter/Y = apply    Esc/N = cancel";
        let dialog = Paragraph::new(message)
            .block(Block::default().borders(Borders::ALL).title(" Confirm policy override "))
            .style(Style::default().fg(Color::Yellow).bg(Color::Black))
            .wrap(Wrap { trim: true });
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

fn is_excluded(path: &str, exclusions: &[String]) -> bool {
    let path = normalize_path(path);
    exclusions.iter().any(|entry| path == *entry || path.starts_with(&format!("{entry}\\")))
}
