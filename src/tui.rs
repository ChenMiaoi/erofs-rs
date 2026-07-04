use crate::fuzz::FuzzSummary;
use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
};
use std::collections::BTreeMap;
use std::io::{self, Stdout};
use std::time::Duration;

type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;

pub(crate) fn show_fuzz_summary(summary: &FuzzSummary) -> Result<()> {
    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error).context("failed to enter alternate screen");
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(error) => {
            let mut stdout = io::stdout();
            let _ = execute!(stdout, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(error).context("failed to initialize TUI terminal");
        }
    };
    let run_result = run_summary_app(&mut terminal, summary);
    let restore_result = restore_terminal(&mut terminal);

    run_result.and(restore_result)
}

fn restore_terminal(terminal: &mut TuiTerminal) -> Result<()> {
    disable_raw_mode().context("failed to disable terminal raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal
        .show_cursor()
        .context("failed to restore terminal cursor")?;
    Ok(())
}

fn run_summary_app(terminal: &mut TuiTerminal, summary: &FuzzSummary) -> Result<()> {
    loop {
        terminal
            .draw(|frame| draw_summary(frame, summary))
            .context("failed to draw fuzz dashboard")?;
        if event::poll(Duration::from_millis(250)).context("failed to poll terminal events")? {
            if let Event::Key(key) = event::read().context("failed to read terminal event")? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn draw_summary(frame: &mut Frame<'_>, summary: &FuzzSummary) {
    let area = frame.area();
    let outer = Block::default()
        .style(Style::default().bg(Color::Rgb(10, 14, 19)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(59, 130, 246)))
        .title(Span::styled(
            " erofs-rs fuzz dashboard ",
            Style::default()
                .fg(Color::Rgb(191, 219, 254))
                .add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(frame, chunks[0], summary);
    render_metrics(frame, chunks[1], summary);
    render_body(frame, chunks[2], summary);
    render_footer(frame, chunks[3], summary);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let title = vec![
        Line::from(vec![
            Span::styled(
                "EROFS",
                Style::default()
                    .fg(Color::Rgb(34, 211, 238))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" mutation campaign finished"),
        ]),
        Line::from(vec![
            Span::styled("seed ", Style::default().fg(Color::Rgb(148, 163, 184))),
            Span::styled(
                summary.rng_seed.to_string(),
                Style::default().fg(Color::Rgb(251, 191, 36)),
            ),
            Span::raw("  "),
            Span::styled("inputs ", Style::default().fg(Color::Rgb(148, 163, 184))),
            Span::styled(
                summary.seed_count.to_string(),
                Style::default().fg(Color::Rgb(167, 243, 208)),
            ),
        ]),
    ];
    let header = Paragraph::new(title).block(clean_block());
    frame.render_widget(header, area);
}

fn render_metrics(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    metric_card(
        frame,
        cards[0],
        "iterations",
        &summary.iterations.to_string(),
        Color::Rgb(96, 165, 250),
    );
    metric_card(
        frame,
        cards[1],
        "unique images",
        &summary.runs.len().to_string(),
        Color::Rgb(52, 211, 153),
    );
    metric_card(
        frame,
        cards[2],
        "findings",
        &format!("{} / {}", summary.finding_count(), summary.runs.len()),
        Color::Rgb(248, 113, 113),
    );
    metric_card(
        frame,
        cards[3],
        "duration",
        &format!("{:.2}s", summary.duration.as_secs_f64()),
        Color::Rgb(251, 191, 36),
    );
}

fn metric_card(frame: &mut Frame<'_>, area: Rect, label: &str, value: &str, color: Color) {
    let text = vec![
        Line::from(Span::styled(
            label,
            Style::default().fg(Color::Rgb(148, 163, 184)),
        )),
        Line::from(Span::styled(
            trim_to_width(value, area.width.saturating_sub(4) as usize),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
    ];
    let card = Paragraph::new(text).alignment(Alignment::Center).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(51, 65, 85)))
            .style(Style::default().bg(Color::Rgb(15, 23, 32))),
    );
    frame.render_widget(card, area);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);
    render_classifications(frame, chunks[0], summary);
    render_runs(frame, chunks[1], summary);
}

fn render_classifications(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let counts = classification_counts(summary);
    let total = summary.runs.len().max(1);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" classification mix ")
        .title_style(Style::default().fg(Color::Rgb(191, 219, 254)))
        .border_style(Style::default().fg(Color::Rgb(51, 65, 85)))
        .style(Style::default().bg(Color::Rgb(12, 18, 27)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if counts.is_empty() {
        let empty = Paragraph::new("No unique artifacts were observed.")
            .style(Style::default().fg(Color::Rgb(148, 163, 184)))
            .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            counts
                .iter()
                .map(|_| Constraint::Length(2))
                .collect::<Vec<_>>(),
        )
        .split(inner);

    for ((name, count), row_area) in counts.iter().zip(rows.iter()) {
        let ratio = *count as f64 / total as f64;
        let gauge = Gauge::default()
            .block(Block::default().title(format!(" {name} ({count}) ")))
            .gauge_style(Style::default().fg(classification_color(name)))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0));
        frame.render_widget(gauge, *row_area);
    }
}

fn render_runs(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" representative runs ")
        .title_style(Style::default().fg(Color::Rgb(191, 219, 254)))
        .border_style(Style::default().fg(Color::Rgb(51, 65, 85)))
        .style(Style::default().bg(Color::Rgb(12, 18, 27)));

    let rows = summary.runs.iter().rev().take(12).map(|run| {
        Row::new(vec![
            Cell::from(run.iteration.to_string()),
            Cell::from(trim_to_width(&run.seed_name, 18)),
            Cell::from(Span::styled(
                run.classification.clone(),
                Style::default().fg(classification_color(&run.classification)),
            )),
            Cell::from(trim_to_width(&run.reason, 42)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(18),
            Constraint::Length(22),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec!["iter", "seed", "result", "reason"])
            .style(Style::default().fg(Color::Rgb(148, 163, 184))),
    )
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(table, area);
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, summary: &FuzzSummary) {
    let text = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Rgb(251, 191, 36))),
        Span::raw(" / "),
        Span::styled("Esc", Style::default().fg(Color::Rgb(251, 191, 36))),
        Span::raw(" close  "),
        Span::styled("report ", Style::default().fg(Color::Rgb(148, 163, 184))),
        Span::styled(
            trim_to_width(&summary.report_path, area.width.saturating_sub(20) as usize),
            Style::default().fg(Color::Rgb(191, 219, 254)),
        ),
    ]);
    let footer = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(clean_block());
    frame.render_widget(footer, area);
}

fn classification_counts(summary: &FuzzSummary) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for run in &summary.runs {
        *counts.entry(run.classification.clone()).or_insert(0usize) += 1;
    }
    let mut items = counts.into_iter().collect::<Vec<_>>();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
}

fn classification_color(classification: &str) -> Color {
    match classification {
        "accepted" => Color::Rgb(52, 211, 153),
        "accepted_with_errors" => Color::Rgb(251, 191, 36),
        "rejected_checksum" => Color::Rgb(96, 165, 250),
        "rejected_timeout" => Color::Rgb(248, 113, 113),
        "rejected_corruption" => Color::Rgb(244, 114, 182),
        "rejected_invalid" => Color::Rgb(167, 139, 250),
        "rejected_io_error" => Color::Rgb(45, 212, 191),
        _ => Color::Rgb(203, 213, 225),
    }
}

fn clean_block() -> Block<'static> {
    Block::default()
        .borders(Borders::NONE)
        .style(Style::default().bg(Color::Rgb(10, 14, 19)))
}

fn trim_to_width(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    format!("{}...", value.chars().take(width - 3).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::trim_to_width;

    #[test]
    fn trim_to_width_preserves_utf8_boundaries() {
        assert_eq!(trim_to_width("seed-中文路径", 8), "seed-...");
    }

    #[test]
    fn trim_to_width_handles_tiny_columns() {
        assert_eq!(trim_to_width("abcdef", 3), "...");
        assert_eq!(trim_to_width("abcdef", 0), "");
    }
}
