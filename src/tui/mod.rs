use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, Borders, Chart, Dataset, List, ListItem},
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::mpsc::Receiver,
    time::{Duration, Instant, UNIX_EPOCH},
};

use crate::{capture::dns_providers::DnsProvider, shared::TxEvent};

// Data structures for tracking DNS traffic
struct DnsTrafficData {
    // History of queries per provider over time (for charts)
    provider_history: HashMap<DnsProvider, Vec<(f64, f64)>>, // (time_offset, count)
    start_time: Instant,
    window_size: f64, // Time window in seconds

    // Current stats
    top_domains: Vec<(String, u32)>,
    top_providers: Vec<(DnsProvider, u32)>,

    // Current query counts
    queries_per_provider: HashMap<DnsProvider, u32>,
    domain_counts: HashMap<String, u32>,
    provider_counts: HashMap<DnsProvider, u32>,

    // Recent queries for detailed view
    recent_queries: VecDeque<TxEvent>,

    // Source-to-destination tracking
    connections: HashMap<String, u32>,
}

impl DnsTrafficData {
    fn new(window_size: f64) -> Self {
        Self {
            provider_history: HashMap::new(),
            start_time: Instant::now(),
            window_size,
            top_domains: Vec::new(),
            top_providers: Vec::new(),
            queries_per_provider: HashMap::new(),
            domain_counts: HashMap::new(),
            provider_counts: HashMap::new(),
            recent_queries: VecDeque::with_capacity(100), // Keep last 100 queries
            connections: HashMap::new(),
        }
    }

    fn update(&mut self, event: TxEvent) {
        let event_clone = event.clone();
        match event {
            TxEvent::DnsQuery {
                domain,
                provider,
                source,
                destination,
                ..
            } => {
                // Update domain counts
                *self.domain_counts.entry(domain.clone()).or_insert(0) += 1;

                // Update provider counts
                *self.provider_counts.entry(provider.clone()).or_insert(0) += 1;

                // Update query count for this provider (for chart)
                *self
                    .queries_per_provider
                    .entry(provider.clone())
                    .or_insert(0) += 1;

                // Track connections (source to destination pairs)
                let connection_key = format!("{}->{}", source, destination);
                *self.connections.entry(connection_key).or_insert(0) += 1;

                // Add data point for chart
                let elapsed = self.start_time.elapsed().as_secs_f64();
                let count = *self.queries_per_provider.get(&provider).unwrap_or(&0) as f64;

                self.provider_history
                    .entry(provider.clone())
                    .or_insert_with(Vec::new)
                    .push((elapsed, count));

                // Store recent query
                self.recent_queries.push_front(event_clone);
                if self.recent_queries.len() > 100 {
                    self.recent_queries.pop_back();
                }

                // Update top lists after each query
                self.update_top_lists();

                // Prune old data points
                self.prune_old_data();
            }
        }
    }

    fn update_top_lists(&mut self) {
        // Update top domains
        self.top_domains = self
            .domain_counts
            .iter()
            .map(|(domain, count)| (domain.clone(), *count))
            .collect::<Vec<_>>();
        self.top_domains.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
        self.top_domains.truncate(10); // Keep top 10

        // Update top providers
        self.top_providers = self
            .provider_counts
            .iter()
            .map(|(provider, count)| (provider.clone(), *count))
            .collect::<Vec<_>>();
        self.top_providers.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
        self.top_providers.truncate(5); // Keep top 5
    }

    fn prune_old_data(&mut self) {
        let current_time = self.start_time.elapsed().as_secs_f64();
        let cutoff = current_time - self.window_size;

        for points in self.provider_history.values_mut() {
            // Keep only points newer than cutoff
            points.retain(|(time, _)| *time >= cutoff);
        }
    }

    // Get top source-destination connections
    fn get_top_connections(&self, limit: usize) -> Vec<(String, u32)> {
        let mut connections: Vec<(String, u32)> = self.connections.clone().into_iter().collect();
        connections.sort_by(|a, b| b.1.cmp(&a.1));
        connections.truncate(limit);
        connections
    }

    // Get recent DNS queries as formatted strings
    fn get_recent_activity(&self, limit: usize) -> Vec<String> {
        self.recent_queries
            .iter()
            .take(limit)
            .map(|event| match event {
                TxEvent::DnsQuery {
                    domain,
                    query_type,
                    provider,
                    timestamp,
                    ..
                } => {
                    let time_since_start = timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        % 86400; // Seconds in current day

                    let hours = (time_since_start / 3600) % 24;
                    let minutes = (time_since_start / 60) % 60;
                    let seconds = time_since_start % 60;

                    format!(
                        "{:02}:{:02}:{:02} - {} - {} ({})",
                        hours,
                        minutes,
                        seconds,
                        domain,
                        query_type,
                        provider.as_str()
                    )
                }
            })
            .collect()
    }
}

pub fn run_tui(rx: Receiver<TxEvent>) -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut traffic_data = DnsTrafficData::new(60.0); // 60 second window

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        // Draw UI
        terminal.draw(|f| {
            // Create layout
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(f.size());

            // Stats area
            let stats_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(30),
                    Constraint::Percentage(30),
                    Constraint::Percentage(40),
                ])
                .split(chunks[0]);

            // 1. Render top domains list
            let domains: Vec<ListItem> = traffic_data
                .top_domains
                .iter()
                .map(|(domain, count)| {
                    ListItem::new(format!("{}: {}", domain, count))
                        .style(Style::default().fg(Color::White))
                })
                .collect();

            let domains_list = List::new(domains)
                .block(
                    Block::default()
                        .title(Span::styled(
                            "Top Domains",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Gray)),
                )
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");

            f.render_widget(domains_list, stats_chunks[0]);

            // 2. Render top providers list
            let providers: Vec<ListItem> = traffic_data
                .top_providers
                .iter()
                .map(|(provider, count)| {
                    // Choose a unique color for each provider if possible
                    let color = match provider {
                        DnsProvider::Cloudflare => Color::Cyan,
                        DnsProvider::Google => Color::Red,
                        DnsProvider::OpenDNS => Color::Green,
                        DnsProvider::Quad9 => Color::Magenta,
                        DnsProvider::AdGuard => Color::Yellow,
                        DnsProvider::CleanBrowsing => Color::White,
                        DnsProvider::Unknown => Color::Gray,
                    };

                    ListItem::new(format!("{}: {}", provider.as_str(), count))
                        .style(Style::default().fg(color))
                })
                .collect();

            let providers_list = List::new(providers)
                .block(
                    Block::default()
                        .title(Span::styled(
                            "Top Providers",
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Gray)),
                )
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");

            f.render_widget(providers_list, stats_chunks[1]);

            // 3. Render connections list
            let connections: Vec<ListItem> = traffic_data
                .get_top_connections(5)
                .iter()
                .map(|(conn, count)| {
                    ListItem::new(format!("{}: {}", conn, count))
                        .style(Style::default().fg(Color::Yellow))
                })
                .collect();

            let connections_list = List::new(connections)
                .block(
                    Block::default()
                        .title(Span::styled(
                            "Top Connections",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Gray)),
                )
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");

            f.render_widget(connections_list, stats_chunks[2]);

            // Chart area
            let chart_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(chunks[1]);

            // DNS Traffic Chart
            let datasets = create_chart_datasets(&traffic_data);

            let chart = Chart::new(datasets)
                .block(
                    Block::default()
                        .title(Span::styled(
                            "DNS Traffic by Provider",
                            Style::default()
                                .fg(Color::Blue)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Gray)),
                )
                .x_axis(
                    Axis::default()
                        .title(Span::styled("Time (s)", Style::default().fg(Color::White)))
                        .style(Style::default().fg(Color::White))
                        .bounds([
                            traffic_data.start_time.elapsed().as_secs_f64()
                                - traffic_data.window_size,
                            traffic_data.start_time.elapsed().as_secs_f64(),
                        ])
                        .labels(vec![
                            Span::styled("-60s", Style::default().fg(Color::White)),
                            Span::styled("now", Style::default().fg(Color::White)),
                        ]),
                )
                .y_axis(
                    Axis::default()
                        .title(Span::styled("Queries", Style::default().fg(Color::White)))
                        .style(Style::default().fg(Color::White))
                        .bounds([0.0, 50.0])
                        .labels(vec![
                            Span::styled("0", Style::default().fg(Color::White)),
                            Span::styled("25", Style::default().fg(Color::White)),
                            Span::styled("50", Style::default().fg(Color::White)),
                        ]),
                );

            f.render_widget(chart, chart_chunks[0]);

            // Recent DNS Activity
            let recent_activity = traffic_data.get_recent_activity(8);
            let activity_items: Vec<ListItem> = recent_activity
                .iter()
                .map(|item| ListItem::new(item.clone()).style(Style::default().fg(Color::White)))
                .collect();

            let activity_list = List::new(activity_items).block(
                Block::default()
                    .title(Span::styled(
                        "Recent DNS Activity",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Gray)),
            );

            f.render_widget(activity_list, chart_chunks[1]);
        })?;

        // Handle events
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Process DNS events
        while let Ok(event) = rx.try_recv() {
            traffic_data.update(event);
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn create_chart_datasets(data: &DnsTrafficData) -> Vec<Dataset> {
    let mut datasets = Vec::new();

    // Define colors for each provider
    let provider_colors = [
        (DnsProvider::Cloudflare, Color::Cyan),
        (DnsProvider::Google, Color::Red),
        (DnsProvider::OpenDNS, Color::Green),
        (DnsProvider::Quad9, Color::Magenta),
        (DnsProvider::AdGuard, Color::Yellow),
        (DnsProvider::Unknown, Color::Gray),
    ];

    for (provider, color) in provider_colors.iter() {
        // Convert string to DnsProvider enum
        if let Some(history) = data.provider_history.get(&provider) {
            if !history.is_empty() {
                datasets.push(
                    Dataset::default()
                        .name(provider.as_str())
                        .marker(symbols::Marker::Braille)
                        .style(Style::default().fg(*color))
                        .data(history),
                );
            }
        }
    }

    datasets
}
