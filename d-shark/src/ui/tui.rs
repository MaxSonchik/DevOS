use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Gauge, Row, Table, List, ListItem, ListState, Cell},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Line},
    Terminal, Frame,
};
use std::io;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

#[derive(Clone)]
pub struct StatsData {
    pub packets_per_second: u64,
    pub traffic_in: f64,
    pub traffic_out: f64,
    pub active_connections: usize,
    pub blocked_connections: u64,
    pub active_rules: usize,
}

pub struct App {
    pub current_view: View,
    pub packet_log: VecDeque<String>,
    pub firewall_rules: Vec<String>,
    pub active_connections: Vec<Connection>,
    pub stats: StatsData,
    pub list_state: ListState,
    pub should_quit: bool,
}

#[derive(PartialEq)]
pub enum View {
    Packets,
    Sessions,
    Firewall,
    Geography,
    Protocols,
}

pub struct Connection {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub status: String,
    pub duration: String,
}

pub async fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    // Настройка терминала
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_tui_loop(&mut terminal).await;

    // Восстановление терминала
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        println!("TUI error: {:?}", err);
    }

    Ok(())
}

impl App {
    fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            current_view: View::Packets,
            packet_log: VecDeque::new(),
            firewall_rules: vec![
                "ALLOW 192.168.1.0/24 → ANY/ANY".to_string(),
                "BLOCK 10.0.0.5 → ANY/22".to_string(),
                "ALLOW ANY → 8.8.8.8/53".to_string(),
                "BLOCK 192.168.1.100 → ANY/ANY".to_string(),
            ],
            active_connections: vec![
                Connection {
                    protocol: "TCP".to_string(),
                    source: "192.168.1.15:44324".to_string(),
                    destination: "93.184.216.34:443".to_string(),
                    status: "ESTABLISHED".to_string(),
                    duration: "05:32".to_string(),
                },
                Connection {
                    protocol: "UDP".to_string(),
                    source: "192.168.1.20:5353".to_string(),
                    destination: "224.0.0.251:5353".to_string(),
                    status: "LISTEN".to_string(),
                    duration: "12:45".to_string(),
                },
                Connection {
                    protocol: "HTTP".to_string(),
                    source: "192.168.1.25:8080".to_string(),
                    destination: "192.168.1.1:80".to_string(),
                    status: "ESTABLISHED".to_string(),
                    duration: "00:45".to_string(),
                },
                Connection {
                    protocol: "DNS".to_string(),
                    source: "192.168.1.15:49152".to_string(),
                    destination: "8.8.8.8:53".to_string(),
                    status: "CLOSED".to_string(),
                    duration: "00:01".to_string(),
                },
            ],
            stats: StatsData {
                packets_per_second: 1234,
                traffic_in: 1.2,
                traffic_out: 0.8,
                active_connections: 45,
                blocked_connections: 12,
                active_rules: 24,
            },
            list_state,
            should_quit: false,
        }
    }

    fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.should_quit = true;
                true
            }
            KeyCode::Char('1') => {
                self.current_view = View::Packets;
                false
            }
            KeyCode::Char('2') => {
                self.current_view = View::Sessions;
                false
            }
            KeyCode::Char('3') => {
                self.current_view = View::Firewall;
                false
            }
            KeyCode::Char('4') => {
                self.current_view = View::Geography;
                false
            }
            KeyCode::Char('5') => {
                self.current_view = View::Protocols;
                false
            }
            KeyCode::Right => {
                self.current_view = match self.current_view {
                    View::Packets => View::Sessions,
                    View::Sessions => View::Firewall,
                    View::Firewall => View::Geography,
                    View::Geography => View::Protocols,
                    View::Protocols => View::Packets,
                };
                false
            }
            KeyCode::Left => {
                self.current_view = match self.current_view {
                    View::Packets => View::Protocols,
                    View::Sessions => View::Packets,
                    View::Firewall => View::Sessions,
                    View::Geography => View::Firewall,
                    View::Protocols => View::Geography,
                };
                false
            }
            KeyCode::Down => {
                if let Some(selected) = self.list_state.selected() {
                    if selected < self.firewall_rules.len().saturating_sub(1) {
                        self.list_state.select(Some(selected + 1));
                    }
                }
                false
            }
            KeyCode::Up => {
                if let Some(selected) = self.list_state.selected() {
                    if selected > 0 {
                        self.list_state.select(Some(selected - 1));
                    }
                }
                false
            }
            _ => false,
        }
    }
}

async fn run_tui_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new();
    let mut last_update = Instant::now();
    let mut counter = 0;

    while !app.should_quit {
        terminal.draw(|f| {
            ui(f, &app);
        })?;

        // Обработка ввода с таймаутом
        let timeout = Duration::from_millis(100);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let should_quit = app.handle_key(key.code);
                    if should_quit {
                        break;
                    }
                }
            }
        }

        // Обновление статистики каждую секунду
        if last_update.elapsed() > Duration::from_secs(1) {
            last_update = Instant::now();
            counter += 1;
            
            // Симуляция обновления статистики
            app.stats.packets_per_second = 1200 + (counter % 100);
            app.stats.traffic_in = 1.2 + (counter % 10) as f64 * 0.1;
            app.stats.traffic_out = 0.8 + (counter % 8) as f64 * 0.1;
            app.stats.active_connections = 40 + (counter % 10) as usize;
            app.stats.blocked_connections = 10 + (counter % 5);
            
            // Добавляем тестовые пакеты в лог
            if counter % 3 == 0 {
                let packet = format!("Packet {}: {} 192.168.1.{} -> 10.0.0.{}", 
                    counter, 
                    match counter % 5 {
                        0 => "TCP",
                        1 => "UDP", 
                        2 => "HTTP",
                        3 => "DNS",
                        _ => "HTTPS",
                    },
                    counter % 255, 
                    (counter + 1) % 255
                );
                
                if app.packet_log.len() >= 50 {
                    app.packet_log.pop_back();
                }
                app.packet_log.push_front(packet);
            }
        }
    }

    Ok(())
}

fn ui<B: ratatui::backend::Backend>(f: &mut Frame<B>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Length(6), // Stats
                Constraint::Length(3), // Menu
                Constraint::Min(10),   // Main content
                Constraint::Length(1), // Status bar
            ]
            .as_ref(),
        )
        .split(f.size());

    render_header(f, chunks[0]);
    render_stats(f, chunks[1], &app.stats);
    render_menu(f, chunks[2], &app.current_view);
    render_main_content(f, chunks[3], app);
    render_status_bar(f, chunks[4], &app.stats);
}

fn render_header<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect) {
    let title = Paragraph::new("d-shark » Analyzer & Firewall Manager")
        .style(Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, area);
}

fn render_stats<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, stats: &StatsData) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    // Traffic Analysis
    let traffic_block = Block::default()
        .title(" Traffic Analysis ")
        .borders(Borders::ALL);
    
    let traffic_in_gauge = Gauge::default()
        .block(Block::default().title("In"))
        .gauge_style(Style::default().fg(Color::Green))
        .ratio(stats.traffic_in as f64 / 10.0)
        .label(format!("{:.1} MB/s", stats.traffic_in));
    
    let traffic_out_gauge = Gauge::default()
        .block(Block::default().title("Out"))
        .gauge_style(Style::default().fg(Color::Blue))
        .ratio(stats.traffic_out as f64 / 10.0)
        .label(format!("{:.1} MB/s", stats.traffic_out));

    let traffic_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3)].as_ref())
        .margin(1)
        .split(chunks[0]);

    f.render_widget(traffic_block, chunks[0]);
    f.render_widget(traffic_in_gauge, traffic_layout[0]);
    f.render_widget(traffic_out_gauge, traffic_layout[1]);

    // Firewall Management
    let firewall_block = Block::default()
        .title(" Firewall Management ")
        .borders(Borders::ALL);
    
    let firewall_gauge = Gauge::default()
        .block(Block::default().title("Enabled"))
        .gauge_style(Style::default().fg(Color::Yellow))
        .ratio(1.0)
        .label("Yes");

    let firewall_text = Paragraph::new(format!(
        "Rules: {} active\nBlocked: {} connections",
        stats.active_rules, stats.blocked_connections
    )).block(Block::default());

    let firewall_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .margin(1)
        .split(chunks[1]);

    f.render_widget(firewall_block, chunks[1]);
    f.render_widget(firewall_gauge, firewall_layout[0]);
    f.render_widget(firewall_text, firewall_layout[1]);
}

fn render_menu<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, current_view: &View) {
    let views = vec!["Packets", "Sessions", "Firewall", "Geography", "Protocols"];
    let menu_items: Vec<Line> = views.iter().enumerate().map(|(i, &name)| {
        let style = if match current_view {
            View::Packets => i == 0,
            View::Sessions => i == 1,
            View::Firewall => i == 2,
            View::Geography => i == 3,
            View::Protocols => i == 4,
        } {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        Line::from(Span::styled(format!("[{}] {}", i + 1, name), style))
    }).collect();

    let menu = Paragraph::new(menu_items)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(menu, area);
}

fn render_main_content<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, app: &App) {
    match app.current_view {
        View::Packets => render_packets_view(f, area, app),
        View::Sessions => render_sessions_view(f, area, app),
        View::Firewall => render_firewall_view(f, area, app),
        View::Geography => render_geography_view(f, area),
        View::Protocols => render_protocols_view(f, area),
    }
}

fn render_packets_view<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, app: &App) {
    let packets: Vec<ListItem> = app.packet_log
        .iter()
        .map(|packet| ListItem::new(Line::from(Span::raw(packet.clone()))))
        .collect();

    let packets_list = List::new(packets)
        .block(Block::default().title(" Recent Packets ").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(packets_list, area);
}

fn render_sessions_view<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, app: &App) {
    let rows: Vec<Row> = app.active_connections
        .iter()
        .map(|conn| {
            Row::new(vec![
                Cell::from(conn.protocol.as_str()),
                Cell::from(conn.source.as_str()),
                Cell::from(conn.destination.as_str()),
                Cell::from(conn.status.as_str()),
                Cell::from(conn.duration.as_str()),
            ])
        })
        .collect();

    let table = Table::new(rows)
        .header(Row::new(vec![
            Cell::from("Protocol"),
            Cell::from("Source"),
            Cell::from("Destination"),
            Cell::from("Status"),
            Cell::from("Duration"),
        ]))
        .block(Block::default().title(" Active Sessions ").borders(Borders::ALL))
        .widths(&[
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Length(8),
        ])
        .style(Style::default().fg(Color::White));

    f.render_widget(table, area);
}

fn render_firewall_view<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, app: &App) {
    let rules: Vec<ListItem> = app.firewall_rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let (action, rest) = if let Some(space_idx) = rule.find(' ') {
                let (a, r) = rule.split_at(space_idx);
                (a, r.trim())
            } else {
                (&rule[..], "")
            };

            let style = if action == "ALLOW" {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            let mut text = Line::from(vec![
                Span::styled(format!("{:8} ", action), style),
                Span::raw(rest),
            ]);

            // Добавляем индикатор прогресса как в ТЗ
            if i == 0 {
                text.spans.push(Span::styled(" ██████████", Style::default().fg(Color::Green)));
            } else if i == 1 {
                text.spans.push(Span::styled(" ████████  ", Style::default().fg(Color::Red)));
            } else if i == 2 {
                text.spans.push(Span::styled(" █████     ", Style::default().fg(Color::Green)));
            } else {
                text.spans.push(Span::styled(" ███       ", Style::default().fg(Color::Red)));
            }

            ListItem::new(text)
        })
        .collect();

    let rules_list = List::new(rules)
        .block(Block::default().title(" Firewall Rules (Active) ").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(rules_list, area, &mut app.list_state.clone());
}

fn render_geography_view<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect) {
    let geo_text = vec![
        Line::from("🌍 Geographic Distribution"),
        Line::from(""),
        Line::from("🇺🇸 United States: 45%"),
        Line::from("🇩🇪 Germany: 22%"),
        Line::from("🇷🇺 Russia: 15%"),
        Line::from("🇨🇳 China: 10%"),
        Line::from("🇬🇧 United Kingdom: 8%"),
        Line::from(""),
        Line::from("Map visualization would be here"),
    ];

    let geo_block = Paragraph::new(geo_text)
        .block(Block::default().title(" Geography ").borders(Borders::ALL))
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(geo_block, area);
}

fn render_protocols_view<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect) {
    let protocol_text = vec![
        Line::from("📊 Protocol Distribution"),
        Line::from(""),
        Line::from("TCP:  45% ██████████"),
        Line::from("HTTP: 25% ██████"),
        Line::from("UDP:  15% ███"),
        Line::from("DNS:  8%  ██"),
        Line::from("TLS:  7%  ██"),
        Line::from(""),
        Line::from("Total packets: 12,345"),
    ];

    let protocol_block = Paragraph::new(protocol_text)
        .block(Block::default().title(" Protocols ").borders(Borders::ALL))
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(protocol_block, area);
}

fn render_status_bar<B: ratatui::backend::Backend>(f: &mut Frame<B>, area: Rect, stats: &StatsData) {
    let status = format!(
        "STATUS: {} active connections | {} blocked | 2 threats detected",
        stats.active_connections, stats.blocked_connections
    );
    let status_bar = Paragraph::new(status)
        .style(Style::default().fg(Color::LightGreen));
    f.render_widget(status_bar, area);
}