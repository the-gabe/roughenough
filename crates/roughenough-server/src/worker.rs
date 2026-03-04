use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use crossbeam_channel::Sender;
use mio::net::{TcpListener, UdpSocket as MioUdpSocket};
use mio::{Events, Poll, Token};
use roughenough_protocol::util::ClockSource;
use roughenough_server::args::Args;
use roughenough_server::metrics::aggregator::WorkerMetrics;
use roughenough_server::network::CollectResult::Empty;
use roughenough_server::network::{CollectResult, NetworkHandler};
use roughenough_server::requests::RequestHandler;
use roughenough_server::responses::ResponseHandler;
use roughenough_server::tcp_network::TcpNetworkHandler;
use tracing::info;

const UDP_TOKEN: Token = Token(0);
const TCP_LISTENER_TOKEN: Token = Token(1);

pub struct Worker {
    worker_id: usize,
    clock: ClockSource,
    net_handler: NetworkHandler,
    tcp_handler: Option<TcpNetworkHandler>,
    req_handler: RequestHandler,
    metrics_channel: Sender<WorkerMetrics>,
    key_replacement_interval: Duration,
    metrics_publish_interval: Duration,
    next_key_replacement: u64,
    next_metrics_publication: u64,
    // Maps TCP client SocketAddr -> token ID for routing responses
    tcp_pending: HashMap<SocketAddr, usize>,
}

impl Worker {
    pub fn new(
        worker_id: usize,
        args: Args,
        responder: ResponseHandler,
        clock: ClockSource,
        metrics_channel: Sender<WorkerMetrics>,
        metrics_interval: Duration,
        has_tcp: bool,
    ) -> Self {
        let batch_size = args.batch_size as usize;
        let now = clock.epoch_seconds();

        Self {
            worker_id,
            clock,
            metrics_channel,
            net_handler: NetworkHandler::new(batch_size),
            tcp_handler: if has_tcp {
                Some(TcpNetworkHandler::new())
            } else {
                None
            },
            req_handler: RequestHandler::new(responder),
            key_replacement_interval: args.rotation_interval(),
            metrics_publish_interval: metrics_interval,
            next_key_replacement: now,
            next_metrics_publication: now + metrics_interval.as_secs(),
            tcp_pending: HashMap::new(),
        }
    }

    pub fn run(
        &mut self,
        mut udp_sock: MioUdpSocket,
        mut tcp_listener: Option<TcpListener>,
        keep_running: &AtomicBool,
    ) {
        let mut poll = Poll::new().expect("failed to create poll");

        poll.registry()
            .register(&mut udp_sock, UDP_TOKEN, mio::Interest::READABLE)
            .expect("failed to register UDP socket");

        if let Some(listener) = &mut tcp_listener {
            poll.registry()
                .register(listener, TCP_LISTENER_TOKEN, mio::Interest::READABLE)
                .expect("failed to register TCP listener");
        }

        let mut events = Events::with_capacity(1024);
        let poll_duration = Duration::from_millis(350);

        while keep_running.load(Relaxed) {
            let now = self.clock.epoch_seconds();

            if now >= self.next_metrics_publication {
                self.publish_metrics();
            }

            if now >= self.next_key_replacement {
                self.replace_online_key();
            }

            if poll.poll(&mut events, Some(poll_duration)).is_err() {
                self.net_handler.record_failed_poll();
            }

            for event in &events {
                match event.token() {
                    UDP_TOKEN => loop {
                        let collect_result = self.collect_udp_requests(&mut udp_sock);

                        self.send_responses(&mut udp_sock, &poll);

                        if collect_result == Empty {
                            break;
                        }
                    },
                    TCP_LISTENER_TOKEN => {
                        if let Some(listener) = &tcp_listener
                            && let Some(tcp) = &mut self.tcp_handler
                        {
                            tcp.accept_connections(listener, &poll);
                        }
                    }
                    token => {
                        let token_id = token.0;
                        if let Some(tcp) = &mut self.tcp_handler
                            && tcp.is_tcp_client(token_id)
                            && let Some((mut buf, addr)) = tcp.try_read_request(token_id, &poll)
                        {
                            self.tcp_pending.insert(addr, token_id);
                            self.req_handler.collect_request(&mut buf, addr);
                            self.send_responses(&mut udp_sock, &poll);
                        }
                    }
                }
            }
        }
    }

    fn send_responses(&mut self, udp_sock: &mut MioUdpSocket, poll: &Poll) {
        let tcp_pending = &mut self.tcp_pending;
        let tcp_handler = &mut self.tcp_handler;
        let net_handler = &mut self.net_handler;

        self.req_handler.generate_responses(|addr, bytes| {
            if let Some(token_id) = tcp_pending.remove(&addr) {
                if let Some(tcp) = tcp_handler {
                    tcp.send_response(token_id, bytes, poll);
                }
            } else {
                net_handler.send_response(udp_sock, bytes, addr);
            }
        });
    }

    fn collect_udp_requests(&mut self, sock: &mut MioUdpSocket) -> CollectResult {
        self.net_handler
            .collect_requests(sock, |request_bytes, src_addr| {
                self.req_handler.collect_request(request_bytes, src_addr);
            })
    }

    fn replace_online_key(&mut self) {
        self.req_handler.replace_online_key();

        info!(
            "worker-{}, online key {:?}",
            self.worker_id,
            self.req_handler.public_key()
        );

        // jitter so that all worker threads don't thundering herd and replace their
        // keys at the same time, stalling all responses
        let jitter = fastrand::u8(0..u8::MAX) as u64;
        self.next_key_replacement += self.key_replacement_interval.as_secs() - jitter;
    }

    fn publish_metrics(&mut self) {
        let snapshot = WorkerMetrics {
            worker_id: self.worker_id,
            network: self.net_handler.metrics(),
            request: self.req_handler.metrics(),
            response: self.req_handler.response_metrics(),
        };

        // Send snapshot, ignoring if channel is full
        let _ = self.metrics_channel.try_send(snapshot);

        // Reset metrics after sending
        self.net_handler.reset_metrics();
        self.req_handler.reset_metrics();

        // Schedule next publication
        let now = self.clock.epoch_seconds();
        self.next_metrics_publication = now + self.metrics_publish_interval.as_secs();
    }
}
