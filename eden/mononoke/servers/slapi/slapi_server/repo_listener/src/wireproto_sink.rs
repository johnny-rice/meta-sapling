/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use chrono::DateTime;
use chrono::Utc;
use futures::sink::Sink;
use futures::task::Context;
use futures::task::Poll;
use pin_project::pin_project;
use sshrelay::IoStream;
use sshrelay::SshMsg;

#[pin_project]
pub struct WireprotoSink<T> {
    #[pin]
    inner: T,
    // Shared with the wireproto idle watchdog in
    // connection_acceptor::handle_wireproto. The lock is held only briefly to
    // record stat updates / read timestamps — never across an `.await`.
    pub data: Arc<Mutex<WireprotoSinkData>>,
}

impl<T> WireprotoSink<T> {
    pub fn with_shared_data(inner: T, data: Arc<Mutex<WireprotoSinkData>>) -> Self {
        Self { inner, data }
    }
}

impl<T> Sink<SshMsg> for WireprotoSink<T>
where
    T: Sink<SshMsg>,
{
    type Error = <T as Sink<SshMsg>>::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        let ret = this.inner.poll_ready(cx);
        this.data
            .lock()
            .expect("WireprotoSinkData lock poisoned")
            .peek_io(&ret);
        ret
    }

    fn start_send(self: Pin<&mut Self>, item: SshMsg) -> Result<(), Self::Error> {
        let this = self.project();
        this.data
            .lock()
            .expect("WireprotoSinkData lock poisoned")
            .peek_message(&item);
        this.inner.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        let ret = this.inner.poll_flush(cx);
        let mut guard = this.data.lock().expect("WireprotoSinkData lock poisoned");
        guard.peek_io(&ret);
        guard.peek_flush(&ret);
        ret
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        let ret = this.inner.poll_close(cx);
        this.data
            .lock()
            .expect("WireprotoSinkData lock poisoned")
            .peek_io(&ret);
        ret
    }
}

pub struct WireprotoSinkData {
    pub last_successful_flush: Option<DateTime<Utc>>,
    pub last_successful_io: Option<DateTime<Utc>>,
    pub last_failed_io: Option<DateTime<Utc>>,
    pub stdout: ChannelData,
    pub stderr: ChannelData,
}

impl WireprotoSinkData {
    pub fn new() -> Self {
        Self {
            last_successful_flush: None,
            last_successful_io: None,
            last_failed_io: None,
            stdout: ChannelData::default(),
            stderr: ChannelData::default(),
        }
    }

    fn peek_message(&mut self, item: &SshMsg) {
        match item.stream_ref() {
            IoStream::Stdout => self.stdout.peek(item.as_ref()),
            IoStream::Stderr => self.stderr.peek(item.as_ref()),
            IoStream::Stdin => {}
        }
    }

    fn peek_io<E>(&mut self, res: &Poll<Result<(), E>>) {
        match res {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.last_successful_io = Some(Utc::now());
            }
            Poll::Ready(Err(..)) => {
                self.last_failed_io = Some(Utc::now());
            }
        }
    }

    fn peek_flush<E>(&mut self, res: &Poll<Result<(), E>>) {
        match res {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.last_successful_flush = Some(Utc::now());
            }
            Poll::Ready(Err(..)) => {
                // No need for this it's already tracked in peek_io.
            }
        }
    }
}

#[derive(Default)]
pub struct ChannelData {
    pub messages: u64,
    pub bytes: u64,
}

impl ChannelData {
    pub fn peek(&mut self, data: &[u8]) {
        let len: u64 = data
            .len()
            .try_into()
            .expect("The length of a buffer that exists will fit in a u64");

        self.messages += 1;
        self.bytes += len;
    }
}
