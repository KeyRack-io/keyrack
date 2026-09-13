// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Actual kernel pipes exercise the same sink used by the subprocess harness.
use super::*;
use rustix::fs::{fcntl_getfl, OFlags};
use rustix::io::{fcntl_getfd, FdFlags};

#[test]
fn supervisor_pipe_rejects_files_sockets_and_read_ends() {
    let file = tempfile::tempfile().unwrap();
    assert!(matches!(Pipe::new(file.into()), Err(Error::Context)));
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(matches!(Pipe::new(socket.into()), Err(Error::Context)));
    let (read, _write) = rustix::pipe::pipe().unwrap();
    assert!(matches!(Pipe::new(read), Err(Error::Context)));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bidirectional-fifo");
    // rustix's mkfifoat is unavailable on macOS; the POSIX utility exercises
    // the same named-FIFO case on both supported test hosts without unsafe FFI.
    assert!(std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&path)
        .status()
        .expect("POSIX mkfifo is required for the FIFO admission test")
        .success());
    let read_write = rustix::fs::open(
        &path,
        OFlags::RDWR | OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    assert!(matches!(Pipe::new(read_write), Err(Error::Context)));
}

#[test]
fn supervisor_pipe_enforces_nonblocking_atomic_records() {
    let (read, write) = rustix::pipe::pipe().unwrap();
    let mut pipe = Pipe::new(write).unwrap();
    assert!(fcntl_getfl(&pipe.0).unwrap().contains(OFlags::NONBLOCK));
    assert!(fcntl_getfd(&pipe.0).unwrap().contains(FdFlags::CLOEXEC));
    assert_eq!(
        pipe.write(&[]).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        pipe.write(&[0; ATOMIC + 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let record = [7; ATOMIC];
    assert!(atomic(&mut pipe, &record).unwrap());
    let mut received = [0; ATOMIC];
    assert_eq!(rustix::io::read(&read, &mut received).unwrap(), ATOMIC);
    assert_eq!(received, record);
}

#[test]
fn full_supervisor_pipe_fences_before_a_capsule_can_commit() {
    let (read, write) = rustix::pipe::pipe().unwrap();
    let mut pipe = Pipe::new(write).unwrap();
    let mut filled = 0;
    while atomic(&mut pipe, &[0; ATOMIC]).unwrap() {
        filled += ATOMIC;
        assert!(filled <= 16 * 1024 * 1024, "pipe failed to reach its bound");
    }
    let (_, delivery, prepared) = fixture();
    delivery.enqueue(prepared).unwrap();
    let id = delivery.state.lock().unwrap().next;
    assert_eq!(delivery.release(id, &mut pipe).unwrap(), Release::Pending);
    delivery.fence("instance", 2, || Ok(())).unwrap();
    assert_eq!(
        delivery.release(id, &mut pipe).unwrap(),
        Release::Suppressed
    );
    drop(pipe);
    let mut buffer = [0; 4096];
    let mut drained = 0;
    loop {
        let size = rustix::io::read(&read, &mut buffer).unwrap();
        if size == 0 {
            break;
        }
        assert!(buffer[..size].iter().all(|byte| *byte == 0));
        drained += size;
    }
    assert_eq!(drained, filled); // No capsule bytes entered the pipe.
}

#[test]
fn stopping_writer_closes_its_owned_supervisor_pipe() {
    let (read, write) = rustix::pipe::pipe().unwrap();
    let (_, delivery, _) = fixture();
    let delivery = Arc::new(delivery);
    let thread = spawn_on_pipe(delivery.clone(), write).unwrap();
    delivery.stop();
    thread.join().unwrap();
    let mut byte = [0];
    assert_eq!(rustix::io::read(&read, &mut byte).unwrap(), 0);
}

#[test]
fn lost_supervisor_reader_latches_fault_without_successful_fence_evidence() {
    let (read, write) = rustix::pipe::pipe().unwrap();
    let mut pipe = Pipe::new(write).unwrap();
    drop(read);
    let (_, delivery, prepared) = fixture();
    delivery.enqueue(prepared).unwrap();
    let id = delivery.state.lock().unwrap().next;
    assert!(delivery.release(id, &mut pipe).is_err());
    assert_eq!(
        delivery.state.lock().unwrap().outcomes[&id].phase,
        Release::Indeterminate
    );
    assert!(delivery.stopped());
    assert!(delivery.fence("instance", 2, || Ok(())).is_err());
    assert!(delivery.state.lock().unwrap().permits.is_empty());
}
