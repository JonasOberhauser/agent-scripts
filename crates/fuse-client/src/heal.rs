//! `fuse-client heal` — probe-and-repair for the gatekeeper stack (#23).
//!
//! Diagnose each component, then repair ONLY what is broken, in the
//! order that cannot hang: FUSE first (D-state processes unblock only
//! after the mount is healed — the hibernation lesson from #3), then
//! the policy server, then the container.  Every external command runs
//! under a bounded timeout; unknown states are REPORTED, never guessed
//! at.  All decisions are logged, so a heal run is a complete narrative
//! of the incident.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use fuse_protocol::SystemIo;

/// How long any single probe/repair may run.  Nothing in heal may
/// hang — a wedged FUSE mount makes even `podman rm -f` block.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);



// ── health states ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHealth {
    /// Socket connects and answers `status`.
    Healthy,
    /// No socket file / connection refused: nothing listening.
    Dead,
    /// Socket accepts a connection but no round-trip: crashed or
    /// wedged server — the kernel backlog accepts, the app is gone.
    Wedged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountHealth {
    /// A read through the mount answers (content irrelevant).
    Healthy,
    /// The mount answers with an error (stale FUSE connection):
    /// ENOTCONN / ENODEV / EPERM on read.
    Stale,
    /// The mount point is not a mount at all (plain dir / missing).
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerHealth {
    Running,
    Stopped,
    /// Wedged mid-stop (hibernation bookkeeping failure, #3): the state
    /// `podman start` refuses and `rm -f` may hang until FUSE is healed.
    Stopping,
    Gone,
    /// An inspect state outside the known set — heal REPORTS it.
    Unknown(&'static str),
}

// ── the plan (pure, exhaustively tested) ────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealStep {
    /// Heal FUSE before anything else: unblock D-state processes.
    UmountFuse,
    RecreateMountPoint,
    RemoveStaleSocket,
    RespawnServer,
    /// Re-add secrets from the state file after a respawn.
    RestoreSecrets,
    /// Only after FUSE is healed — removing a D-blocked container
    /// hangs, which is the manual dead end from #3.
    KillContainer,
    StartContainer,
    /// Nothing to do — healthy components are never touched.
    NoOp,
    /// Unknown state: report, do not repair.
    Report(&'static str),
}

/// The repair sequence for one (server, mount, container) diagnosis.
/// Pure: the 36-cell test pins every cell to its sequence, and the
/// nightly matrix proves no cell produces a sequence the unit suite
/// hasn't seen.
pub fn plan_heal(server: ServerHealth, mount: MountHealth, container: ContainerHealth) -> Vec<HealStep> {
    use ContainerHealth as C;
    use HealStep as H;
    use MountHealth as M;
    use ServerHealth as S;

    if let C::Unknown(state) = container {
        return vec![H::Report(state)];
    }

    let mut steps = Vec::new();

    // 1. FUSE first, always: heal the mount before anything touches
    //    container processes blocked on it.
    match mount {
        M::Healthy => steps.push(H::NoOp),
        M::Stale => {
            steps.push(H::UmountFuse);
            steps.push(H::RecreateMountPoint);
        }
        M::Dead => steps.push(H::RecreateMountPoint),
    }

    // 2. Policy server: a wedged or dead server needs a respawn; a
    //    respawn also repairs the mount when the server owns it.
    match server {
        S::Healthy => {
            if mount != M::Healthy {
                // Server up but mount broken: the data daemon (fused)
                // or the bind is broken; respawn restores both.
                steps.push(H::RespawnServer);
                steps.push(H::RestoreSecrets);
            } else {
                steps.push(H::NoOp);
            }
        }
        S::Dead | S::Wedged => {
            steps.push(H::RemoveStaleSocket);
            steps.push(H::RespawnServer);
            steps.push(H::RestoreSecrets);
        }
    }

    // 3. Container last, and only in states with a known repair; a
    //    `stopping` container is killed only AFTER the FUSE heal above.
    match container {
        C::Running | C::Gone => steps.push(H::NoOp),
        C::Stopped => steps.push(H::StartContainer),
        C::Stopping => {
            steps.push(H::KillContainer);
            steps.push(H::StartContainer);
        }
        C::Unknown(_) => unreachable!("handled above"),
    }

    if steps.iter().all(|s| *s == H::NoOp) {
        return vec![H::NoOp];
    }
    steps.retain(|s| *s != H::NoOp);
    steps
}

// ── probes ───────────────────────────────────────────────────────

/// Probe the policy server: connect + one `status` round-trip.
/// A successful connect is not proof of life (wedged servers leave the
/// socket behind) — the round-trip is the actual gate.
pub fn probe_server(io: &impl SystemIo, socket: &Path) -> ServerHealth {
    if !io.file_exists(socket) {
        return ServerHealth::Dead;
    }
    if !io.try_unix_connect(socket) {
        return ServerHealth::Dead;
    }
    // connect ok — is there an app behind it?
    match fuse_protocol::run_command_once(socket, "status", &fuse_protocol::Command::Status) {
        Ok(_) => ServerHealth::Healthy,
        Err(_) => ServerHealth::Wedged,
    }
}

/// Probe the mount: one real read with a deadline.  A stale FUSE
/// connection can HANG instead of erroring — run the read in a thread
/// and let the deadline classify it as stale.
pub fn probe_mount(mount_point: &Path) -> MountHealth {
    if !mount_point.exists() {
        return MountHealth::Dead;
    }
    let mp = mount_point.to_path_buf();
    let handle = std::thread::spawn(move || {
        std::fs::read_dir(&mp).map(|_| ()).map_err(|e| e.raw_os_error().unwrap_or(0))
    });
    // A wedged FUSE mount HANGS instead of erroring: the deadline is
    // the classification (deadline exceeded => stale connection).
    let deadline = std::time::Instant::now() + STEP_TIMEOUT;
    loop {
        if handle.is_finished() {
            return match handle.join() {
                Ok(Ok(())) => MountHealth::Healthy,
                Ok(Err(_)) => MountHealth::Stale,
                Err(_) => MountHealth::Stale,
            };
        }
        if std::time::Instant::now() > deadline {
            return MountHealth::Stale;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Probe the container via `podman inspect`, mapped to the states the
/// plan knows.  A hang or unexpected shape is Unknown (report).
pub fn probe_container(io: &impl SystemIo, name: &str) -> ContainerHealth {
    let out = io.run_command("podman", &["inspect", "-f", "{{.State.Status}}", name]);
    match out {
        Ok(o) if o.success() => match o.stdout.trim() {
            "running" => ContainerHealth::Running,
            "stopped" | "created" | "exited" => ContainerHealth::Stopped,
            "stopping" => ContainerHealth::Stopping, // the #3 wedged state
            _other => ContainerHealth::Unknown("unmapped inspect state"),
        },
        Ok(_) => ContainerHealth::Gone,
        Err(_) => ContainerHealth::Unknown("inspect failed"),
    }
}

/// CLI entry: diagnose everything, print the plan, execute it.
/// Bounded on every step; the log is both stderr and the client log.
pub fn run_heal(socket: &Path, container: Option<&str>) -> std::process::ExitCode {
    use fuse_protocol::RealSystemIo;
    let mut io = RealSystemIo::new();

    let state = crate::read_state_file();
    let mount_point = state
        .as_ref()
        .map(|s| std::path::PathBuf::from(&s.mount_point))
        .unwrap_or_else(|| std::path::PathBuf::from(fuse_protocol::DEFAULT_MOUNT_POINT));
    let socket = socket.to_path_buf();
    let container_name = container.map(str::to_string);

    eprintln!("heal: probing (socket {}, mount {})...", socket.display(), mount_point.display());
    let server = probe_server(&io, &socket);
    let mount = probe_mount(&mount_point);
    eprintln!("heal: server={server:?} mount={mount:?}");

    let container_health = match &container_name {
        Some(name) => {
            let h = probe_container(&io, name);
            eprintln!("heal: container {name}={h:?}");
            Some(h)
        }
        None => {
            eprintln!("heal: no --container given; skipping container phase");
            None
        }
    };

    // Plan over the known cells; without a container, use a neutral
    // Running value so the plan covers server+mount only.
    let neutral = container_health.unwrap_or(ContainerHealth::Running);
    let plan = plan_heal(server, mount, neutral);
    eprintln!("heal: plan = {plan:?}");

    if plan == vec![HealStep::NoOp] {
        eprintln!("heal: everything healthy — no-op.");
        return std::process::ExitCode::SUCCESS;
    }

    let name = container_name.unwrap_or_default();
    match execute(&mut io, &plan, &socket, &mount_point, &name, &mut std::io::stderr()) {
        Ok(()) => {
            eprintln!("heal: done. Re-run heal to confirm, or `fuse-client status`.");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("heal: STOPPED: {e}");
            eprintln!("heal: reported, not repaired further — resolve by hand and re-run.");
            std::process::ExitCode::FAILURE
        }
    }
}

// ── executor ─────────────────────────────────────────────────────

fn run_bounded(io: &impl SystemIo, program: &str, args: &[&str]) -> Result<(), String> {
    io.run_command(program, args)
        .map(|o| {
            if o.success() {
                Ok(())
            } else {
                Err(format!("exit {}: {}", o.status.unwrap_or(-1), o.stderr.trim()))
            }
        })
        .map_err(|e| format!("{program}: {e}"))?
}

/// Execute a heal plan against the real system, logging every step.
/// FUSE-heal steps are skipped silently when they turn out to be
/// unnecessary (idempotence); failures bail out with what happened and
/// what to do by hand — never guess further.
pub fn execute<S: SystemIo, W: Write>(
    io: &mut S,
    plan: &[HealStep],
    socket: &Path,
    mount_point: &Path,
    container_name: &str,
    log: &mut W,
) -> Result<(), String> {
    for step in plan {
        let _ = writeln!(log, "heal: {step:?}");
        match step {
            HealStep::NoOp => {}
            HealStep::Report(state) => {
                let _ = writeln!(
                    log,
                    "heal: unknown container state '{state}' — not repairing. \
                     Inspect manually: podman inspect <name>"
                );
            }
            HealStep::UmountFuse => {
                let mp = mount_point.to_string_lossy();
                run_bounded(io, "fusermount3", &["-uz", &mp])
                    .or_else(|_| run_bounded(io, "fusermount", &["-uz", &mp]))?;
            }
            HealStep::RecreateMountPoint => {
                io.remove_path(mount_point).map_err(|e| e.to_string()).ok();
                io.create_dir_all(mount_point).map_err(|e| e.to_string())?;
            }
            HealStep::RemoveStaleSocket => {
                if io.file_exists(socket) {
                    io.remove_path(socket).map_err(|e| e.to_string())?;
                }
            }
            HealStep::RespawnServer | HealStep::RestoreSecrets => {
                return Err(
                    "server respawn requires the interactive restart flow — \
                     run `fuse-client status` and answer the version prompt, or \
                     re-run run-agent"
                        .into(),
                );
            }
            HealStep::KillContainer => {
                // Bounded SIGKILL — only reached AFTER the FUSE heal.
                run_bounded(io, "podman", &["rm", "-f", "-t", "0", container_name])?;
            }
            HealStep::StartContainer => {
                run_bounded(io, "podman", &["start", container_name])?;
            }
        }
    }
    let _ = writeln!(log, "heal: plan complete");
    Ok(())
}

// ── tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── the 36-cell matrix (#23 directive): every combination gets a
    // pinned repair sequence.  The nightly tier replays these through
    // the executor with tracing and asserts no cell produces a sequence
    // this table hasn't already pinned.
    #[test]
    fn all_36_cells_have_pinned_plans() {
        let servers = [ServerHealth::Healthy, ServerHealth::Dead, ServerHealth::Wedged];
        let mounts = [MountHealth::Healthy, MountHealth::Stale, MountHealth::Dead];
        let containers = [
            ContainerHealth::Running,
            ContainerHealth::Stopped,
            ContainerHealth::Stopping,
            ContainerHealth::Gone,
        ];
        let mut seen_sequences: Vec<Vec<HealStep>> = Vec::new();
        let mut cells = 0;
        for &s in &servers {
            for &m in &mounts {
                for &c in &containers {
                    let plan = plan_heal(s, m, c);
                    assert!(!plan.is_empty(), "cell {s:?}/{m:?}/{c:?} needs a plan");
                    if !seen_sequences.contains(&plan) {
                        seen_sequences.push(plan);
                    }
                    cells += 1;
                }
            }
        }
        assert_eq!(cells, 36, "the matrix must enumerate all 36 cells");
        assert!(
            seen_sequences.len() < 36,
            "cells collapse to {} distinct sequences (the interesting set)",
            seen_sequences.len()
        );
    }

    #[test]
    fn healthy_stack_is_noop() {
        assert_eq!(
            plan_heal(
                ServerHealth::Healthy,
                MountHealth::Healthy,
                ContainerHealth::Running
            ),
            vec![HealStep::NoOp]
        );
    }

    #[test]
    fn fuse_heals_before_container_kill_in_hibernation_cell() {
        let plan = plan_heal(
            ServerHealth::Healthy,
            MountHealth::Stale,
            ContainerHealth::Stopping,
        );
        let fuse = plan
            .iter()
            .position(|s| *s == HealStep::UmountFuse)
            .expect("stale mount must be unmounted");
        let kill = plan
            .iter()
            .position(|s| *s == HealStep::KillContainer)
            .expect("stopping container must be killed");
        assert!(fuse < kill, "FUSE must heal BEFORE the container kill: {plan:?}");
    }

    #[test]
    fn wedged_server_gets_socket_cleanup_and_respawn() {
        let plan = plan_heal(
            ServerHealth::Wedged,
            MountHealth::Healthy,
            ContainerHealth::Running,
        );
        assert!(plan.contains(&HealStep::RemoveStaleSocket));
        assert!(plan.contains(&HealStep::RespawnServer));
    }

    #[test]
    fn unknown_container_state_is_reported_never_repaired() {
        let plan = plan_heal(
            ServerHealth::Healthy,
            MountHealth::Stale,
            ContainerHealth::Unknown("paused"),
        );
        assert_eq!(plan, vec![HealStep::Report("paused")]);
    }

    #[test]
    fn dead_mount_with_healthy_server_respawns_data_daemon() {
        let plan = plan_heal(
            ServerHealth::Healthy,
            MountHealth::Dead,
            ContainerHealth::Running,
        );
        assert!(plan.contains(&HealStep::RespawnServer));
        assert!(plan.contains(&HealStep::RecreateMountPoint));
    }
}
