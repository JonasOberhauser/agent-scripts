//! `stack_testkit_only`: in TEST code, the file-backed parts of a
//! gatekeeper stack (rendezvous sockets, mounts, shared-temp-dir
//! scratch paths) may only be created through the testkit — never
//! hand-rolled (issue #63). Every hand-rolled copy is another harness
//! generation waiting to drift, and the fixed-name ones collide under
//! parallel test binaries.
//!
//! Used as a `RUSTC_WRAPPER` (the architecture servyi/lints'
//! unsafe-scope driver established): cargo invokes this binary in
//! place of rustc; it registers one extra late lint and otherwise
//! behaves exactly like the compiler it ships with (same pinned
//! nightly toolchain).
//!
//! What it flags, in test contexts only:
//!   - `UnixListener::bind` — every rendezvous socket (oracle,
//!     control, mock-fuse) is kit-minted inside a per-stack root;
//!   - `std::env::temp_dir()` — fixed names under the shared temp
//!     dir collide across parallel test binaries; the kit provides
//!     per-stack scratch();
//!   - `fuser::mount2` — mounts are the kit's `Driver::RealMount`.
//!
//! "Test context" = anything in a `tests/` source file, plus
//! `#[test]`/`#[ignore]`-annotated items and what they (lexically)
//! contain. The `gatekeeper_testkit` crate is exempt wholesale. The
//! escape hatch is `#[allow(stack_testkit_only)]` — every use is a
//! reviewable migration marker (the count should fall to zero as #63
//! lands, then the CI flag flips to deny).
#![feature(rustc_private)]
#![allow(internal_features)]
extern crate rustc_ast;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_hir as hir;
use rustc_hir::intravisit::{self, Visitor};
use rustc_hir::{ExprKind, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext, declare_lint, impl_lint_pass};
use rustc_span::def_id::{DefId, LOCAL_CRATE};
use rustc_span::{Span, sym};

declare_lint! {
    /// File-backed stack parts in tests must come from the testkit.
    pub STACK_TESTKIT_ONLY,
    Warn,
    "tests must create sockets/mounts/shared-temp scratch through the gatekeeper testkit, not by hand"
}

pub struct StackTestkitOnly;

impl_lint_pass!(StackTestkitOnly => [STACK_TESTKIT_ONLY]);

/// The kit crate: its own code (and only its own) may mint these.
const KIT_CRATE: &str = "gatekeeper_testkit";

/// Callee def-path suffixes forbidden in test contexts, with the
/// remediation surfaced in the diagnostic.
const FORBIDDEN: &[(&str, &str)] = &[
    ("UnixListener::bind", "the kit mints rendezvous sockets inside per-stack roots"),
    ("std::env::temp_dir", "shared-temp paths collide across parallel test binaries; use the kit's scratch()"),
    ("fuser::mount2", "mounts are the kit's Driver::RealMount"),
];

struct LintCallbacks;

impl rustc_driver::Callbacks for LintCallbacks {
    fn config(&mut self, config: &mut rustc_interface::Config) {
        let previous = config.register_lints.take();
        config.register_lints = Some(Box::new(move |sess, store| {
            if let Some(prev) = &previous {
                prev(sess, store);
            }
            store.register_lints(&[STACK_TESTKIT_ONLY]);
            store.register_late_lint_pass(Box::new(|_| Box::new(StackTestkitOnly)));
        }));
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // cargo probes the wrapper (`--print=file-names` et al.): delegate
    // to the wrapped compiler verbatim.
    let rustc_path = if std::env::var_os("RUSTC_WRAPPER").is_some()
        && args
            .first()
            .is_some_and(|a| a.ends_with("rustc") || a.ends_with("clippy-driver"))
    {
        Some(args.remove(0))
    } else {
        None
    };
    if rustc_path.is_some() && args.iter().any(|a| a == "--print=file-names") {
        let real = rustc_path.as_deref().unwrap();
        let status = std::process::Command::new(real)
            .args(&args)
            .status()
            .unwrap_or_else(|e| {
                eprintln!("stack-lint: probe delegation failed: {e}");
                std::process::exit(101);
            });
        std::process::exit(status.code().unwrap_or(101));
    }

    let mut at_args: Vec<String> = vec!["rustc".to_string()];
    at_args.extend(args);
    let early_dcx = rustc_session::EarlyDiagCtxt::new(
        rustc_session::config::ErrorOutputType::default(),
    );
    rustc_driver::init_rustc_env_logger(&early_dcx);
    let mut callbacks = LintCallbacks;
    let exit_code = rustc_driver::catch_fatal_errors(move || {
        rustc_driver::run_compiler(&at_args, &mut callbacks);
    })
    .map(|()| 0)
    .unwrap_or(101);
    std::process::exit(exit_code);
}

/// The current crate is the kit (exempt wholesale).
fn kit_crate(cx: &LateContext<'_>) -> bool {
    cx.tcx.crate_name(LOCAL_CRATE).as_str() == KIT_CRATE
}

/// Is this source position inside a `tests/` integration file?
fn in_tests_file(cx: &LateContext<'_>, span: Span) -> bool {
    let name = cx.sess().source_map().span_to_filename(span);
    std::format!("{name:?}").contains("/tests/")
}

impl<'tcx> LateLintPass<'tcx> for StackTestkitOnly {
    /// The expression hook: `LateContext::typeck_results` is only
    /// legal inside body contexts, which is exactly where check_expr
    /// runs. Test context = the expression's source file lives under
    /// `tests/` (integration harnesses — where every hand-rolled
    /// stack lives today). `#[test]`-annotated items in src/ files
    /// are a future gate; unit tests there create no file-backed
    /// parts today.
    fn check_expr(&mut self, cx: &LateContext<'tcx>, e: &'tcx hir::Expr<'tcx>) {
        if kit_crate(cx) || !in_tests_file(cx, e.span) {
            return;
        }
        if let ExprKind::Call(callee, _) = e.kind
            && let ExprKind::Path(qpath) = callee.kind
            && let hir::def::Res::Def(_, def) =
                cx.typeck_results().qpath_res(&qpath, callee.hir_id)
        {
            check_def(cx, def, e.span);
        }
        if let ExprKind::MethodCall(..) = e.kind
            && let Some(def) = cx.typeck_results().type_dependent_def_id(e.hir_id)
        {
            check_def(cx, def, e.span);
        }
    }
}

fn check_def(cx: &LateContext<'_>, def: DefId, span: Span) {
    let path = cx.tcx.def_path_str(def);
    if std::env::var_os("STACK_LINT_DEBUG").is_some() {
        eprintln!("stack-lint: resolved call in test ctx: {path}");
    }
    for (suffix, why) in FORBIDDEN {
        if path.ends_with(suffix) {
            cx.opt_span_lint(
                STACK_TESTKIT_ONLY,
                Some(span),
                rustc_errors::DiagDecorator(|diag| {
                    diag.note(format!(
                        "`{path}` hand-creates a file-backed stack part — {why} (issue #63)"
                    ));
                }),
            );
            return;
        }
    }
}

