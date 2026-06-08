//! `huddle app` — build the desktop GUI from source and install it where the
//! OS expects desktop apps, then launch it.
//!
//! - **macOS**: assembles a `Huddle.app` bundle in `/Applications` (falling back
//!   to `~/Applications` when the system folder isn't writable) and `open`s it.
//! - **Linux** (Ubuntu / Debian / Kali / …): copies the binary to `~/.local/bin`
//!   and writes a `~/.local/share/applications/huddle.desktop` launcher so it
//!   shows up in the app menu, then runs it.
//! - **Windows**: copies `huddle-gui.exe` into `%LOCALAPPDATA%\Programs\Huddle`,
//!   adds a best-effort Start-Menu shortcut, and launches it.
//!
//! The build itself is just `cargo build --release -p huddle-gui`, which is
//! portable, so the only platform-specific work is the install + launch step.
//! Everything here is plain `std` (runtime-branched on `env::consts::OS`), so
//! all branches compile on every platform.
//!
//! huddle 1.2.2: once the app is installed out to its OS location, `huddle app`
//! runs `cargo clean` to reclaim the multi-GB release build cache (the binary
//! is already copied elsewhere, so this is safe). Set `HUDDLE_KEEP_BUILD=1` to
//! keep the cache.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

/// Entry point for the `huddle app` subcommand.
pub fn run() -> Result<()> {
    let workspace = find_workspace().ok_or_else(|| {
        anyhow!(
            "couldn't find the huddle source checkout to build from.\n\
             `huddle app` builds the GUI from source — run it from inside a \
             clone of the repo, set HUDDLE_SRC=/path/to/huddle, or install the \
             GUI directly with `cargo install huddle-gui`."
        )
    })?;
    println!("huddle source: {}", workspace.display());

    build_gui(&workspace)?;

    let built = workspace
        .join("target")
        .join("release")
        .join(format!("huddle-gui{}", std::env::consts::EXE_SUFFIX));
    if !built.exists() {
        bail!(
            "build reported success but the binary is missing at {}",
            built.display()
        );
    }

    // Whether the app was copied OUT to an OS location (so the build cache is
    // now safe to delete) vs. launched in place from `target/release`.
    let installed_out = match std::env::consts::OS {
        "macos" => {
            let app = install_macos(&built)?;
            println!("installed {}", app.display());
            launch_macos(&app)?;
            true
        }
        "linux" => {
            let dest = install_linux(&built)?;
            launch_detached(&dest)?;
            true
        }
        "windows" => {
            let dest = install_windows(&built)?;
            launch_detached(&dest)?;
            true
        }
        other => {
            eprintln!(
                "note: `huddle app` doesn't know where to install on `{other}` — \
                 launching the freshly built binary in place."
            );
            launch_detached(&built)?;
            false
        }
    };

    // huddle 1.2.2: reclaim the (multi-GB) release build cache now that the app
    // lives elsewhere. Skipped when the binary runs in place (we'd delete what
    // we just launched) or when HUDDLE_KEEP_BUILD is set — e.g. a dev iterating
    // from the clone who doesn't want to rebuild from scratch next time.
    if installed_out && std::env::var_os("HUDDLE_KEEP_BUILD").is_none() {
        clean_build_cache(&workspace);
    }
    Ok(())
}

/// huddle 1.2.2: `cargo clean` the workspace to reclaim the release build cache
/// after a successful `huddle app` install. Best-effort — a failure here never
/// fails the install, since the app is already in place. Set `HUDDLE_KEEP_BUILD=1`
/// to keep the cache.
fn clean_build_cache(workspace: &Path) {
    println!(
        "reclaiming the build cache (cargo clean) — set HUDDLE_KEEP_BUILD=1 to keep it next time…"
    );
    match Command::new(cargo_bin())
        .args(["clean"])
        .current_dir(workspace)
        .status()
    {
        Ok(s) if s.success() => println!("build cache cleared."),
        Ok(s) => eprintln!(
            "note: `cargo clean` exited {:?}; the build cache was left in place.",
            s.code()
        ),
        Err(e) => eprintln!(
            "note: couldn't run `cargo clean` ({e}); the build cache was left in place."
        ),
    }
}

/// Run `cargo build --release -p huddle-gui` in the workspace, streaming output.
fn build_gui(workspace: &Path) -> Result<()> {
    println!("building huddle-gui (release) — the first build can take a few minutes…");
    let status = Command::new(cargo_bin())
        .args(["build", "--release", "-p", "huddle-gui"])
        .current_dir(workspace)
        .status()
        .context("failed to launch `cargo` — is the Rust toolchain on your PATH?")?;
    if !status.success() {
        bail!("`cargo build -p huddle-gui` failed (exit {:?})", status.code());
    }
    Ok(())
}

/// Honour `$CARGO` (set when we're invoked via cargo) but fall back to `cargo`.
fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// Find the workspace root to build from: an explicit `HUDDLE_SRC`, then walking
/// up from the current directory, then the source tree this binary was built
/// from (`CARGO_MANIFEST_DIR` is `…/crates/huddle`, so the workspace is two up).
fn find_workspace() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HUDDLE_SRC") {
        let p = PathBuf::from(p);
        if is_workspace(&p) {
            return Some(p);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir: Option<&Path> = Some(cwd.as_path());
        while let Some(d) = dir {
            if is_workspace(d) {
                return Some(d.to_path_buf());
            }
            dir = d.parent();
        }
    }
    let built_from = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent);
    if let Some(ws) = built_from {
        if is_workspace(ws) {
            return Some(ws.to_path_buf());
        }
    }
    // huddle 1.3.2: last-resort search of common clone locations under $HOME.
    // The `CARGO_MANIFEST_DIR` fallback above only resolves to a real workspace
    // when this binary was built from a clone (e.g. `cargo install --path`); a
    // binary installed from crates.io (`cargo install huddle`) bakes a registry
    // path that is NOT a workspace, so without this `huddle app` failed for
    // anyone who hadn't cd'd into a clone or set HUDDLE_SRC. Find their checkout.
    if let Some(home) = dirs::home_dir() {
        for rel in [
            "GitHub/huddle",
            "github/huddle",
            "Github/huddle",
            "huddle",
            "src/huddle",
            "code/huddle",
            "Code/huddle",
            "Developer/huddle",
            "dev/huddle",
            "projects/huddle",
            "Projects/huddle",
            "repos/huddle",
            "Documents/huddle",
            "Documents/GitHub/huddle",
        ] {
            let cand = home.join(rel);
            if is_workspace(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// A directory is the huddle workspace if it has a root `Cargo.toml` and the
/// `huddle-gui` crate beneath it.
fn is_workspace(p: &Path) -> bool {
    p.join("Cargo.toml").exists() && p.join("crates/huddle-gui/Cargo.toml").exists()
}

// ---- macOS: /Applications/Huddle.app ----

fn install_macos(bin: &Path) -> Result<PathBuf> {
    // Prefer the system /Applications; fall back to ~/Applications when it isn't
    // writable (no admin rights), which always works for the current user.
    let mut bases: Vec<PathBuf> = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        bases.push(home.join("Applications"));
    }
    let mut last_err: Option<anyhow::Error> = None;
    for base in bases {
        match write_macos_bundle(&base, bin) {
            Ok(app) => return Ok(app),
            Err(e) => {
                eprintln!("  ({} not usable: {e})", base.display());
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no Applications directory available")))
}

fn write_macos_bundle(base: &Path, bin: &Path) -> Result<PathBuf> {
    let app = base.join("Huddle.app");
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    // Replace any existing bundle wholesale so a stale `_CodeSignature` /
    // Resources from a prior install can't linger — a leftover signature that
    // no longer matches the new binary makes Gatekeeper reject the app as
    // "damaged". A running instance keeps its now-unlinked inode, so this is
    // safe even when we're about to relaunch.
    let _ = std::fs::remove_dir_all(&app);
    std::fs::create_dir_all(&macos)
        .with_context(|| format!("create {}", macos.display()))?;
    let dest = macos.join("huddle-gui");
    // Remove any existing binary first — overwriting a running executable fails
    // with "text file busy"; replacing the inode is fine.
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(bin, &dest).with_context(|| format!("copy into {}", dest.display()))?;
    set_executable(&dest)?;
    std::fs::write(contents.join("Info.plist"), macos_info_plist())?;
    let _ = std::fs::write(contents.join("PkgInfo"), "APPL????");
    Ok(app)
}

fn macos_info_plist() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Huddle</string>
    <key>CFBundleDisplayName</key><string>Huddle</string>
    <key>CFBundleExecutable</key><string>huddle-gui</string>
    <key>CFBundleIdentifier</key><string>com.huddle.gui</string>
    <key>CFBundleVersion</key><string>{version}</string>
    <key>CFBundleShortVersionString</key><string>{version}</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>10.15</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
"#
    )
}

fn launch_macos(app: &Path) -> Result<()> {
    println!("launching {}", app.display());
    // `open` hands off to LaunchServices and returns immediately.
    let status = Command::new("open").arg(app).status()?;
    if !status.success() {
        bail!("`open {}` failed", app.display());
    }
    Ok(())
}

// ---- Linux: ~/.local/bin + a .desktop launcher ----

fn install_linux(bin: &Path) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home directory"))?;
    let bindir = home.join(".local/bin");
    std::fs::create_dir_all(&bindir)?;
    let dest = bindir.join("huddle-gui");
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(bin, &dest).with_context(|| format!("copy into {}", dest.display()))?;
    set_executable(&dest)?;

    let apps = home.join(".local/share/applications");
    std::fs::create_dir_all(&apps)?;
    let desktop = apps.join("huddle.desktop");
    std::fs::write(&desktop, linux_desktop_entry(&dest))?;
    // Best-effort: refresh the desktop database so it appears in the menu now.
    let _ = Command::new("update-desktop-database").arg(&apps).status();

    println!("installed huddle-gui → {}", dest.display());
    println!("added app launcher → {}", desktop.display());
    if !dir_on_path(&bindir) {
        println!(
            "note: {} isn't on your PATH — add it (e.g. in ~/.profile) to run \
             `huddle-gui` from a shell.",
            bindir.display()
        );
    }
    Ok(dest)
}

fn linux_desktop_entry(exec: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Huddle\n\
         GenericName=Encrypted chat\n\
         Comment=Decentralized end-to-end-encrypted chat\n\
         Exec={exec} %U\n\
         Icon=huddle\n\
         Terminal=false\n\
         Categories=Network;InstantMessaging;Chat;\n\
         StartupWMClass=huddle\n",
        exec = exec.display()
    )
}

// ---- Windows: %LOCALAPPDATA%\Programs\Huddle + Start-Menu shortcut ----

fn install_windows(bin: &Path) -> Result<PathBuf> {
    let base = dirs::data_local_dir().ok_or_else(|| anyhow!("no %LOCALAPPDATA%"))?;
    let dir = base.join("Programs").join("Huddle");
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join("huddle-gui.exe");
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(bin, &dest).with_context(|| format!("copy into {}", dest.display()))?;

    // Best-effort Start-Menu shortcut via PowerShell's WScript.Shell.
    if let Some(roaming) = dirs::data_dir() {
        let lnk = roaming.join("Microsoft/Windows/Start Menu/Programs/Huddle.lnk");
        if let Some(parent) = lnk.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let script = format!(
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');\
             $s.TargetPath='{target}';$s.Save()",
            lnk = lnk.display(),
            target = dest.display()
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status();
    }

    println!("installed huddle-gui → {}", dest.display());
    Ok(dest)
}

// ---- shared helpers ----

/// Launch a GUI binary detached from this terminal (null std streams) so
/// `huddle app` can return while the app keeps running.
fn launch_detached(bin: &Path) -> Result<()> {
    println!("launching {}", bin.display());
    Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("launch {}", bin.display()))?;
    Ok(())
}

/// Mark a file executable (no-op on Windows, where the `.exe` suffix is enough).
fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm)?;
    }
    let _ = path;
    Ok(())
}

/// Is `dir` listed in `$PATH`?
fn dir_on_path(dir: &Path) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p == dir))
        .unwrap_or(false)
}
