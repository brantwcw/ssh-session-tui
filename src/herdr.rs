//! Optional Herdr handoff. Discovery never launches an executable or SSH.
//!
//! H opens Herdr for the selected row: plain `herdr` on Local terminal, or
//! `herdr --remote ssh://user@host:port` for a machine route. Herdr resolves an
//! alias through the default SSH config only, so a route bound to another
//! config file is refused instead of silently connecting somewhere else.
use crate::{
    catalog::{Catalog, Machine, Route, identifier, locked, write_json},
    ssh_import,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub argv: Vec<OsString>,
    pub title: String,
}

fn resolve_with(
    explicit: Option<&OsStr>,
    lookup: impl FnOnce(&str) -> Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(value) = explicit {
        let path = Path::new(value);
        ensure!(
            path.is_absolute() && path.is_file(),
            "HERDR_BIN must name an existing absolute executable path."
        );
        return Ok(path.to_path_buf());
    }
    lookup(if cfg!(windows) { "herdr.exe" } else { "herdr" })
        .context("Herdr is not installed. See https://herdr.dev, then press H again.")
}

pub fn executable() -> Result<PathBuf> {
    resolve_with(std::env::var_os("HERDR_BIN").as_deref(), |name| {
        which::which(name).ok()
    })
}

fn unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-')
}

/// The SSH target Herdr receives. An alias stays an alias so its proxy and key
/// settings apply; the catalog's user and port are explicit.
pub fn target(machine: &Machine, route: &Route) -> Result<String> {
    let host = route.ssh_alias.as_ref().unwrap_or(&route.host);
    let plain = !host.is_empty()
        && !host.starts_with('-')
        && host.chars().all(|c| unreserved(c) && c != '~');
    let ipv6 = route.ssh_alias.is_none()
        && host.contains(':')
        && host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    ensure!(
        plain || ipv6,
        "Herdr cannot use the address \"{host}\". Give this route an SSH alias, or press Enter for a plain SSH session."
    );
    let mut user = String::new();
    for byte in machine.user.bytes() {
        if unreserved(byte as char) {
            user.push(byte as char);
        } else {
            user.push_str(&format!("%{byte:02X}"));
        }
    }
    ensure!(!user.is_empty(), "This machine has no SSH username.");
    Ok(if ipv6 {
        format!("ssh://{user}@[{host}]:{}", route.port)
    } else {
        format!("ssh://{user}@{host}:{}", route.port)
    })
}

/// Build the command for one frozen selection. `None` is the Local terminal row.
pub fn launch(
    catalog: &Catalog,
    program: &Path,
    selection: Option<(&Machine, &Route)>,
) -> Result<Launch> {
    let Some((machine, route)) = selection else {
        return Ok(Launch {
            argv: vec![program.as_os_str().into()],
            title: "Local Herdr".into(),
        });
    };
    if let Some(alias) = &route.ssh_alias
        && ssh_import::connection_config(catalog, machine, route)?.is_some()
    {
        bail!(
            "Herdr reads only your default SSH config, and the alias \"{alias}\" comes from another file. Press Enter for a plain SSH session."
        );
    }
    Ok(Launch {
        argv: vec![
            program.as_os_str().into(),
            "--remote".into(),
            target(machine, route)?.into(),
        ],
        title: format!("{} | {} | Herdr", machine.name, route.name),
    })
}

/// Machines this device has already opened with Herdr. The first remote attach
/// can install Herdr on that machine, so the picker asks once per machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Known {
    pub version: u8,
    pub machines: BTreeSet<String>,
}
impl Default for Known {
    fn default() -> Self {
        Self {
            version: 1,
            machines: BTreeSet::new(),
        }
    }
}
impl Known {
    fn path(catalog: &Catalog) -> PathBuf {
        catalog.device_path.with_extension("herdr.json")
    }
    pub fn load(catalog: &Catalog) -> Result<Self> {
        let path = Self::path(catalog);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read(path)?;
        ensure!(raw.len() <= 65536, "Herdr machine list is too large.");
        let value: Self =
            serde_json::from_slice(raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&raw))
                .context("Invalid Herdr machine list. Keep a backup before repairing it.")?;
        ensure!(
            value.version == 1,
            "Unsupported Herdr machine list version."
        );
        for id in &value.machines {
            identifier(id)?;
        }
        Ok(value)
    }
    pub fn contains(&self, machine: &str) -> bool {
        self.machines.contains(machine)
    }
    /// Record a confirmed machine. Unknown IDs from other catalogs' history are kept.
    pub fn remember(catalog: &Catalog, machine: &str) -> Result<()> {
        identifier(machine)?;
        let _guard = locked(&catalog.lock_path)?;
        let mut value = Self::load(catalog)?;
        if value.machines.insert(machine.into()) {
            write_json(&Self::path(catalog), &value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(user: &str) -> Machine {
        Machine {
            id: "lab".into(),
            name: "Lab".into(),
            user: user.into(),
            routes: Vec::new(),
            group: String::new(),
            tags: Vec::new(),
        }
    }
    fn route(host: &str, port: u16, alias: Option<&str>) -> Route {
        Route {
            id: "lan".into(),
            name: "LAN".into(),
            host: host.into(),
            port,
            ssh_alias: alias.map(Into::into),
        }
    }
    fn catalog(temp: &tempfile::TempDir) -> Catalog {
        Catalog::new(
            &temp.path().join("catalog.json"),
            &temp.path().join("device"),
        )
        .unwrap()
    }

    #[test]
    fn target_keeps_alias_user_and_port_and_brackets_ipv6() {
        let dev = machine("dev");
        assert_eq!(
            target(&dev, &route("192.0.2.10", 22, None)).unwrap(),
            "ssh://dev@192.0.2.10:22"
        );
        assert_eq!(
            target(&dev, &route("192.0.2.10", 2222, Some("workbox"))).unwrap(),
            "ssh://dev@workbox:2222"
        );
        assert_eq!(
            target(&dev, &route("2001:db8::10", 22, None)).unwrap(),
            "ssh://dev@[2001:db8::10]:22"
        );
        assert_eq!(
            target(&machine("a b@c"), &route("gpu.example.test", 22, None)).unwrap(),
            "ssh://a%20b%40c@gpu.example.test:22"
        );
    }

    #[test]
    fn target_rejects_addresses_that_could_change_the_destination() {
        let dev = machine("dev");
        for host in [
            "",
            "host name",
            "host/path",
            "user@host",
            "fe80::1%en0",
            "-oProxyCommand=x",
            "-leading",
        ] {
            assert!(target(&dev, &route(host, 22, None)).is_err(), "{host}");
        }
        assert!(target(&dev, &route("192.0.2.10", 22, Some("bad alias"))).is_err());
        assert!(target(&dev, &route("192.0.2.10", 22, Some("a:b"))).is_err());
    }

    #[test]
    fn launch_builds_local_and_remote_commands_without_running_them() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = catalog(&temp);
        let program = Path::new("/opt/example/herdr");
        let local = launch(&catalog, program, None).unwrap();
        assert_eq!(local.argv, vec![OsString::from("/opt/example/herdr")]);
        assert_eq!(local.title, "Local Herdr");
        let dev = machine("dev");
        let lan = route("192.0.2.10", 22, None);
        let remote = launch(&catalog, program, Some((&dev, &lan))).unwrap();
        assert_eq!(
            remote.argv,
            ["/opt/example/herdr", "--remote", "ssh://dev@192.0.2.10:22"].map(OsString::from)
        );
        assert_eq!(remote.title, "Lab | LAN | Herdr");
    }

    #[test]
    fn alias_bound_to_another_ssh_config_is_refused_before_any_command_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = catalog(&temp);
        let config = temp.path().join("other config");
        fs::write(&config, b"Host work-box\n  HostName old.example.test\n").unwrap();
        let dev = machine("dev");
        let bound = route("192.0.2.18", 2222, Some("work-box"));
        let bindings = std::collections::BTreeMap::from([("lab/lan", config.to_str().unwrap())]);
        write_json(
            &catalog.device_path.with_extension("ssh-configs.json"),
            &bindings,
        )
        .unwrap();
        let error = launch(
            &catalog,
            Path::new("/opt/example/herdr"),
            Some((&dev, &bound)),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("default SSH config"), "{error}");
        // An alias that exists in no config is reported by the existing import check.
        let missing = route("192.0.2.18", 22, Some("nowhere-box"));
        fs::remove_file(catalog.device_path.with_extension("ssh-configs.json")).unwrap();
        assert!(
            launch(
                &catalog,
                Path::new("/opt/example/herdr"),
                Some((&dev, &missing))
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_program_must_exist_and_missing_herdr_explains_itself() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("herdr");
        fs::write(&file, b"").unwrap();
        assert_eq!(
            resolve_with(Some(file.as_os_str()), |_| None).unwrap(),
            file
        );
        assert!(
            resolve_with(Some(OsStr::new("herdr")), |_| None)
                .unwrap_err()
                .to_string()
                .contains("HERDR_BIN")
        );
        assert!(
            resolve_with(None, |_| None)
                .unwrap_err()
                .to_string()
                .contains("not installed")
        );
        assert_eq!(
            resolve_with(None, |name| Some(PathBuf::from("/bin").join(name))).unwrap(),
            PathBuf::from("/bin").join(if cfg!(windows) { "herdr.exe" } else { "herdr" })
        );
    }

    #[test]
    fn known_machines_are_remembered_once_and_bad_files_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = catalog(&temp);
        assert!(!Known::load(&catalog).unwrap().contains("lab"));
        Known::remember(&catalog, "lab").unwrap();
        Known::remember(&catalog, "lab").unwrap();
        Known::remember(&catalog, "school").unwrap();
        let known = Known::load(&catalog).unwrap();
        assert!(known.contains("lab") && known.contains("school"));
        assert_eq!(known.machines.len(), 2);
        fs::write(Known::path(&catalog), br#"{"version":2,"machines":[]}"#).unwrap();
        assert!(Known::load(&catalog).is_err());
        fs::write(
            Known::path(&catalog),
            br#"{"version":1,"machines":[],"x":1}"#,
        )
        .unwrap();
        assert!(Known::load(&catalog).is_err());
    }
}
