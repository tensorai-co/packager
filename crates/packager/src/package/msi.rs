//! `.msi`: a Windows Installer package, one per architecture. The opinionated authoring from the
//! proposal: one feature, one component per file, a Start menu shortcut, URL schemes and file
//! types in the registry, the icon in Add/Remove Programs, and a major upgrade every release
//! (downgrades blocked with a message). Codes are derived (see [`crate::identity`]), so apps never
//! manage GUIDs. Per-machine by default (`Program Files`, elevation) or per-user
//! (`%LocalAppData%\Programs`, no UAC prompt).

use std::collections::{BTreeMap, HashSet};

use crate::app::{App, Arch};
use crate::crypto::{hex, sha256};
use crate::error::IoContext;
use crate::format::cab::{self, CabFile};
use crate::format::msi::{col, Database, Summary, Table, Value};
use crate::identity::{guid, msi_product_code, msi_upgrade_code, msi_version};
use crate::package::windows::{arch_label, exe_name, prepare_exe, resource_files, windows_archs};
use crate::package::{file_name, Context, Package, PackageBuilder, PackageKind};
use crate::util::source_date_epoch;
use crate::{Error, Result};

/// Who the package installs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Everyone: `Program Files`, needs elevation.
    PerMachine,
    /// The installing user: `%LocalAppData%\Programs`, no UAC prompt.
    PerUser,
}

/// The `.msi` builder.
#[derive(Debug, Clone)]
pub struct Msi {
    scope: Scope,
    archs: Option<Vec<Arch>>,
    upgrade_code: Option<String>,
    shortcut: bool,
}

impl Default for Msi {
    fn default() -> Self {
        Self::new()
    }
}

/// `DefaultDir` / `FileName` text: the long name, as `SHORT~1|Long name` when it isn't a valid
/// 8.3 name already. `used` holds the short names taken in the same directory.
fn short_long(long: &str, used: &mut HashSet<String>) -> String {
    let legal = |c: char| c.is_ascii_alphanumeric() || "!#$%&'()-@^_`{}~".contains(c);
    let (stem, ext) = match long.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, e),
        _ => (long, ""),
    };
    let is_83 = !stem.is_empty() && stem.len() <= 8 && ext.len() <= 3 && stem.chars().all(legal) && ext.chars().all(legal) && long.matches('.').count() <= 1;
    if is_83 && used.insert(long.to_uppercase()) {
        return long.to_string();
    }
    let clean = |s: &str, n: usize| s.chars().filter(|&c| legal(c)).map(|c| c.to_ascii_uppercase()).take(n).collect::<String>();
    let (base, e) = (clean(stem, 6), clean(ext, 3));
    let base = if base.is_empty() { "FILE".to_string() } else { base };
    for n in 1.. {
        let tail = format!("~{n}");
        let b: String = base.chars().take(8 - tail.len()).collect();
        let short = if e.is_empty() { format!("{b}{tail}") } else { format!("{b}{tail}.{e}") };
        if used.insert(short.clone()) {
            return format!("{short}|{long}");
        }
    }
    unreachable!()
}

/// The `Directory` key for the folder holding `path` (relative to the install directory),
/// adding rows for folders not seen yet.
fn dir_of(path: &str, directory: &mut Table, dirs: &mut BTreeMap<String, String>, used_names: &mut BTreeMap<String, HashSet<String>>) -> String {
    let mut parent = "INSTALLDIR".to_string();
    let mut acc = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        acc = if acc.is_empty() { part.to_string() } else { format!("{acc}/{part}") };
        if let Some(k) = dirs.get(&acc.to_lowercase()) {
            parent = k.clone();
            continue;
        }
        let k = key("D", &acc);
        let name = short_long(part, used_names.entry(parent.clone()).or_default());
        directory.row(vec![k.clone().into(), parent.clone().into(), name.into()]);
        dirs.insert(acc.to_lowercase(), k.clone());
        parent = k;
    }
    parent
}

/// A table key from a path: `F_` + 16 hex digits, stable across builds.
fn key(prefix: &str, path: &str) -> String {
    format!("{prefix}_{}", &hex(&sha256(path.to_lowercase().as_bytes()))[..16])
}

impl Msi {
    /// Per-machine, one package per Windows binary, with a Start menu shortcut.
    pub fn new() -> Self {
        Msi { scope: Scope::PerMachine, archs: None, upgrade_code: None, shortcut: true }
    }
    /// Installs for the current user only (no elevation).
    pub fn per_user(mut self) -> Self {
        self.scope = Scope::PerUser;
        self
    }
    /// Installs for everyone (the default).
    pub fn per_machine(mut self) -> Self {
        self.scope = Scope::PerMachine;
        self
    }
    /// Only these architectures.
    pub fn archs(mut self, archs: impl IntoIterator<Item = Arch>) -> Self {
        self.archs = Some(archs.into_iter().collect());
        self
    }
    /// An existing UpgradeCode, for apps moving from another installer.
    pub fn upgrade_code(mut self, code: impl Into<String>) -> Self {
        self.upgrade_code = Some(code.into());
        self
    }
    /// Leaves out the Start menu shortcut.
    pub fn no_shortcut(mut self) -> Self {
        self.shortcut = false;
        self
    }

    fn archs_for(&self, app: &App) -> Vec<Arch> {
        let have = windows_archs(app);
        match &self.archs {
            Some(want) => have.into_iter().filter(|a| want.contains(a)).collect(),
            None => have,
        }
    }

    /// The database for one architecture: (tables, cabinet).
    pub fn database(&self, app: &App, arch: Arch, exe: Vec<u8>) -> Result<Database> {
        let version = msi_version(app)?;
        let upgrade = self.upgrade_code.clone().unwrap_or_else(|| msi_upgrade_code(app));
        let product = msi_product_code(app, arch)?;
        let manufacturer = app.publisher.clone().unwrap_or_else(|| app.name.clone());
        let exe_file = exe_name(app);

        // Files: the executable first, then resources, by install path.
        let mut files: Vec<(String, Vec<u8>)> = vec![(exe_file.clone(), exe)];
        let mut res = resource_files(app)?;
        res.sort_by(|a, b| a.0.cmp(&b.0));
        files.extend(res);
        let mut seen = HashSet::new();
        for (p, _) in &files {
            if !seen.insert(p.to_lowercase()) {
                return Err(Error::invalid("msi", p.clone(), "two files install to the same path (paths are case-insensitive on Windows)"));
            }
        }

        let mut directory = Table::new("Directory", vec![col("Directory", "*s72"), col("Directory_Parent", "s72?"), col("DefaultDir", "l255")]);
        let pf = match arch {
            Arch::WindowsX64 | Arch::WindowsArm64 => "ProgramFiles64Folder",
            _ => "ProgramFilesFolder",
        };
        directory.row(vec!["TARGETDIR".into(), Value::Null, "SourceDir".into()]);
        directory.row(vec![pf.into(), "TARGETDIR".into(), ".".into()]);
        directory.row(vec!["ProgramMenuFolder".into(), "TARGETDIR".into(), ".".into()]);
        let mut top_used = HashSet::new();
        directory.row(vec!["INSTALLDIR".into(), pf.into(), short_long(&file_name(&app.name), &mut top_used).into()]);
        // Subdirectories of the install directory, created as files need them.
        let mut dirs: BTreeMap<String, String> = BTreeMap::new(); // path -> key
        let mut used_names: BTreeMap<String, HashSet<String>> = BTreeMap::new(); // dir key -> short names
        let x64 = matches!(arch, Arch::WindowsX64 | Arch::WindowsArm64);
        let mut component = Table::new("Component", vec![col("Component", "*s72"), col("ComponentId", "s38?"), col("Directory_", "s72"), col("Attributes", "i2"), col("Condition", "s255?"), col("KeyPath", "s72?")]);
        let mut file = Table::new("File", vec![col("File", "*s72"), col("Component_", "s72"), col("FileName", "l255"), col("FileSize", "i4"), col("Version", "s72?"), col("Language", "s20?"), col("Attributes", "i2?"), col("Sequence", "i4")]);
        let mut fc = Table::new("FeatureComponents", vec![col("Feature_", "*s38"), col("Component_", "*s72")]);
        let mut cab_files = Vec::new();
        let (exe_key, exe_comp) = ("F_main".to_string(), "C_main".to_string());
        for (i, (path, data)) in files.iter().enumerate() {
            let (fkey, ckey) = if i == 0 { (exe_key.clone(), exe_comp.clone()) } else { (key("F", path), key("C", path)) };
            let dkey = dir_of(path, &mut directory, &mut dirs, &mut used_names);
            let leaf = path.rsplit('/').next().unwrap_or(path);
            let name = short_long(leaf, used_names.entry(dkey.clone()).or_default());
            let comp_id = guid(&format!("msi-component:{upgrade}:{}:{}", arch.name(), path.to_lowercase()));
            component.row(vec![ckey.clone().into(), comp_id.into(), dkey.into(), (if x64 { 256 } else { 0 }).into(), Value::Null, fkey.clone().into()]);
            let (ver, lang) = if i == 0 { (Value::from(format!("{version}.0")), Value::from("1033")) } else { (Value::Null, Value::Null) };
            if data.len() > i32::MAX as usize {
                return Err(Error::invalid("msi", path.clone(), "files over 2 GB aren't supported"));
            }
            file.row(vec![fkey.clone().into(), ckey.clone().into(), name.into(), (data.len() as i32).into(), ver, lang, 512.into(), (i as i32 + 1).into()]);
            fc.row(vec!["Main".into(), ckey.into()]);
            cab_files.push(CabFile { name: fkey, data: data.clone() });
        }
        let cabinet = cab::write(&cab_files, source_date_epoch())?;

        let mut property = Table::new("Property", vec![col("Property", "*s72"), col("Value", "l0")]);
        let mut props = vec![
            ("ProductCode", product.clone()),
            ("UpgradeCode", upgrade.clone()),
            ("ProductName", app.name.clone()),
            ("ProductVersion", version.clone()),
            ("Manufacturer", manufacturer.clone()),
            ("ProductLanguage", "1033".into()),
            ("ARPNOMODIFY", "1".into()),
            ("SecureCustomProperties", "NEWERVERSIONDETECTED;OLDERVERSIONBEINGUPGRADED".into()),
        ];
        match self.scope {
            Scope::PerMachine => props.push(("ALLUSERS", "1".into())),
            Scope::PerUser => {
                props.push(("ALLUSERS", "2".into()));
                props.push(("MSIINSTALLPERUSER", "1".into()));
            }
        }
        let mut icon = Table::new("Icon", vec![col("Name", "*s72"), col("Data", "v0")]);
        if let Some(p) = &app.icon
            && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("png"))
        {
            icon.row(vec!["ProductIcon.ico".into(), Value::Binary(crate::image::ico_from_png(p)?)]);
            props.push(("ARPPRODUCTICON", "ProductIcon.ico".into()));
        }
        if let Some(c) = &app.description {
            props.push(("ARPCOMMENTS", c.clone()));
        }
        for (k, v) in props {
            property.row(vec![k.into(), v.into()]);
        }

        let mut feature = Table::new("Feature", vec![col("Feature", "*s38"), col("Feature_Parent", "s38?"), col("Title", "l64?"), col("Description", "l255?"), col("Display", "i2?"), col("Level", "i2"), col("Directory_", "s72?"), col("Attributes", "i2")]);
        feature.row(vec!["Main".into(), Value::Null, app.name.clone().into(), Value::Null, 0.into(), 1.into(), "INSTALLDIR".into(), 0.into()]);
        let mut media = Table::new("Media", vec![col("DiskId", "*i2"), col("LastSequence", "i4"), col("DiskPrompt", "l64?"), col("Cabinet", "s255?"), col("VolumeLabel", "s32?"), col("Source", "s72?")]);
        media.row(vec![1.into(), (files.len() as i32).into(), Value::Null, "#data.cab".into(), Value::Null, Value::Null]);

        let mut upgrade_t = Table::new("Upgrade", vec![col("UpgradeCode", "*s38"), col("VersionMin", "*s20?"), col("VersionMax", "*s20?"), col("Language", "*s255?"), col("Attributes", "*i4"), col("Remove", "s255?"), col("ActionProperty", "s72")]);
        // Older versions are removed (migrating feature states); newer ones are detected to block
        // a downgrade.
        upgrade_t.row(vec![upgrade.clone().into(), Value::Null, version.clone().into(), Value::Null, 1.into(), Value::Null, "OLDERVERSIONBEINGUPGRADED".into()]);
        upgrade_t.row(vec![upgrade.clone().into(), version.clone().into(), Value::Null, Value::Null, 2.into(), Value::Null, "NEWERVERSIONDETECTED".into()]);
        let mut launch = Table::new("LaunchCondition", vec![col("Condition", "*s255"), col("Description", "l255")]);
        launch.row(vec!["NOT NEWERVERSIONDETECTED OR Installed".into(), "A newer version of [ProductName] is already installed.".into()]);

        let seq_cols = || vec![col("Action", "*s72"), col("Condition", "s255?"), col("Sequence", "i2?")];
        let mut exec = Table::new("InstallExecuteSequence", seq_cols());
        for (a, n) in [
            ("FindRelatedProducts", 25),
            ("LaunchConditions", 100),
            ("ValidateProductID", 700),
            ("CostInitialize", 800),
            ("FileCost", 900),
            ("CostFinalize", 1000),
            ("MigrateFeatureStates", 1200),
            ("InstallValidate", 1400),
            ("RemoveExistingProducts", 1401),
            ("InstallInitialize", 1500),
            ("ProcessComponents", 1600),
            ("UnpublishFeatures", 1800),
            ("RemoveRegistryValues", 2600),
            ("RemoveShortcuts", 3200),
            ("RemoveFiles", 3500),
            ("InstallFiles", 4000),
            ("CreateShortcuts", 4500),
            ("WriteRegistryValues", 5000),
            ("RegisterUser", 6000),
            ("RegisterProduct", 6100),
            ("PublishFeatures", 6300),
            ("PublishProduct", 6400),
            ("InstallFinalize", 6600),
        ] {
            exec.row(vec![a.into(), Value::Null, n.into()]);
        }
        let mut ui = Table::new("InstallUISequence", seq_cols());
        for (a, n) in [("FindRelatedProducts", 25), ("LaunchConditions", 100), ("ValidateProductID", 700), ("CostInitialize", 800), ("FileCost", 900), ("CostFinalize", 1000), ("MigrateFeatureStates", 1200), ("ExecuteAction", 1300)] {
            ui.row(vec![a.into(), Value::Null, n.into()]);
        }

        let mut tables = vec![directory, component, file, fc, property, feature, media, upgrade_t, launch, exec, ui];
        if !icon.rows.is_empty() {
            tables.push(icon);
        }
        if self.shortcut {
            let mut sc = Table::new("Shortcut", vec![col("Shortcut", "*s72"), col("Directory_", "s72"), col("Name", "l128"), col("Component_", "s72"), col("Target", "s72"), col("Arguments", "s255?"), col("Description", "l255?"), col("Hotkey", "i2?"), col("Icon_", "s72?"), col("IconIndex", "i2?"), col("ShowCmd", "i2?"), col("WkDir", "s72?")]);
            let mut used = HashSet::new();
            sc.row(vec!["S_main".into(), "ProgramMenuFolder".into(), short_long(&file_name(&app.name), &mut used).into(), exe_comp.clone().into(), format!("[#{exe_key}]").into(), Value::Null, app.description.clone().into(), Value::Null, Value::Null, Value::Null, Value::Null, "INSTALLDIR".into()]);
            tables.push(sc);
        }
        let open = format!("\"[#{exe_key}]\" \"%1\"");
        let mut reg = Table::new("Registry", vec![col("Registry", "*s72"), col("Root", "i2"), col("Key", "l255"), col("Name", "l255?"), col("Value", "l0?"), col("Component_", "s72")]);
        for s in &app.url_schemes {
            let k = s.to_lowercase();
            reg.row(vec![key("R", &format!("url:{k}")).into(), 0.into(), k.clone().into(), Value::Null, format!("URL:{} Protocol", app.name).into(), exe_comp.clone().into()]);
            reg.row(vec![key("R", &format!("url:{k}:flag")).into(), 0.into(), k.clone().into(), "URL Protocol".into(), Value::Null, exe_comp.clone().into()]);
            reg.row(vec![key("R", &format!("url:{k}:cmd")).into(), 0.into(), format!("{k}\\shell\\open\\command").into(), Value::Null, open.clone().into(), exe_comp.clone().into()]);
        }
        for ft in &app.file_types {
            let ext = format!(".{}", ft.extension.trim_start_matches('.').to_lowercase());
            let progid = format!("{}{}", app.identifier, ext);
            reg.row(vec![key("R", &format!("ext:{ext}")).into(), 0.into(), ext.clone().into(), Value::Null, progid.clone().into(), exe_comp.clone().into()]);
            reg.row(vec![key("R", &format!("progid:{progid}")).into(), 0.into(), progid.clone().into(), Value::Null, ft.name.clone().into(), exe_comp.clone().into()]);
            reg.row(vec![key("R", &format!("icon:{progid}")).into(), 0.into(), format!("{progid}\\DefaultIcon").into(), Value::Null, format!("[#{exe_key}],0").into(), exe_comp.clone().into()]);
            reg.row(vec![key("R", &format!("cmd:{progid}")).into(), 0.into(), format!("{progid}\\shell\\open\\command").into(), Value::Null, open.clone().into(), exe_comp.clone().into()]);
        }
        if !reg.rows.is_empty() {
            tables.push(reg);
        }

        let package_code = guid(&format!("msi-package:{product}:{}", hex(&sha256(&cabinet))));
        let summary = Summary {
            title: "Installation Database".into(),
            subject: app.name.clone(),
            author: manufacturer,
            keywords: "Installer".into(),
            comments: app.description.clone().unwrap_or_else(|| format!("{} {version}", app.name)),
            template: format!("{};1033", if arch == Arch::WindowsArm64 { "Arm64" } else { "x64" }),
            revision: package_code,
            app_name: concat!("packager ", env!("CARGO_PKG_VERSION")).into(),
            time: source_date_epoch(),
            page_count: 500,
            word_count: if self.scope == Scope::PerUser { 2 | 8 } else { 2 },
            security: 2,
        };
        Ok(Database { tables, streams: vec![("data.cab".into(), cabinet)], summary })
    }
}

impl PackageBuilder for Msi {
    fn kind(&self) -> PackageKind {
        PackageKind::Msi
    }
    fn validate(&self, app: &App) -> Result<()> {
        msi_version(app)?;
        crate::format::msi::cp1252(&app.name)?;
        if self.archs_for(app).is_empty() {
            return Err(Error::invalid("msi", "binaries", "needs a windows-x64 or windows-arm64 binary"));
        }
        if let Some(c) = &self.upgrade_code {
            let ok = c.len() == 38 && c.starts_with('{') && c.ends_with('}') && c[1..37].chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-') && c == &c.to_uppercase();
            if !ok {
                return Err(Error::invalid("msi", "upgrade_code", format!("`{c}` must be an uppercase GUID in braces")));
            }
        }
        Ok(())
    }
    fn build(&self, ctx: &mut Context) -> Result<Vec<Package>> {
        let app = ctx.app;
        let mut out = Vec::new();
        for arch in self.archs_for(app) {
            let exe = prepare_exe(app, arch, ctx.authenticode)?;
            let db = self.database(app, arch, exe)?;
            let mut bytes = db.write(&[])?;
            if let Some(a) = ctx.authenticode {
                bytes = crate::sign::msi::sign_msi(&bytes, a.signer.as_ref(), &a.options())?;
            }
            std::fs::create_dir_all(&ctx.out_dir).at(&ctx.out_dir)?;
            let path = ctx.out_dir.join(format!("{}-{}-{}.msi", file_name(&app.name), app.version, arch_label(arch)));
            std::fs::write(&path, bytes).at(&path)?;
            out.push(Package::file(PackageKind::Msi, arch.name(), path, ctx.authenticode.is_some())?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names() {
        let mut used = HashSet::new();
        assert_eq!(short_long("app.exe", &mut used), "app.exe");
        assert_eq!(short_long("My App", &mut used), "MYAPP~1|My App");
        assert_eq!(short_long("My App 2", &mut used), "MYAPP2~1|My App 2");
        assert_eq!(short_long("README.markdown", &mut used), "README~1.MAR|README.markdown");
        assert_eq!(short_long("readme.markdown", &mut used), "README~2.MAR|readme.markdown");
    }
}
