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

/// The most uncompressed data per cabinet; larger packages get several.
const CABINET_LIMIT: usize = 1 << 30;

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
    wizard: bool,
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

/// One `_Validation` rule: (category, min, max, key table, key column, set).
type Rule = (&'static str, Option<i32>, Option<i32>, Option<&'static str>, Option<i32>, Option<&'static str>);

/// The validation rule Windows Installer's schema gives a column.
fn rule(table: &str, column: &str) -> Rule {
    const MAX: i32 = i32::MAX;
    let fk = |t: &'static str| -> Rule { ("Identifier", None, None, Some(t), Some(1), None) };
    match (table, column) {
        (_, "Property") | ("Directory", "Directory") | ("Component", "Component") | ("File", "File") | ("Feature", "Feature") | ("Shortcut", "Shortcut") | ("Registry", "Registry") | ("Icon", "Name") => ("Identifier", None, None, None, None, None),
        (_, "Action") => ("Identifier", None, None, None, None, None),
        ("Property", "Value") => ("Text", None, None, None, None, None),
        ("Directory", "Directory_Parent") => fk("Directory"),
        ("Directory", "DefaultDir") => ("DefaultDir", None, None, None, None, None),
        ("Component", "ComponentId") | ("Upgrade", "UpgradeCode") => ("Guid", None, None, None, None, None),
        ("Component", "Directory_") | ("Shortcut", "Directory_") => fk("Directory"),
        ("Component", "Attributes") => ("", Some(0), Some(32767), None, None, None),
        ("Component", "Condition") | ("LaunchCondition", "Condition") | (_, "Condition") => ("Condition", None, None, None, None, None),
        ("Component", "KeyPath") => ("Identifier", None, None, Some("File;Registry;ODBCDataSource"), Some(1), None),
        ("File", "Component_") | ("FeatureComponents", "Component_") | ("Shortcut", "Component_") | ("Registry", "Component_") => fk("Component"),
        ("File", "FileName") | ("Shortcut", "Name") => ("Filename", None, None, None, None, None),
        ("File", "FileSize") => ("", Some(0), Some(MAX), None, None, None),
        ("File", "Version") => ("Version", None, None, Some("File"), Some(1), None),
        ("File", "Language") | ("Upgrade", "Language") => ("Language", None, None, None, None, None),
        ("File", "Attributes") => ("", Some(0), Some(32767), None, None, None),
        ("File", "Sequence") => ("", Some(1), Some(MAX), None, None, None),
        ("Feature", "Feature_Parent") | ("FeatureComponents", "Feature_") => fk("Feature"),
        ("Feature", "Title") | ("Feature", "Description") | ("Shortcut", "Description") | ("Media", "DiskPrompt") | ("Media", "VolumeLabel") => ("Text", None, None, None, None, None),
        ("Feature", "Display") | ("Feature", "Level") => ("", Some(0), Some(32767), None, None, None),
        ("Feature", "Directory_") => ("UpperCase", None, None, Some("Directory"), Some(1), None),
        ("Feature", "Attributes") => ("", None, None, None, None, Some("0;1;2;4;5;6;8;9;10;16;17;18;20;21;22;24;25;26;32;33;34;36;37;38;48;49;50;52;53;54")),
        ("Media", "DiskId") => ("", Some(1), Some(32767), None, None, None),
        ("Media", "LastSequence") => ("", Some(0), Some(MAX), None, None, None),
        ("Media", "Cabinet") => ("Cabinet", None, None, None, None, None),
        ("Media", "Source") => ("Property", None, None, None, None, None),
        ("Upgrade", "VersionMin") | ("Upgrade", "VersionMax") => ("Text", None, None, None, None, None),
        ("Upgrade", "Attributes") => ("", Some(0), Some(MAX), None, None, None),
        ("Upgrade", "Remove") | ("LaunchCondition", "Description") | ("Shortcut", "Arguments") | ("Registry", "Name") | ("Registry", "Value") => ("Formatted", None, None, None, None, None),
        ("Upgrade", "ActionProperty") => ("UpperCase", None, None, None, None, None),
        (_, "Sequence") => ("", Some(-4), Some(32767), None, None, None),
        ("Shortcut", "Target") => ("Shortcut", None, None, None, None, None),
        ("Shortcut", "Hotkey") => ("", Some(0), Some(32767), None, None, None),
        ("Shortcut", "Icon_") => fk("Icon"),
        ("Shortcut", "IconIndex") => ("", Some(-32767), Some(32767), None, None, None),
        ("Shortcut", "ShowCmd") => ("", None, None, None, None, Some("1;3;7")),
        ("Shortcut", "WkDir") => ("Identifier", None, None, None, None, None),
        ("Registry", "Root") => ("", Some(-1), Some(3), None, None, None),
        ("Registry", "Key") => ("RegPath", None, None, None, None, None),
        ("Icon", "Data") => ("Binary", None, None, None, None, None),
        ("Dialog", "Dialog") | ("Control", "Control") | ("Control", "Type") | ("TextStyle", "TextStyle") | ("UIText", "Key") => ("Identifier", None, None, None, None, None),
        ("Dialog", "Title") | ("Control", "Text") => ("Formatted", None, None, None, None, None),
        ("ListBox", "Value") => ("Identifier", None, None, None, None, None),
        ("ListBox", "Order") => ("", Some(1), Some(32767), None, None, None),
        ("Dialog", "Control_First") | ("Dialog", "Control_Default") | ("Dialog", "Control_Cancel") => ("Identifier", None, None, Some("Control"), Some(2), None),
        ("Control", "Dialog_") | ("ControlEvent", "Dialog_") | ("EventMapping", "Dialog_") => ("Identifier", None, None, Some("Dialog"), Some(1), None),
        ("Control", "Control_Next") => ("Identifier", None, None, Some("Control"), Some(2), None),
        ("ControlEvent", "Control_") | ("EventMapping", "Control_") => ("Identifier", None, None, Some("Control"), Some(2), None),
        ("EventMapping", "Attribute") => ("Identifier", None, None, None, None, None),
        ("ControlEvent", "Event") | ("EventMapping", "Event") => ("Formatted", None, None, None, None, None),
        ("ControlEvent", "Argument") => ("Formatted", None, None, None, None, None),
        ("TextStyle", "FaceName") | ("Control", "Help") => ("Text", None, None, None, None, None),
        ("Dialog", "HCentering") | ("Dialog", "VCentering") => ("", Some(0), Some(100), None, None, None),
        ("Dialog", "Width") | ("Dialog", "Height") | ("Control", "X") | ("Control", "Y") | ("Control", "Width") | ("Control", "Height") | ("TextStyle", "Size") => ("", Some(0), Some(32767), None, None, None),
        ("Dialog", "Attributes") | ("Control", "Attributes") => ("", Some(0), Some(i32::MAX), None, None, None),
        ("TextStyle", "Color") => ("", Some(0), Some(16_777_215), None, None, None),
        ("TextStyle", "StyleBits") => ("", Some(0), Some(15), None, None, None),
        ("ControlEvent", "Ordering") => ("", Some(0), Some(2_147_483_647), None, None, None),
        _ => ("Text", None, None, None, None, None),
    }
}

/// The `_Validation` table for `tables` (what ICE validation checks the data against).
fn validation(tables: &[Table]) -> Table {
    use crate::format::msi::Kind;
    let mut v = Table::new(
        "_Validation",
        vec![col("Table", "*s32"), col("Column", "*s32"), col("Nullable", "s4"), col("MinValue", "i4?"), col("MaxValue", "i4?"), col("KeyTable", "s255?"), col("KeyColumn", "i2?"), col("Category", "s32?"), col("Set", "l255?"), col("Description", "l255?")],
    );
    for t in tables {
        for c in &t.columns {
            let (cat, min, max, kt, kc, set) = rule(&t.name, &c.name);
            let integer = matches!(c.kind, Kind::Short | Kind::Long);
            let (cat, min, max) = if integer {
                let (lo, hi) = if c.kind == Kind::Short { (-32767, 32767) } else { (i32::MIN + 1, i32::MAX) };
                ("", min.or(Some(lo)).filter(|_| set.is_none()), max.or(Some(hi)).filter(|_| set.is_none()))
            } else {
                (cat, None, None)
            };
            v.row(vec![
                t.name.clone().into(),
                c.name.clone().into(),
                (if c.nullable { "Y" } else { "N" }).into(),
                min.map(Value::Int).unwrap_or(Value::Null),
                max.map(Value::Int).unwrap_or(Value::Null),
                kt.map(Value::from).unwrap_or(Value::Null),
                kc.map(Value::Int).unwrap_or(Value::Null),
                (if cat.is_empty() { Value::Null } else { cat.into() }),
                set.map(Value::from).unwrap_or(Value::Null),
                Value::Null,
            ]);
        }
    }
    v
}

impl Msi {
    /// Per-machine, one package per Windows binary, with a Start menu shortcut.
    pub fn new() -> Self {
        Msi { scope: Scope::PerMachine, archs: None, upgrade_code: None, shortcut: true, wizard: false }
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
    /// Shows a minimal install wizard (Welcome with the install folder, progress, finished)
    /// instead of Windows Installer's basic progress window.
    pub fn wizard(mut self) -> Self {
        self.wizard = true;
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
        // Cabinets of at most CABINET_LIMIT uncompressed bytes each (a cabinet tops out at 4 GB).
        let mut cabinets: Vec<(i32, Vec<u8>)> = Vec::new(); // (last sequence, cabinet)
        let mut batch: Vec<CabFile> = Vec::new();
        let mut batch_size = 0usize;
        let n_files = cab_files.len();
        for (i, f) in cab_files.into_iter().enumerate() {
            if !batch.is_empty() && batch_size + f.data.len() > CABINET_LIMIT {
                cabinets.push((i as i32, cab::write(&std::mem::take(&mut batch), source_date_epoch())?));
                batch_size = 0;
            }
            batch_size += f.data.len();
            batch.push(f);
        }
        cabinets.push((n_files as i32, cab::write(&batch, source_date_epoch())?));
        let cab_name = |k: usize| if k == 0 { "data.cab".to_string() } else { format!("data{}.cab", k + 1) };

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
        let ui = self.wizard.then(|| super::msi_ui::wizard(self.scope == Scope::PerMachine));
        if let Some(ui) = &ui {
            for (k, v) in &ui.properties {
                props.push((k, (*v).into()));
            }
        }
        for (k, v) in props {
            property.row(vec![k.into(), v.into()]);
        }

        let mut feature = Table::new("Feature", vec![col("Feature", "*s38"), col("Feature_Parent", "s38?"), col("Title", "l64?"), col("Description", "l255?"), col("Display", "i2?"), col("Level", "i2"), col("Directory_", "s72?"), col("Attributes", "i2")]);
        feature.row(vec!["Main".into(), Value::Null, app.name.clone().into(), Value::Null, 0.into(), 1.into(), "INSTALLDIR".into(), 0.into()]);
        let mut media = Table::new("Media", vec![col("DiskId", "*i2"), col("LastSequence", "i4"), col("DiskPrompt", "l64?"), col("Cabinet", "s255?"), col("VolumeLabel", "s32?"), col("Source", "s72?")]);
        for (k, (last, _)) in cabinets.iter().enumerate() {
            media.row(vec![(k as i32 + 1).into(), (*last).into(), Value::Null, format!("#{}", cab_name(k)).into(), Value::Null, Value::Null]);
        }

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
        let mut ui_seq = Table::new("InstallUISequence", seq_cols());
        for (a, n) in [("FindRelatedProducts", 25), ("LaunchConditions", 100), ("ValidateProductID", 700), ("CostInitialize", 800), ("FileCost", 900), ("CostFinalize", 1000), ("MigrateFeatureStates", 1200), ("ExecuteAction", 1300)] {
            ui_seq.row(vec![a.into(), Value::Null, n.into()]);
        }
        if let Some(ui) = &ui {
            for (a, c, n) in &ui.sequence {
                ui_seq.row(vec![(*a).into(), c.map(Value::from).unwrap_or(Value::Null), (*n).into()]);
            }
        }

        let mut tables = Vec::new();
        if !icon.rows.is_empty() {
            tables.push(icon);
        }
        let mut reg = Table::new("Registry", vec![col("Registry", "*s72"), col("Root", "i2"), col("Key", "l255"), col("Name", "l255?"), col("Value", "l0?"), col("Component_", "s72")]);
        let manufacturer_dir = manufacturer.replace('\\', "-");
        if self.shortcut {
            // The shortcut gets a component of its own, keyed by a per-user registry value
            // (ICE43/ICE57: non-advertised shortcuts need an HKCU key path).
            let sc_comp = "C_shortcut".to_string();
            let sc_key = "R_shortcut".to_string();
            component.row(vec![sc_comp.clone().into(), guid(&format!("msi-component:{upgrade}:{}:shortcut", arch.name())).into(), "INSTALLDIR".into(), (if x64 { 256 | 4 } else { 4 }).into(), Value::Null, sc_key.clone().into()]);
            fc.row(vec!["Main".into(), sc_comp.clone().into()]);
            reg.row(vec![sc_key.into(), 1.into(), format!("Software\\{}\\{}", manufacturer_dir, app.name).into(), "Shortcut".into(), "#1".into(), sc_comp.clone().into()]);
            let mut sc = Table::new("Shortcut", vec![col("Shortcut", "*s72"), col("Directory_", "s72"), col("Name", "l128"), col("Component_", "s72"), col("Target", "s72"), col("Arguments", "s255?"), col("Description", "l255?"), col("Hotkey", "i2?"), col("Icon_", "s72?"), col("IconIndex", "i2?"), col("ShowCmd", "i2?"), col("WkDir", "s72?")]);
            let mut used = HashSet::new();
            sc.row(vec!["S_main".into(), "ProgramMenuFolder".into(), short_long(&file_name(&app.name), &mut used).into(), sc_comp.into(), format!("[INSTALLDIR]{exe_file}").into(), Value::Null, app.description.clone().into(), Value::Null, Value::Null, Value::Null, Value::Null, "INSTALLDIR".into()]);
            tables.push(sc);
        }
        let open = format!("\"[#{exe_key}]\" \"%1\"");
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
        tables.extend([directory, component, file, fc, property, feature, media, upgrade_t, launch, exec, ui_seq]);
        if let Some(ui) = ui {
            tables.extend(ui.tables);
        }

        let v = validation(&tables);
        tables.push(v);
        let all: Vec<u8> = cabinets.iter().flat_map(|(_, c)| sha256(c)).collect();
        let package_code = guid(&format!("msi-package:{product}:{}", hex(&sha256(&all))));
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
        let streams = cabinets.into_iter().enumerate().map(|(k, (_, c))| (cab_name(k), c)).collect();
        Ok(Database { tables, streams, summary })
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
