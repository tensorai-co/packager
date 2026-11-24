//! A minimal install wizard for `.msi` packages, as Windows Installer tables: Welcome (with the
//! install folder) → Progress → Finished, plus the dialogs Windows Installer requires for
//! errors, files in use, a cancel confirmation, and a premature or cancelled end. Without it, a
//! package shows only Windows Installer's basic progress UI.

use crate::format::msi::{Table, Value, col};

/// The UI tables, and the `InstallUISequence` rows to add.
pub struct Ui {
    /// `Dialog`, `Control`, `ControlEvent`, `EventMapping`, `TextStyle`, `UIText`.
    pub tables: Vec<Table>,
    /// (action, condition, sequence).
    pub sequence: Vec<(&'static str, Option<&'static str>, i32)>,
    /// Properties the UI needs (`DefaultUIFont`, `ErrorDialog`).
    pub properties: Vec<(&'static str, &'static str)>,
}

const W: i32 = 370;
const H: i32 = 270;

struct Builder {
    dialog: Table,
    control: Table,
    event: Table,
    mapping: Table,
}

/// One control: (name, type, x, y, w, h, attributes, property, text, next).
type Ctl<'a> = (&'a str, &'a str, i32, i32, i32, i32, i32, Option<&'a str>, Option<&'a str>, Option<&'a str>);

impl Builder {
    fn dialog(&mut self, name: &str, attrs: i32, first: &str, default: Option<&str>, cancel: Option<&str>, controls: &[Ctl]) {
        self.dialog.row(vec![name.into(), 50.into(), 50.into(), W.into(), H.into(), attrs.into(), "[ProductName] Setup".into(), first.into(), default.into(), cancel.into()]);
        for (c, ty, x, y, w, h, a, prop, text, next) in controls {
            self.control.row(vec![
                name.into(),
                (*c).into(),
                (*ty).into(),
                (*x).into(),
                (*y).into(),
                (*w).into(),
                (*h).into(),
                (*a).into(),
                (*prop).into(),
                text.map(Value::from).unwrap_or(Value::Null),
                (*next).into(),
                Value::Null,
            ]);
        }
    }
    fn on(&mut self, dialog: &str, control: &str, event: &str, arg: &str, cond: &str, order: i32) {
        self.event.row(vec![dialog.into(), control.into(), event.into(), arg.into(), cond.into(), order.into()]);
    }
}

// Control attributes.
const VISIBLE: i32 = 1;
const ENABLED: i32 = 2;
const TRANSPARENT: i32 = 0x10000;
const NO_PREFIX: i32 = 0x20000;
const TEXT: i32 = VISIBLE | TRANSPARENT | NO_PREFIX;
const BUTTON: i32 = VISIBLE | ENABLED;
const ELEVATION_SHIELD: i32 = 0x0080_0000;

/// The wizard's tables. `elevated` puts the UAC shield on the Install button.
pub fn wizard(elevated: bool) -> Ui {
    let mut b = Builder {
        dialog: Table::new(
            "Dialog",
            vec![
                col("Dialog", "*s72"),
                col("HCentering", "i2"),
                col("VCentering", "i2"),
                col("Width", "i2"),
                col("Height", "i2"),
                col("Attributes", "i4?"),
                col("Title", "l128?"),
                col("Control_First", "s50"),
                col("Control_Default", "s50?"),
                col("Control_Cancel", "s50?"),
            ],
        ),
        control: Table::new(
            "Control",
            vec![
                col("Dialog_", "*s72"),
                col("Control", "*s50"),
                col("Type", "s20"),
                col("X", "i2"),
                col("Y", "i2"),
                col("Width", "i2"),
                col("Height", "i2"),
                col("Attributes", "i4?"),
                col("Property", "s72?"),
                col("Text", "l0?"),
                col("Control_Next", "s50?"),
                col("Help", "l50?"),
            ],
        ),
        event: Table::new("ControlEvent", vec![col("Dialog_", "*s72"), col("Control_", "*s50"), col("Event", "*s50"), col("Argument", "*s255"), col("Condition", "*s255?"), col("Ordering", "i2?")]),
        mapping: Table::new("EventMapping", vec![col("Dialog_", "*s72"), col("Control_", "*s50"), col("Event", "*s50"), col("Attribute", "s50")]),
    };
    // Dialog attributes: visible, modal, minimize (+ keep modeless for progress).
    const MODAL: i32 = 1 | 2 | 4;
    let title = |t: &'static str| -> Ctl<'static> { ("Title", "Text", 20, 15, 330, 40, TEXT, None, Some(t), None) };
    let line = ("BottomLine", "Line", 0, 234, W, 0, VISIBLE, None, None, None);
    let install = if elevated { BUTTON | ELEVATION_SHIELD } else { BUTTON };

    b.dialog(
        "WelcomeDlg",
        MODAL,
        "Install",
        Some("Install"),
        Some("Cancel"),
        &[
            title("{\\DlgTitle}Welcome to the [ProductName] Setup"),
            ("Description", "Text", 20, 60, 330, 40, TEXT, None, Some("This will install [ProductName] [ProductVersion] on your computer. Click Install to continue, or Cancel to exit."), None),
            ("FolderLabel", "Text", 20, 110, 330, 12, TEXT, None, Some("It will be installed in:"), None),
            ("Folder", "Text", 20, 124, 330, 24, TEXT, None, Some("[INSTALLDIR]"), None),
            line,
            ("Install", "PushButton", 236, 243, 56, 17, install, None, Some("&Install"), Some("Cancel")),
            ("Cancel", "PushButton", 304, 243, 56, 17, BUTTON, None, Some("Cancel"), Some("Install")),
        ],
    );
    b.on("WelcomeDlg", "Install", "EndDialog", "Return", "1", 1);
    b.on("WelcomeDlg", "Cancel", "SpawnDialog", "CancelDlg", "1", 1);

    b.dialog(
        "ProgressDlg",
        1 | 4, // visible, minimize; modeless
        "Cancel",
        Some("Cancel"),
        Some("Cancel"),
        &[
            title("{\\DlgTitle}Installing [ProductName]"),
            ("Description", "Text", 20, 60, 330, 24, TEXT, None, Some("Please wait while [ProductName] is installed."), None),
            ("ActionText", "Text", 20, 100, 330, 12, TEXT, None, None, None),
            ("ProgressBar", "ProgressBar", 20, 116, 330, 12, VISIBLE | 1 << 16, None, Some("Progress done"), None),
            line,
            ("Cancel", "PushButton", 304, 243, 56, 17, BUTTON, None, Some("Cancel"), None),
        ],
    );
    b.on("ProgressDlg", "Cancel", "SpawnDialog", "CancelDlg", "1", 1);
    b.mapping.row(vec!["ProgressDlg".into(), "ProgressBar".into(), "SetProgress".into(), "Progress".into()]);
    b.mapping.row(vec!["ProgressDlg".into(), "ActionText".into(), "ActionText".into(), "Text".into()]);

    let finish = |b: &mut Builder, name: &str, heading: &'static str, body: &'static str, ret: &str| {
        b.dialog(
            name,
            MODAL,
            "Finish",
            Some("Finish"),
            Some("Finish"),
            &[title(heading), ("Description", "Text", 20, 60, 330, 60, TEXT, None, Some(body), None), line, ("Finish", "PushButton", 304, 243, 56, 17, BUTTON, None, Some("&Finish"), None)],
        );
        b.on(name, "Finish", "EndDialog", ret, "1", 1);
    };
    finish(&mut b, "ExitDialog", "{\\DlgTitle}[ProductName] is installed", "Click Finish to close Setup.", "Return");
    finish(&mut b, "UserExit", "{\\DlgTitle}[ProductName] Setup was cancelled", "[ProductName] wasn't installed. Run Setup again to install it.", "Exit");
    finish(&mut b, "FatalError", "{\\DlgTitle}[ProductName] Setup ended early", "An error stopped Setup before [ProductName] was installed. Nothing was changed.", "Exit");

    b.dialog(
        "CancelDlg",
        MODAL,
        "No",
        Some("No"),
        Some("No"),
        &[
            ("Text", "Text", 20, 30, 330, 30, TEXT, None, Some("Are you sure you want to cancel [ProductName] Setup?"), None),
            ("Yes", "PushButton", 236, 243, 56, 17, BUTTON, None, Some("&Yes"), Some("No")),
            ("No", "PushButton", 304, 243, 56, 17, BUTTON, None, Some("&No"), Some("Yes")),
        ],
    );
    b.on("CancelDlg", "Yes", "EndDialog", "Exit", "1", 1);
    b.on("CancelDlg", "No", "EndDialog", "Return", "1", 1);

    // The error dialog: Windows Installer shows the buttons it needs (A, C, I, N, O, R, Y).
    // Tab order: the text, then each button, back to the text.
    let mut err: Vec<Ctl> = vec![("ErrorText", "Text", 50, 15, 300, 60, TEXT, None, None, Some("A"))];
    let names = [("A", "&Abort"), ("C", "&Cancel"), ("I", "&Ignore"), ("N", "&No"), ("O", "&OK"), ("R", "&Retry"), ("Y", "&Yes")];
    for (k, (n, t)) in names.iter().enumerate() {
        let next = names.get(k + 1).map(|x| x.0).unwrap_or("ErrorText");
        err.push((n, "PushButton", 20 + 48 * k as i32, 243, 44, 17, BUTTON, None, Some(t), Some(next)));
    }
    b.dialog("ErrorDlg", MODAL | 0x10000, "ErrorText", Some("O"), Some("C"), &err); // + error dialog
    for (n, _) in names {
        let ret = match n {
            "A" => "ErrorAbort",
            "C" => "ErrorCancel",
            "I" => "ErrorIgnore",
            "N" => "ErrorNo",
            "O" => "ErrorOk",
            "R" => "ErrorRetry",
            _ => "ErrorYes",
        };
        b.on("ErrorDlg", n, "EndDialog", ret, "1", 1);
    }

    b.dialog(
        "FilesInUse",
        MODAL | 32, // + keep modeless (it can appear over the progress dialog)
        "Retry",
        Some("Retry"),
        Some("Retry"),
        &[
            ("Text", "Text", 20, 15, 330, 30, TEXT, None, Some("These applications are using files Setup needs to update. Close them and click Retry, or click Ignore to continue."), None),
            ("List", "ListBox", 20, 50, 330, 170, VISIBLE | ENABLED, Some("FileInUseProcess"), None, Some("Retry")),
            ("Retry", "PushButton", 170, 243, 56, 17, BUTTON, None, Some("&Retry"), Some("Ignore")),
            ("Ignore", "PushButton", 236, 243, 56, 17, BUTTON, None, Some("&Ignore"), Some("Exit")),
            ("Exit", "PushButton", 304, 243, 56, 17, BUTTON, None, Some("E&xit"), Some("List")),
        ],
    );
    b.on("FilesInUse", "Retry", "EndDialog", "Retry", "1", 1);
    b.on("FilesInUse", "Ignore", "EndDialog", "Ignore", "1", 1);
    b.on("FilesInUse", "Exit", "EndDialog", "Exit", "1", 1);

    let mut style = Table::new("TextStyle", vec![col("TextStyle", "*s72"), col("FaceName", "s32"), col("Size", "i2"), col("Color", "i4?"), col("StyleBits", "i2?")]);
    style.row(vec!["DefaultFont".into(), "Segoe UI".into(), 9.into(), Value::Null, Value::Null]);
    style.row(vec!["DlgTitle".into(), "Segoe UI".into(), 12.into(), Value::Null, 1.into()]);
    let mut uitext = Table::new("UIText", vec![col("Key", "*s72"), col("Text", "l255?")]);
    for (k, t) in
        [("bytes", "bytes"), ("KB", "KB"), ("MB", "MB"), ("GB", "GB"), ("AbsentPath", ""), ("NewFolder", "Folder|New Folder"), ("TimeRemaining", "Time remaining: {[1] minutes }{[2] seconds}")]
    {
        uitext.row(vec![k.into(), t.into()]);
    }
    // FilesInUse lists processes in a ListBox, filled at run time (ICE20 wants the table).
    let listbox = Table::new("ListBox", vec![col("Property", "*s72"), col("Order", "*i2"), col("Value", "s64"), col("Text", "l64?")]);
    let Builder { dialog, control, event, mapping } = b;
    Ui {
        tables: vec![dialog, control, event, mapping, style, uitext, listbox],
        sequence: vec![("FatalError", None, -3), ("UserExit", None, -2), ("ExitDialog", None, -1), ("WelcomeDlg", Some("NOT Installed"), 1230), ("ProgressDlg", None, 1280)],
        properties: vec![("DefaultUIFont", "DefaultFont"), ("ErrorDialog", "ErrorDlg")],
    }
}
