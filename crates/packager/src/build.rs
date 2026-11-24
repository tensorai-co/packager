//! Orchestration: validate everything up front, then build each package in the order that
//! signing requires (inner code, bundles, containers), sharing one signed `.app`.

use std::path::PathBuf;

use crate::app::App;
use crate::error::IoContext;
use crate::package::{AppBundle, Context, Package, PackageBuilder, PackageKind};
use crate::notary::Notarize;
use crate::sign::{Apple, AppleIdentity};
use crate::Error;
use crate::Result;

/// Starts a build of `app`.
pub fn build(app: &App) -> Builder<'_> {
    Builder { app, packages: Vec::new(), apple: None, notarize: None, out_dir: PathBuf::from("target/dist"), app_bundle: AppBundle::new() }
}

/// Collects packages and signing settings; [`Builder::run`] writes them.
pub struct Builder<'a> {
    app: &'a App,
    packages: Vec<Box<dyn PackageBuilder>>,
    apple: Option<Apple>,
    notarize: Option<Notarize>,
    out_dir: PathBuf,
    app_bundle: AppBundle,
}

impl<'a> Builder<'a> {
    /// Adds a package to build.
    pub fn package(mut self, p: impl PackageBuilder + 'static) -> Self {
        self.packages.push(Box::new(p));
        self
    }
    /// Apple signing for binaries, bundles and installers. Without it, macOS code is signed ad
    /// hoc (Apple silicon won't run unsigned code).
    pub fn sign(mut self, apple: Apple) -> Self {
        self.apple = Some(apple);
        self
    }
    /// Notarizes and staples every macOS package after it's built and signed (needs Developer
    /// ID signing; `.pkg` files also need an installer identity).
    pub fn notarize(mut self, n: Notarize) -> Self {
        self.notarize = Some(n);
        self
    }
    /// The `.app` settings used by every macOS package (the `.dmg` and `.pkg` wrap this bundle).
    pub fn app_bundle(mut self, b: AppBundle) -> Self {
        self.app_bundle = b;
        self
    }
    /// Where packages are written (default `target/dist`).
    pub fn out_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.out_dir = dir.into();
        self
    }

    /// Validates, then builds every package.
    pub fn run(self) -> Result<Output> {
        self.app.validate()?;
        let needs_app = self.packages.iter().any(|p| matches!(p.kind(), PackageKind::App | PackageKind::Dmg | PackageKind::Pkg));
        if needs_app {
            self.app_bundle.check(self.app)?;
        }
        for p in &self.packages {
            p.validate(self.app)?;
        }
        if self.notarize.is_some() {
            let apple = self.apple.as_ref();
            if !apple.is_some_and(|a| matches!(a.application, AppleIdentity::Signer(_))) {
                return Err(Error::invalid("notarize", "sign", "notarization needs a Developer ID Application identity, not ad-hoc signing"));
            }
            if self.packages.iter().any(|p| p.kind() == PackageKind::Pkg) && !apple.is_some_and(|a| a.installer.is_some()) {
                return Err(Error::invalid("notarize", "sign.installer", "notarizing a .pkg needs a Developer ID Installer identity"));
            }
        }
        std::fs::create_dir_all(&self.out_dir).at(&self.out_dir)?;
        let work = self.out_dir.join(format!(".packager-work-{}", std::process::id()));
        if work.exists() {
            std::fs::remove_dir_all(&work).at(&work)?;
        }
        std::fs::create_dir_all(&work).at(&work)?;
        let mut ctx = Context::new(self.app, self.out_dir.clone(), work.clone(), self.apple.as_ref(), self.app_bundle.clone());
        // Bundles before containers, so a requested `.app` is reused by the `.dmg` and `.pkg`.
        let mut order: Vec<&Box<dyn PackageBuilder>> = self.packages.iter().collect();
        order.sort_by_key(|p| p.kind() != PackageKind::App);
        let mut packages = Vec::new();
        let result = (|| -> Result<()> {
            for p in order {
                packages.extend(p.build(&mut ctx)?);
            }
            // Containers first: their tickets cover the .app inside, so a requested .app can
            // usually be stapled without a submission of its own.
            if let Some(n) = &self.notarize {
                let mut idx: Vec<usize> = (0..packages.len()).collect();
                idx.sort_by_key(|&i| packages[i].kind() == PackageKind::App);
                for i in idx {
                    n.run(packages[i].path())?;
                    packages[i].mark_notarized()?;
                }
            }
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&work);
        result?;
        Ok(Output { packages })
    }
}

/// What a build produced.
#[derive(Debug, Clone)]
pub struct Output {
    packages: Vec<Package>,
}

impl Output {
    /// Every package written, in build order.
    pub fn packages(&self) -> &[Package] {
        &self.packages
    }
}
