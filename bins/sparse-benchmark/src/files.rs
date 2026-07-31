use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use ssv_problem::GeneratedProblem;

pub(crate) const MAX_RUN_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct RunPaths {
    pub root: PathBuf,
}

impl RunPaths {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(crate) fn benchmark(&self) -> PathBuf {
        self.root.join("benchmark.json")
    }

    pub(crate) fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }

    pub(crate) fn lock(&self) -> PathBuf {
        self.root.join(".runner.lock")
    }

    pub(crate) fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    pub(crate) fn challenge(&self) -> PathBuf {
        self.public_dir().join("challenge.json")
    }

    pub(crate) fn problem(&self) -> PathBuf {
        self.public_dir().join("problem.json")
    }

    pub(crate) fn matrix(&self) -> PathBuf {
        self.public_dir().join("A.mtx")
    }

    pub(crate) fn rhs(&self) -> PathBuf {
        self.public_dir().join("b.mtx")
    }

    pub(crate) fn submission_dir(&self) -> PathBuf {
        self.root.join("submission")
    }

    pub(crate) fn solution(&self) -> PathBuf {
        self.submission_dir().join("x.json")
    }

    pub(crate) fn validation_dir(&self) -> PathBuf {
        self.root.join("validation")
    }

    pub(crate) fn proof(&self) -> PathBuf {
        self.validation_dir().join("proof.ssv")
    }

    pub(crate) fn certificate(&self) -> PathBuf {
        self.validation_dir().join("certificate.json")
    }

    pub(crate) fn card(&self) -> PathBuf {
        self.root.join("result-card.json")
    }
}

pub(crate) struct RunLock {
    _file: File,
}

impl RunLock {
    pub(crate) fn acquire(paths: &RunPaths) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(paths.lock())
            .with_context(|| format!("could not open run lock in {}", paths.root.display()))?;
        file.try_lock().with_context(|| {
            format!(
                "another runner process is already using {}",
                paths.root.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}

pub(crate) fn create_run_directory(parent: &Path, now: i64) -> Result<RunPaths> {
    fs::create_dir_all(parent)
        .with_context(|| format!("could not create run parent {}", parent.display()))?;
    let process = std::process::id();
    for suffix in 0_u16..1_000 {
        let name = if suffix == 0 {
            format!("run-{now}-{process}")
        } else {
            format!("run-{now}-{process}-{suffix}")
        };
        let paths = RunPaths::new(parent.join(name));
        match fs::create_dir(&paths.root) {
            Ok(()) => {
                fs::create_dir(paths.public_dir())?;
                fs::create_dir(paths.submission_dir())?;
                fs::create_dir(paths.validation_dir())?;
                return Ok(paths);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not create run directory {}", paths.root.display())
                });
            }
        }
    }
    bail!("could not allocate a unique run directory")
}

pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{} exceeds the {maximum}-byte input limit", path.display());
    }
    Ok(bytes)
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, maximum)?)
        .with_context(|| format!("invalid JSON in {}", path.display()))
}

pub(crate) fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_atomic(path, &bytes)
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, |output| output.write_all(bytes))
}

pub(crate) fn write_matrix_market_matrix(path: &Path, problem: &GeneratedProblem) -> Result<()> {
    write_atomic(path, |output| {
        let mut output = BufWriter::new(output);
        writeln!(output, "%%MatrixMarket matrix coordinate real general")?;
        writeln!(output, "% problem_digest {}", problem.problem_digest())?;
        writeln!(
            output,
            "% coefficient_fractional_bits {}",
            problem.certificate().coefficient_fractional_bits
        )?;
        writeln!(
            output,
            "% indices one-based; values binary64 round-trip decimal"
        )?;
        writeln!(
            output,
            "{} {} {}",
            problem.dimension(),
            problem.dimension(),
            problem.structural_nonzeros()
        )?;
        for row_index in 0..problem.dimension() {
            let row = problem.row(row_index).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "validated generator omitted an in-bounds row",
                )
            })?;
            for entry in row {
                writeln!(
                    output,
                    "{} {} {}",
                    row_index + 1,
                    entry.column + 1,
                    entry.value.to_f64()
                )?;
            }
        }
        output.flush()
    })
}

pub(crate) fn write_matrix_market_rhs(path: &Path, problem: &GeneratedProblem) -> Result<()> {
    write_atomic(path, |output| {
        let mut output = BufWriter::new(output);
        writeln!(output, "%%MatrixMarket matrix array real general")?;
        writeln!(output, "% problem_digest {}", problem.problem_digest())?;
        writeln!(
            output,
            "% rhs_fractional_bits {}",
            problem.certificate().rhs_fractional_bits
        )?;
        writeln!(output, "% values binary64 round-trip decimal")?;
        writeln!(output, "{} 1", problem.dimension())?;
        for row_index in 0..problem.dimension() {
            let value = problem.rhs_f64(row_index).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "validated generator omitted an in-bounds RHS entry",
                )
            })?;
            writeln!(output, "{value}")?;
        }
        output.flush()
    })
}

fn write_atomic(path: &Path, write: impl FnOnce(&mut File) -> std::io::Result<()>) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    let process = std::process::id();
    let mut temporary = None;
    for suffix in 0_u16..1_000 {
        let candidate = parent.join(format!(".ssv-tmp-{process}-{suffix}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("could not create temporary output file"),
        }
    }
    let (temporary_path, mut file) = temporary.context("could not allocate a temporary file")?;
    let result = (|| -> Result<()> {
        write(&mut file).with_context(|| format!("could not write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("could not synchronize {}", path.display()))?;
        drop(file);
        fs::rename(&temporary_path, path)
            .with_context(|| format!("could not publish {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}
