//! PyO3 binding for the IntakeGuard core. The GIL is released while the engine runs; reads from a
//! Python file object re-acquire it per chunk.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};

use intakeguard_core::{Claimed, Mode, Outcome, Policy};

type Ret = (String, &'static str, u64, Option<Py<PyBytes>>);

fn ret(py: Python<'_>, o: Outcome) -> Ret {
    let out = o.output.map(|b| PyBytes::new(py, &b).unbind());
    (o.report.to_string(), o.decision.as_str(), o.bytes_read, out)
}

#[pyclass(module = "intakeguard._native", frozen)]
#[derive(Clone, Default)]
struct CancelToken(Arc<AtomicBool>);

#[pymethods]
impl CancelToken {
    #[new]
    fn new() -> Self { Self::default() }
    fn cancel(&self) { self.0.store(true, Ordering::Relaxed) }
    #[getter]
    fn cancelled(&self) -> bool { self.0.load(Ordering::Relaxed) }
}

#[pyclass(module = "intakeguard._native", frozen)]
struct CompiledPolicy(Policy);

#[pymethods]
impl CompiledPolicy {
    #[new]
    fn new(json: &str) -> PyResult<Self> {
        Policy::from_json(json).map(CompiledPolicy).map_err(PyValueError::new_err)
    }
    #[getter]
    fn digest(&self) -> String { self.0.digest() }
}

fn mode(sanitize: bool) -> Mode { if sanitize { Mode::Sanitize } else { Mode::Inspect } }

/// Returns (report_json, decision, bytes_read, output_bytes_or_None).
#[pyfunction]
#[pyo3(signature = (data, policy, filename=None, mime=None, cancel=None, sanitize=false))]
fn process_bytes(py: Python<'_>, data: &Bound<'_, PyAny>, policy: &CompiledPolicy, filename: Option<String>,
                 mime: Option<String>, cancel: Option<CancelToken>, sanitize: bool) -> PyResult<Ret> {
    let claimed = Claimed { filename, mime };
    let tok = cancel.map(|c| c.0);
    let m = mode(sanitize);
    let run = |buf: &[u8]| -> Outcome {
        py.allow_threads(|| intakeguard_core::process_bytes(buf, &policy.0, &claimed, tok.as_deref(), m))
    };
    if let Ok(b) = data.downcast::<PyBytes>() {
        Ok(ret(py, run(b.as_bytes())))
    } else if let Ok(b) = data.downcast::<PyByteArray>() {
        let v = b.to_vec(); // a bytearray may be mutated by another thread; copy first
        Ok(ret(py, run(&v)))
    } else {
        Err(PyValueError::new_err("data must be bytes or bytearray"))
    }
}

/// Reads a Python binary file-like object (anything with .read(n)) in fixed chunks.
struct PyReader { f: Py<PyAny>, err: Option<PyErr> }

impl Read for PyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Python::with_gil(|py| {
            let r = self.f.bind(py).call_method1("read", (buf.len(),)).and_then(|o| {
                let b = o.downcast_into::<PyBytes>()?;
                let s = b.as_bytes();
                if s.len() > buf.len() {
                    return Err(PyValueError::new_err("read(n) returned more than n bytes"));
                }
                buf[..s.len()].copy_from_slice(s);
                Ok(s.len())
            });
            r.map_err(|e| {
                let msg = e.to_string();
                self.err = Some(e);
                std::io::Error::other(msg)
            })
        })
    }
}

#[pyfunction]
#[pyo3(signature = (stream, policy, filename=None, mime=None, cancel=None, sanitize=false))]
fn process_stream(py: Python<'_>, stream: Py<PyAny>, policy: &CompiledPolicy, filename: Option<String>,
                  mime: Option<String>, cancel: Option<CancelToken>, sanitize: bool) -> PyResult<Ret> {
    let claimed = Claimed { filename, mime };
    let tok = cancel.map(|c| c.0);
    let mut reader = PyReader { f: stream, err: None };
    let m = mode(sanitize);
    let o = py.allow_threads(|| intakeguard_core::process_reader(&mut reader, &policy.0, &claimed, tok.as_deref(), m));
    // A read failure is reported as verdict=error in the report; the Python exception is not re-raised
    // so callers get one uniform fail-closed path.
    drop(reader.err.take());
    Ok(ret(py, o))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ENGINE_VERSION", intakeguard_core::ENGINE_VERSION)?;
    m.add("STREAM_CHUNK", intakeguard_core::STREAM_CHUNK)?;
    m.add_class::<CancelToken>()?;
    m.add_class::<CompiledPolicy>()?;
    m.add_function(wrap_pyfunction!(process_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(process_stream, m)?)?;
    Ok(())
}
