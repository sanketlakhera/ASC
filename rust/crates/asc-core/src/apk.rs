//! Per-entry work over an APK's DEX entries (`ApkHandler.for_each_findrefs`).
//!
//! Entries run on a pool of threads and their results are handed back in entry
//! order, whatever order they finish in. A failed entry is held like any other
//! result and reported when the cursor reaches it: every entry before it is
//! emitted, none after it.

use crate::dex::iter_logical_dex_buffers;
use crate::error::AscError;
use crate::findrefs::{self, Query};
use crate::inflate::inflate_entry;
use crate::zip::DexEntry;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

/// Runs `work` over `items` on up to `workers` threads. `on_done` sees each
/// successful result as it completes; `emit` receives results in item order.
/// The first error in item order (from `work` or `emit`) is returned once the
/// work in flight has finished; no later item is emitted.
pub fn map_ordered<T, R, W, D, E>(
    items: &[T],
    workers: usize,
    work: W,
    mut on_done: D,
    mut emit: E,
) -> Result<(), AscError>
where
    T: Sync,
    R: Send,
    W: Fn(&T) -> Result<R, AscError> + Sync,
    D: FnMut(&R),
    E: FnMut(R) -> Result<(), AscError>,
{
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let workers = workers.clamp(1, items.len().max(1));
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<(usize, Result<R, AscError>)>();
        for _ in 0..workers {
            let tx = tx.clone();
            let (next, stop, work) = (&next, &stop, &work);
            scope.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(idx) else { break };
                    if tx.send((idx, work(item))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);

        let mut ready: BTreeMap<usize, Result<R, AscError>> = BTreeMap::new();
        let mut cursor = 0;
        let mut outcome = Ok(());
        for (idx, result) in rx {
            if let Ok(r) = &result {
                on_done(r);
            }
            ready.insert(idx, result);
            while let Some(result) = ready.remove(&cursor) {
                cursor = cursor.saturating_add(1);
                if let Err(e) = result.and_then(&mut emit) {
                    outcome = Err(e);
                    break;
                }
            }
            if outcome.is_err() {
                // No new entries; the scope still joins the ones in flight.
                stop.store(true, Ordering::Relaxed);
                break;
            }
        }
        outcome
    })
}

/// One DEX entry's findrefs result (`_findrefs_worker`).
pub struct EntryRefs {
    pub name: String,
    /// Lines of every logical DEX of the entry, as UTF-16 units.
    pub lines: Vec<Vec<u16>>,
    pub inflate_us: f64,
    pub process_us: f64,
}

/// `_findrefs_worker`: inflate the entry, then search each logical DEX.
pub fn findrefs_entry(apk: &[u8], entry: &DexEntry, query: &Query) -> Result<EntryRefs, AscError> {
    let t0 = Instant::now();
    let data = inflate_entry(apk, entry, None)?.unwrap_or_default();
    let t1 = Instant::now();
    let mut lines = Vec::new();
    for (name, buf) in iter_logical_dex_buffers(&entry.name, &data) {
        lines.extend(findrefs::findrefs(&name, &buf, query)?);
    }
    let t2 = Instant::now();
    Ok(EntryRefs {
        name: entry.name.clone(),
        lines,
        inflate_us: (t1 - t0).as_secs_f64() * 1e6,
        process_us: (t2 - t1).as_secs_f64() * 1e6,
    })
}
