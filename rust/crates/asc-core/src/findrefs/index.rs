//! A multimap from a `u32` key to ascending `u32` ids, as the locators'
//! `defaultdict(set)` maps: `(key, id)` pairs sorted once, looked up by binary
//! search. DEX tables are mostly in key order already, so the sort is close to
//! linear, and there is no hashing and no allocation per key.

pub(crate) struct Index {
    keys: Vec<u32>,
    ids: Vec<u32>,
}

impl Index {
    pub(crate) fn build(mut pairs: Vec<(u32, u32)>) -> Self {
        pairs.sort_unstable();
        let (keys, ids) = pairs.into_iter().unzip();
        Self { keys, ids }
    }

    /// The ids of `key`, ascending.
    pub(crate) fn get(&self, key: u32) -> &[u32] {
        let lo = self.keys.partition_point(|&k| k < key);
        let hi = self.keys.partition_point(|&k| k <= key);
        self.ids.get(lo..hi).unwrap_or_default()
    }

    /// Every key with its ids, ascending by key.
    pub(crate) fn entries(&self) -> Vec<(u32, &[u32])> {
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(&key) = self.keys.get(start) {
            let end = start.saturating_add(
                self.keys
                    .get(start..)
                    .unwrap_or_default()
                    .partition_point(|&k| k == key),
            );
            out.push((key, self.ids.get(start..end).unwrap_or_default()));
            start = end;
        }
        out
    }
}
