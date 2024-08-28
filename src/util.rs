use crate::collections::BTreeMap;
use crate::{vec::Vec, MMRStoreReadOps, MMRStoreWriteOps, Result, MMR};
use core::cell::RefCell;

#[derive(Clone)]
pub struct MemStore<T>(RefCell<BTreeMap<u64, T>>);

impl<T> Default for MemStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MemStore<T> {
    fn new() -> Self {
        MemStore(RefCell::new(Default::default()))
    }
}

impl<T: Clone> MMRStoreReadOps<T> for &MemStore<T> {
    fn get_elem(&self, pos: u64) -> Result<Option<T>> {
        Ok(self.0.borrow().get(&pos).cloned())
    }
}

impl<T> MMRStoreWriteOps<T> for &MemStore<T> {
    fn append(&mut self, pos: u64, elems: Vec<T>) -> Result<()> {
        let mut store = self.0.borrow_mut();
        for (i, elem) in elems.into_iter().enumerate() {
            store.insert(pos + i as u64, elem);
        }
        Ok(())
    }
}

pub type MemMMR<'a, T, M> = MMR<T, M, &'a MemStore<T>>;

pub trait BTreeMapExt<K, V> {
    fn checked_insert(&mut self, key: K, value: V) -> bool;
}

impl<K: Ord, V: PartialEq> BTreeMapExt<K, V> for BTreeMap<K, V> {
    fn checked_insert(&mut self, key: K, value: V) -> bool {
        use crate::BTreeMapEntry;

        let entry = self.entry(key);
        match entry {
            BTreeMapEntry::Vacant(slot) => {
                slot.insert(value);
            }
            BTreeMapEntry::Occupied(old_value) => {
                if old_value.get() != &value {
                    return false;
                }
            }
        }

        true
    }
}
