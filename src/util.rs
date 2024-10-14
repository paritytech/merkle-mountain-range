use crate::collections::{BTreeMap, VecDeque};
use crate::{vec::Vec, MMRStoreReadOps, MMRStoreWriteOps, Result, MMR};
use core::cell::RefCell;
use core::cmp::Ordering;

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

pub trait VeqDequeExt<T> {
    fn insert_sorted(&mut self, value: T)
    where
        T: Ord;

    fn insert_sorted_by<F: FnMut(&T, &T) -> Ordering>(&mut self, value: T, f: F) -> bool;
}

impl<T: PartialEq> VeqDequeExt<T> for VecDeque<T> {
    fn insert_sorted(&mut self, value: T)
    where
        T: Ord,
    {
        self.insert_sorted_by(value, |a, b| a.cmp(b));
    }

    fn insert_sorted_by<F: FnMut(&T, &T) -> Ordering>(&mut self, value: T, mut f: F) -> bool {
        match self.binary_search_by(|x| f(x, &value)) {
            Ok(pos) => {
                // element already in vector @ `pos`
                if self[pos] != value {
                    return false;
                }
            }
            Err(pos) => self.insert(pos, value),
        }

        true
    }
}
