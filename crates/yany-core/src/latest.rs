use std::sync::Mutex;

/// Keeps only the newest item. Producers never block; consumers skip stale work.
#[derive(Debug, Default)]
pub struct LatestSlot<T> {
    inner: Mutex<Option<T>>,
}

impl<T> LatestSlot<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn push(&self, value: T) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(value);
        }
    }

    pub fn take(&self) -> Option<T> {
        self.inner.lock().ok().and_then(|mut g| g.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_newest() {
        let slot = LatestSlot::new();
        slot.push(1u32);
        slot.push(2);
        slot.push(9);
        assert_eq!(slot.take(), Some(9));
        assert_eq!(slot.take(), None);
    }
}
