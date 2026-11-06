// Wakeup bookkeeping for the connection event loop.
//
// The loop used to touch every connection on every iteration: once to find the
// earliest timer, then again to drive quiche, flush tunnels, and reap closed
// connections. A single arriving packet therefore cost O(connections) of work,
// and the 50ms wakeup cap repeated that scan 20 times a second while idle.
//
// This module replaces both halves of the scan:
//
// - `DirtySet` names the connections that actually have work pending, so a
//   round services only those.
// - `TimerQueue` orders connections by their next deadline, so the loop can ask
//   for the earliest one instead of computing a minimum over all of them.

use std::time::Instant;

use crate::fxhash::{FxHashMap, FxHashSet};

/// The connections with work pending for the current round.
///
/// Arrival order is preserved so a connection is serviced in the order its
/// event landed, and membership is deduplicated so several events on one
/// connection still cost a single visit.
///
/// Membership outlives [`take_into`](Self::take_into) so that work discovered
/// partway through a round — the idle sweep closing a tunnel, say — can be
/// appended without servicing a connection twice. [`end_round`](Self::end_round)
/// clears it.
#[derive(Default)]
pub(crate) struct DirtySet {
    pending: Vec<u64>,
    seen: FxHashSet<u64>,
}

impl DirtySet {
    /// Record that `index` needs servicing this round.
    pub(crate) fn mark(&mut self, index: u64) {
        if self.seen.insert(index) {
            self.pending.push(index);
        }
    }

    /// Append everything marked since the last call to `out`.
    ///
    /// Connections already taken this round are not repeated, so this can be
    /// called several times within one round.
    pub(crate) fn take_into(&mut self, out: &mut Vec<u64>) {
        out.append(&mut self.pending);
    }

    /// Forget this round's membership. Both allocations are retained.
    pub(crate) fn end_round(&mut self) {
        self.pending.clear();
        self.seen.clear();
    }
}

/// A deadline-ordered queue of connection wakeups.
///
/// An indexed min-heap keeps exactly one entry per scheduled connection.
/// Replacing and cancelling deadlines cost O(log n); storage is bounded by
/// peak live connections, independent of packet rate or deadline churn.
/// `positions` is a bijection between connection indices and heap positions.
#[derive(Default)]
pub(crate) struct TimerQueue {
    heap: Vec<Timer>,
    positions: FxHashMap<u64, usize>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Timer {
    at: Instant,
    index: u64,
}

impl TimerQueue {
    /// Insert or replace a connection's deadline without retaining stale entries.
    pub(crate) fn schedule(&mut self, index: u64, at: Instant) {
        if let Some(&position) = self.positions.get(&index) {
            self.heap[position].at = at;
            self.repair(position);
        } else {
            let position = self.heap.len();
            self.heap.push(Timer { at, index });
            self.positions.insert(index, position);
            self.sift_up(position);
        }
    }

    /// Remove a disarmed or closed connection immediately.
    pub(crate) fn cancel(&mut self, index: u64) {
        let Some(position) = self.positions.remove(&index) else {
            return;
        };
        self.heap.swap_remove(position);
        if position < self.heap.len() {
            *self.positions.get_mut(&self.heap[position].index).unwrap() = position;
            self.repair(position);
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        *self.positions.get_mut(&self.heap[a].index).unwrap() = a;
        *self.positions.get_mut(&self.heap[b].index).unwrap() = b;
    }

    fn sift_up(&mut self, mut position: usize) {
        while position > 0 {
            let parent = (position - 1) / 2;
            if self.heap[parent] <= self.heap[position] {
                break;
            }
            self.swap(parent, position);
            position = parent;
        }
    }

    fn repair(&mut self, mut position: usize) {
        if position > 0 && self.heap[position] < self.heap[(position - 1) / 2] {
            self.sift_up(position);
            return;
        }
        loop {
            let left = 2 * position + 1;
            if left >= self.heap.len() {
                break;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[position] <= self.heap[child] {
                break;
            }
            self.swap(position, child);
            position = child;
        }
    }

    /// The earliest live deadline.
    pub(crate) fn next_wakeup(&self) -> Option<(u64, Instant)> {
        self.heap.first().map(|timer| (timer.index, timer.at))
    }

    /// Pop every entry due at `now`, passing each `(index, deadline)` to
    /// `fire` after removing it from the queue.
    pub(crate) fn expire(&mut self, now: Instant, mut fire: impl FnMut(u64, Instant)) {
        while let Some(timer) = self.heap.first() {
            if timer.at > now {
                break;
            }
            let at = timer.at;
            let index = timer.index;
            self.cancel(index);
            fire(index, at);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.heap.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dirty_set_preserves_order_and_deduplicates() {
        let mut dirty = DirtySet::default();
        dirty.mark(7);
        dirty.mark(3);
        dirty.mark(7);

        let mut taken = Vec::new();
        dirty.take_into(&mut taken);
        assert_eq!(taken, [7, 3]);
    }

    #[test]
    fn dirty_set_appends_late_marks_without_repeating() {
        let mut dirty = DirtySet::default();
        dirty.mark(1);

        let mut taken = Vec::new();
        dirty.take_into(&mut taken);

        // The idle sweep marking a connection already serviced this round must
        // not queue it a second time, but a new one must still be picked up.
        dirty.mark(1);
        dirty.mark(2);
        dirty.take_into(&mut taken);
        assert_eq!(taken, [1, 2]);
    }

    #[test]
    fn dirty_set_round_boundary_allows_remarking() {
        let mut dirty = DirtySet::default();
        dirty.mark(1);
        let mut taken = Vec::new();
        dirty.take_into(&mut taken);

        dirty.end_round();
        taken.clear();

        dirty.mark(1);
        dirty.take_into(&mut taken);
        assert_eq!(taken, [1]);
    }

    #[test]
    fn end_round_drops_marks_never_taken() {
        let mut dirty = DirtySet::default();
        dirty.mark(4);
        dirty.end_round();

        let mut taken = Vec::new();
        dirty.take_into(&mut taken);
        assert!(taken.is_empty());
    }

    #[test]
    fn timer_queue_reports_earliest_deadline() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        assert_eq!(timers.next_wakeup(), None);

        timers.schedule(1, now + Duration::from_millis(50));
        timers.schedule(2, now + Duration::from_millis(10));
        timers.schedule(3, now + Duration::from_millis(30));

        assert_eq!(
            timers.next_wakeup(),
            Some((2, now + Duration::from_millis(10)))
        );
    }

    #[test]
    fn timer_queue_expires_due_entries_in_order() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        timers.schedule(1, now + Duration::from_millis(30));
        timers.schedule(2, now + Duration::from_millis(10));
        timers.schedule(3, now + Duration::from_millis(50));

        let mut fired = Vec::new();
        timers.expire(now + Duration::from_millis(30), |index, _| {
            fired.push(index)
        });

        assert_eq!(fired, [2, 1]);
        // The future entry is untouched.
        assert_eq!(timers.len(), 1);
        assert_eq!(
            timers.next_wakeup(),
            Some((3, now + Duration::from_millis(50)))
        );
    }

    #[test]
    fn timer_queue_expires_nothing_before_the_deadline() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        timers.schedule(1, now + Duration::from_millis(10));

        let mut fired = Vec::new();
        timers.expire(now, |index, _| fired.push(index));
        assert!(fired.is_empty());
        assert_eq!(timers.len(), 1);
    }

    #[test]
    fn timer_queue_replaces_superseded_entries() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();

        let stale = now + Duration::from_millis(10);
        let live = now + Duration::from_millis(40);
        timers.schedule(1, stale);
        timers.schedule(1, live);

        let mut fired = Vec::new();
        timers.expire(now + Duration::from_millis(40), |index, at| {
            fired.push((index, at));
        });

        assert_eq!(fired, [(1, live)]);
        assert_eq!(timers.len(), 0);
    }

    #[test]
    fn deadline_churn_has_connection_bounded_storage() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        for i in 0..100_000 {
            timers.schedule(7, now + Duration::from_micros(i));
        }
        assert_eq!(timers.len(), 1);
        assert_eq!(timers.positions.len(), 1);
        assert!(timers.heap.capacity() <= 4);
        timers.cancel(7);
        assert_eq!(timers.next_wakeup(), None);
        assert!(timers.positions.is_empty());
    }

    #[test]
    fn replacement_cancellation_and_expiry_match_reference() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        let mut reference = std::collections::BTreeMap::new();
        let mut random = 17_u64;
        for _ in 0..20_000 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = (random >> 32) % 128;
            let at = now + Duration::from_millis((random >> 16) % 1_000);
            match random % 5 {
                0 => {
                    timers.cancel(index);
                    reference.remove(&index);
                }
                1 => {
                    let mut expected: Vec<_> = reference
                        .iter()
                        .filter(|(_, deadline)| **deadline <= at)
                        .map(|(&id, &deadline)| (deadline, id))
                        .collect();
                    expected.sort_unstable();
                    let mut fired = Vec::new();
                    timers.expire(at, |id, deadline| {
                        fired.push((deadline, id));
                        reference.remove(&id);
                    });
                    assert_eq!(fired, expected);
                }
                _ => {
                    timers.schedule(index, at);
                    reference.insert(index, at);
                }
            }
            assert_eq!(timers.len(), reference.len());
            assert_eq!(timers.positions.len(), reference.len());
            let next = reference.iter().map(|(&id, &at)| (at, id)).min();
            assert_eq!(timers.next_wakeup(), next.map(|(at, id)| (id, at)));
            for (position, timer) in timers.heap.iter().enumerate() {
                assert_eq!(timers.positions[&timer.index], position);
            }
        }
    }
}
