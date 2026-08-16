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

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use crate::fxhash::FxHashSet;

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
/// quiche recomputes a connection's timeout on nearly every `recv` and `send`,
/// so entries are never removed when a deadline moves. A superseded entry is
/// left in the heap and discarded when it surfaces, by checking it against the
/// deadline the connection currently holds — see
/// `Server::expire_connection_timers`. Stale entries are always in the past
/// relative to the live one, so they surface and die promptly rather than
/// accumulating.
#[derive(Default)]
pub(crate) struct TimerQueue {
    heap: BinaryHeap<Reverse<Timer>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Timer {
    at: Instant,
    index: u64,
}

impl TimerQueue {
    /// Wake `index` at `at`. Any earlier entry for the same connection stays in
    /// the heap and is rejected as stale when it surfaces.
    pub(crate) fn schedule(&mut self, index: u64, at: Instant) {
        self.heap.push(Reverse(Timer { at, index }));
    }

    /// The earliest scheduled deadline, stale entries included.
    ///
    /// A stale entry only makes the loop wake early and find nothing to do, so
    /// it costs an iteration rather than correctness.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|Reverse(timer)| timer.at)
    }

    /// Pop every entry due at `now`, passing each `(index, deadline)` to
    /// `fire`. The caller decides whether an entry is still live.
    pub(crate) fn expire(&mut self, now: Instant, mut fire: impl FnMut(u64, Instant)) {
        while let Some(Reverse(timer)) = self.heap.peek() {
            if timer.at > now {
                break;
            }
            let at = timer.at;
            let index = timer.index;
            self.heap.pop();
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
        assert_eq!(timers.next_deadline(), None);

        timers.schedule(1, now + Duration::from_millis(50));
        timers.schedule(2, now + Duration::from_millis(10));
        timers.schedule(3, now + Duration::from_millis(30));

        assert_eq!(
            timers.next_deadline(),
            Some(now + Duration::from_millis(10))
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
            timers.next_deadline(),
            Some(now + Duration::from_millis(50))
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
    fn timer_queue_surfaces_superseded_entries_for_the_caller_to_reject() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();

        // A deadline pushed out to a later time leaves the earlier entry behind.
        let stale = now + Duration::from_millis(10);
        let live = now + Duration::from_millis(40);
        timers.schedule(1, stale);
        timers.schedule(1, live);

        let mut fired = Vec::new();
        timers.expire(now + Duration::from_millis(40), |index, at| {
            fired.push((index, at));
        });

        // Both surface; only the caller knows which deadline is current.
        assert_eq!(fired, [(1, stale), (1, live)]);
        assert_eq!(timers.len(), 0);
    }
}
