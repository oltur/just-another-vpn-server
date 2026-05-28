//! Sliding replay window for the OpenVPN data channel.
//!
//! Inbound data packets carry a monotonically increasing 32-bit `packet_id`.
//! After AEAD authentication succeeds, the id is fed through this window so
//! that authenticated-but-replayed packets are rejected and out-of-order
//! delivery within `WINDOW_SIZE` is still accepted.

/// Number of past packet IDs we track. OpenVPN's default is 64.
pub const WINDOW_SIZE: u32 = 64;

#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    /// Highest `packet_id` we have ever accepted. Bit 0 of `bitmap` represents
    /// this id; bit `n` represents `highest - n`.
    highest: u32,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the packet is acceptable and records it as seen.
    /// Returns `false` for the reserved id `0`, for duplicates within the
    /// window, and for ids older than the window.
    pub fn check_and_set(&mut self, packet_id: u32) -> bool {
        if packet_id == 0 {
            return false;
        }
        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = packet_id;
            true
        } else {
            let diff = self.highest - packet_id;
            if diff >= WINDOW_SIZE {
                return false;
            }
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                false
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order() {
        let mut w = ReplayWindow::new();
        for pid in 1..=10 {
            assert!(w.check_and_set(pid), "should accept {pid}");
        }
    }

    #[test]
    fn rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(5));
        assert!(!w.check_and_set(5));
    }

    #[test]
    fn accepts_within_window_out_of_order() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10));
        assert!(w.check_and_set(8));
        assert!(w.check_and_set(9));
        // 8 and 9 are now duplicates.
        assert!(!w.check_and_set(8));
        assert!(!w.check_and_set(9));
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(100));
        // 100 - WINDOW_SIZE (64) = 36 → ids <= 36 are out of window.
        assert!(!w.check_and_set(36));
        assert!(!w.check_and_set(1));
        // 37 is in-window.
        assert!(w.check_and_set(37));
    }

    #[test]
    fn rejects_zero() {
        let mut w = ReplayWindow::new();
        assert!(!w.check_and_set(0));
    }

    #[test]
    fn large_jump_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        // A jump of >= 64 wipes the bitmap and only the new id is recorded.
        assert!(w.check_and_set(1_000));
        // 1 is now far out of window.
        assert!(!w.check_and_set(1));
        // The new id is a duplicate now.
        assert!(!w.check_and_set(1_000));
    }
}
