// Clock interface implementation - Requirement 6

use crate::error::{HalError, HalResult};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Clock interface for time operations
#[derive(Debug)]
pub struct ClockInterface {
    monotonic_start: Instant,
    timezone_offset: Option<Duration>,
}

/// Time information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInfo {
    pub seconds: u64,
    pub nanoseconds: u32,
    pub timezone_offset_seconds: i32,
}

/// Monotonic time information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonotonicTime {
    pub elapsed_seconds: u64,
    pub elapsed_nanoseconds: u32,
}

impl ClockInterface {
    /// Create a new clock interface
    pub fn new() -> Self {
        Self {
            monotonic_start: Instant::now(),
            timezone_offset: None,
        }
    }

    /// Read current system time
    pub fn read_current_time(&self) -> HalResult<TimeInfo> {
        let now = SystemTime::now();
        let duration_since_epoch = now
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HalError::Internal(format!("System time error: {}", e)))?;

        let timezone_offset_seconds = self.timezone_offset
            .map(|offset| offset.as_secs() as i32)
            .unwrap_or(0);

        Ok(TimeInfo {
            seconds: duration_since_epoch.as_secs(),
            nanoseconds: duration_since_epoch.subsec_nanos(),
            timezone_offset_seconds,
        })
    }

    /// Read timezone information
    pub fn read_timezone(&self) -> HalResult<i32> {
        // In a real implementation, this would read from system timezone settings
        // For now, return UTC (0) or cached timezone offset
        Ok(self.timezone_offset
            .map(|offset| offset.as_secs() as i32)
            .unwrap_or(0))
    }

    /// Set timezone offset (in seconds from UTC)
    pub fn set_timezone(&mut self, offset_seconds: i32) -> HalResult<()> {
        if offset_seconds.abs() > 12 * 3600 {
            return Err(HalError::InvalidParameter(
                "Timezone offset must be between -12 and +12 hours".to_string()
            ));
        }

        self.timezone_offset = if offset_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(offset_seconds.abs() as u64))
        };

        Ok(())
    }

    /// Start a new monotonic timer (reset the baseline)
    pub fn start_monotonic_timer(&mut self) -> HalResult<()> {
        self.monotonic_start = Instant::now();
        Ok(())
    }

    /// Read elapsed time from monotonic clock
    pub fn read_monotonic_time(&self) -> HalResult<MonotonicTime> {
        let elapsed = self.monotonic_start.elapsed();
        
        Ok(MonotonicTime {
            elapsed_seconds: elapsed.as_secs(),
            elapsed_nanoseconds: elapsed.subsec_nanos(),
        })
    }

    /// Stop and read elapsed time from monotonic clock
    pub fn stop_and_read_monotonic(&self) -> HalResult<MonotonicTime> {
        // Same as read_monotonic_time, but semantically indicates stopping
        self.read_monotonic_time()
    }

    /// Sleep for a specified duration
    pub async fn sleep(&self, duration: Duration) -> HalResult<()> {
        tokio::time::sleep(duration).await;
        Ok(())
    }

    /// Get high-resolution timestamp for performance measurements
    pub fn get_high_resolution_timestamp(&self) -> HalResult<u64> {
        // Use platform-specific high-resolution counter if available
        #[cfg(target_arch = "x86_64")]
        {
            // On x86_64, we can use RDTSC for very high resolution
            // In a production implementation, this would use actual RDTSC
            Ok(self.monotonic_start.elapsed().as_nanos() as u64)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Ok(self.monotonic_start.elapsed().as_nanos() as u64)
        }
    }

    /// Get system uptime
    pub fn get_system_uptime(&self) -> HalResult<Duration> {
        // In a real implementation, this would read from /proc/uptime or similar
        // For now, return elapsed time since HAL initialization
        Ok(self.monotonic_start.elapsed())
    }
}

impl Default for ClockInterface {
    fn default() -> Self {
        Self::new()
    }
}

/// WASI-compatible clock functions
pub mod wasi_clock {
    use super::*;
    use wasi;

    /// Get current time with WASI compatibility
    pub fn clock_time_get(clock_id: u32) -> HalResult<u64> {
        match clock_id {
            // CLOCK_REALTIME
            0 => {
                let now = SystemTime::now();
                let duration = now
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| HalError::Internal(format!("Time error: {}", e)))?;
                Ok(duration.as_nanos() as u64)
            }
            // CLOCK_MONOTONIC
            1 => {
                let clock = ClockInterface::new();
                let monotonic = clock.read_monotonic_time()?;
                Ok((monotonic.elapsed_seconds * 1_000_000_000 + monotonic.elapsed_nanoseconds as u64))
            }
            _ => Err(HalError::InvalidParameter(format!("Invalid clock ID: {}", clock_id))),
        }
    }

    /// Get clock resolution
    pub fn clock_res_get(clock_id: u32) -> HalResult<u64> {
        match clock_id {
            0 | 1 => Ok(1), // 1 nanosecond resolution
            _ => Err(HalError::InvalidParameter(format!("Invalid clock ID: {}", clock_id))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration as TokioDuration;

    #[tokio::test]
    async fn test_current_time() {
        let clock = ClockInterface::new();
        let time_info = clock.read_current_time().unwrap();
        
        // Should be reasonably recent (after 2020)
        assert!(time_info.seconds > 1_577_836_800); // 2020-01-01
    }

    #[test]
    fn test_timezone() {
        let mut clock = ClockInterface::new();
        
        // Test setting valid timezone
        assert!(clock.set_timezone(3600).is_ok()); // +1 hour
        assert_eq!(clock.read_timezone().unwrap(), 3600);
        
        // Test invalid timezone
        assert!(clock.set_timezone(50000).is_err()); // Invalid: > 12 hours
    }

    #[tokio::test]
    async fn test_monotonic_timer() {
        let mut clock = ClockInterface::new();
        
        clock.start_monotonic_timer().unwrap();
        tokio::time::sleep(TokioDuration::from_millis(10)).await;
        
        let elapsed = clock.read_monotonic_time().unwrap();
        assert!(elapsed.elapsed_seconds > 0 || elapsed.elapsed_nanoseconds > 1_000_000);
    }

    #[test]
    fn test_high_resolution_timestamp() {
        let clock = ClockInterface::new();
        let ts1 = clock.get_high_resolution_timestamp().unwrap();
        
        // Small delay
        std::thread::sleep(Duration::from_nanos(1));
        
        let ts2 = clock.get_high_resolution_timestamp().unwrap();
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_wasi_clock_compatibility() {
        use wasi_clock::*;
        
        let realtime = clock_time_get(0).unwrap();
        let monotonic = clock_time_get(1).unwrap();
        
        assert!(realtime > 0);
        assert!(monotonic > 0);
        
        let resolution = clock_res_get(0).unwrap();
        assert_eq!(resolution, 1);
    }
}
