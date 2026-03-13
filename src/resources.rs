// Resource allocation interface - Requirement 9

use crate::error::{HalError, HalResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Resource allocation interface
#[derive(Debug)]
pub struct ResourceInterface {
    allocations: Arc<RwLock<HashMap<String, ResourceAllocation>>>,
    total_limits: ResourceLimits,
    current_usage: Arc<RwLock<ResourceUsage>>,
}

/// Resource allocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    allocation_id: String,
    resource_type: ResourceType,
    amount: u64,
    allocated_at: u64,
    requester: String,
}

/// Resource type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    Memory,           // Memory in MB
    CpuCores,         // Number of CPU cores
    Storage,          // Storage in MB
    NetworkBandwidth, // Network bandwidth in Mbps
    GpuMemory,        // GPU memory in MB
}

/// System resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub max_storage_mb: u64,
    pub max_network_bandwidth_mbps: u64,
    pub max_gpu_memory_mb: u64,
}

/// Current resource usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_mb: u64,
    pub cpu_cores: u32,
    pub storage_mb: u64,
    pub network_bandwidth_mbps: u64,
    pub gpu_memory_mb: u64,
}

/// Resource allocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub resource_type: ResourceType,
    pub amount: u64,
    pub requester: String,
    pub priority: RequestPriority,
    pub timeout_seconds: Option<u64>,
}

/// Request priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Resource allocation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationResult {
    pub allocation_id: String,
    pub granted_amount: u64,
    pub expires_at: Option<u64>,
}

impl ResourceInterface {
    /// Create a new resource interface with system limits
    pub fn new() -> HalResult<Self> {
        let limits = Self::detect_system_limits()?;

        Ok(Self {
            allocations: Arc::new(RwLock::new(HashMap::new())),
            total_limits: limits,
            current_usage: Arc::new(RwLock::new(ResourceUsage {
                memory_mb: 0,
                cpu_cores: 0,
                storage_mb: 0,
                network_bandwidth_mbps: 0,
                gpu_memory_mb: 0,
            })),
        })
    }

    /// Create resource interface with custom limits
    pub fn with_limits(limits: ResourceLimits) -> Self {
        Self {
            allocations: Arc::new(RwLock::new(HashMap::new())),
            total_limits: limits,
            current_usage: Arc::new(RwLock::new(ResourceUsage {
                memory_mb: 0,
                cpu_cores: 0,
                storage_mb: 0,
                network_bandwidth_mbps: 0,
                gpu_memory_mb: 0,
            })),
        }
    }

    /// List current memory and CPU allocation
    pub async fn list_current_allocation(&self) -> HalResult<ResourceUsage> {
        let usage = self.current_usage.read().await;
        Ok(usage.clone())
    }

    /// Get total system limits
    pub async fn get_system_limits(&self) -> HalResult<ResourceLimits> {
        Ok(self.total_limits.clone())
    }

    /// Request additional RAM memory
    pub async fn request_additional_memory(
        &self,
        memory_mb: u64,
        requester: &str,
    ) -> HalResult<AllocationResult> {
        let request = ResourceRequest {
            resource_type: ResourceType::Memory,
            amount: memory_mb,
            requester: requester.to_string(),
            priority: RequestPriority::Normal,
            timeout_seconds: None,
        };

        self.allocate_resource(request).await
    }

    /// Request additional CPU allocations
    pub async fn request_additional_cpu(
        &self,
        cpu_cores: u32,
        requester: &str,
    ) -> HalResult<AllocationResult> {
        let request = ResourceRequest {
            resource_type: ResourceType::CpuCores,
            amount: cpu_cores as u64,
            requester: requester.to_string(),
            priority: RequestPriority::Normal,
            timeout_seconds: None,
        };

        self.allocate_resource(request).await
    }

    /// Request storage allocation
    pub async fn request_storage(
        &self,
        storage_mb: u64,
        requester: &str,
    ) -> HalResult<AllocationResult> {
        let request = ResourceRequest {
            resource_type: ResourceType::Storage,
            amount: storage_mb,
            requester: requester.to_string(),
            priority: RequestPriority::Normal,
            timeout_seconds: None,
        };

        self.allocate_resource(request).await
    }

    /// Request network bandwidth allocation
    pub async fn request_network_bandwidth(
        &self,
        bandwidth_mbps: u64,
        requester: &str,
    ) -> HalResult<AllocationResult> {
        let request = ResourceRequest {
            resource_type: ResourceType::NetworkBandwidth,
            amount: bandwidth_mbps,
            requester: requester.to_string(),
            priority: RequestPriority::Normal,
            timeout_seconds: None,
        };

        self.allocate_resource(request).await
    }

    /// Request GPU memory allocation
    pub async fn request_gpu_memory(
        &self,
        gpu_memory_mb: u64,
        requester: &str,
    ) -> HalResult<AllocationResult> {
        let request = ResourceRequest {
            resource_type: ResourceType::GpuMemory,
            amount: gpu_memory_mb,
            requester: requester.to_string(),
            priority: RequestPriority::Normal,
            timeout_seconds: None,
        };

        self.allocate_resource(request).await
    }

    /// Generic resource allocation
    pub async fn allocate_resource(&self, request: ResourceRequest) -> HalResult<AllocationResult> {
        let mut allocations = self.allocations.write().await;
        let mut usage = self.current_usage.write().await;

        // Check if resource is available
        let available = self.check_resource_availability(&request, &usage)?;
        if !available {
            return Err(HalError::ResourceError(format!(
                "Insufficient {:?} resources available",
                request.resource_type
            )));
        }

        // Generate allocation ID
        let allocation_id = self.generate_allocation_id(&request);

        // Calculate expiration time if timeout is set
        let expires_at = request.timeout_seconds.map(|timeout| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + timeout
        });

        // Update resource usage
        match request.resource_type {
            ResourceType::Memory => {
                usage.memory_mb += request.amount;
            }
            ResourceType::CpuCores => {
                usage.cpu_cores += request.amount as u32;
            }
            ResourceType::Storage => {
                usage.storage_mb += request.amount;
            }
            ResourceType::NetworkBandwidth => {
                usage.network_bandwidth_mbps += request.amount;
            }
            ResourceType::GpuMemory => {
                usage.gpu_memory_mb += request.amount;
            }
        }

        // Create allocation record
        let allocation = ResourceAllocation {
            allocation_id: allocation_id.clone(),
            resource_type: request.resource_type.clone(),
            amount: request.amount,
            allocated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: request.requester.clone(),
        };

        log::info!(
            "Allocated {:?} resources: {} units for requester {}",
            &request.resource_type,
            request.amount,
            &allocation.requester
        );

        allocations.insert(allocation_id.clone(), allocation);

        Ok(AllocationResult {
            allocation_id,
            granted_amount: request.amount,
            expires_at,
        })
    }

    /// Release allocated resources
    pub async fn release_resource(&self, allocation_id: &str) -> HalResult<()> {
        let mut allocations = self.allocations.write().await;
        let mut usage = self.current_usage.write().await;

        let allocation = allocations.remove(allocation_id).ok_or_else(|| {
            HalError::NotFound(format!("Allocation '{}' not found", allocation_id))
        })?;

        // Update resource usage
        match allocation.resource_type {
            ResourceType::Memory => {
                usage.memory_mb = usage.memory_mb.saturating_sub(allocation.amount);
            }
            ResourceType::CpuCores => {
                usage.cpu_cores = usage.cpu_cores.saturating_sub(allocation.amount as u32);
            }
            ResourceType::Storage => {
                usage.storage_mb = usage.storage_mb.saturating_sub(allocation.amount);
            }
            ResourceType::NetworkBandwidth => {
                usage.network_bandwidth_mbps = usage
                    .network_bandwidth_mbps
                    .saturating_sub(allocation.amount);
            }
            ResourceType::GpuMemory => {
                usage.gpu_memory_mb = usage.gpu_memory_mb.saturating_sub(allocation.amount);
            }
        }

        log::info!(
            "Released {:?} resources: {} units from allocation {}",
            allocation.resource_type,
            allocation.amount,
            allocation_id
        );

        Ok(())
    }

    /// Get allocation information
    pub async fn get_allocation_info(&self, allocation_id: &str) -> HalResult<ResourceAllocation> {
        let allocations = self.allocations.read().await;
        let allocation = allocations.get(allocation_id).ok_or_else(|| {
            HalError::NotFound(format!("Allocation '{}' not found", allocation_id))
        })?;

        Ok(allocation.clone())
    }

    /// List all allocations
    pub async fn list_allocations(&self) -> HalResult<Vec<ResourceAllocation>> {
        let allocations = self.allocations.read().await;
        Ok(allocations.values().cloned().collect())
    }

    /// List allocations by requester
    pub async fn list_allocations_by_requester(
        &self,
        requester: &str,
    ) -> HalResult<Vec<ResourceAllocation>> {
        let allocations = self.allocations.read().await;
        let filtered: Vec<ResourceAllocation> = allocations
            .values()
            .filter(|alloc| alloc.requester == requester)
            .cloned()
            .collect();

        Ok(filtered)
    }

    /// Get resource utilization statistics
    pub async fn get_resource_statistics(&self) -> HalResult<ResourceStatistics> {
        let usage = self.current_usage.read().await;
        let limits = &self.total_limits;

        let memory_utilization = if limits.max_memory_mb > 0 {
            (usage.memory_mb as f64 / limits.max_memory_mb as f64) * 100.0
        } else {
            0.0
        };

        let cpu_utilization = if limits.max_cpu_cores > 0 {
            (usage.cpu_cores as f64 / limits.max_cpu_cores as f64) * 100.0
        } else {
            0.0
        };

        let storage_utilization = if limits.max_storage_mb > 0 {
            (usage.storage_mb as f64 / limits.max_storage_mb as f64) * 100.0
        } else {
            0.0
        };

        let network_utilization = if limits.max_network_bandwidth_mbps > 0 {
            (usage.network_bandwidth_mbps as f64 / limits.max_network_bandwidth_mbps as f64) * 100.0
        } else {
            0.0
        };

        let gpu_memory_utilization = if limits.max_gpu_memory_mb > 0 {
            (usage.gpu_memory_mb as f64 / limits.max_gpu_memory_mb as f64) * 100.0
        } else {
            0.0
        };

        Ok(ResourceStatistics {
            memory_utilization_percent: memory_utilization,
            cpu_utilization_percent: cpu_utilization,
            storage_utilization_percent: storage_utilization,
            network_utilization_percent: network_utilization,
            gpu_memory_utilization_percent: gpu_memory_utilization,
            total_allocations: self.allocations.read().await.len(),
        })
    }

    /// Clean up expired allocations
    pub async fn cleanup_expired_allocations(&self) -> HalResult<Vec<String>> {
        // In a real implementation, this would track allocation expiration times
        // and automatically release expired allocations
        let released = Vec::new();

        // For now, this is a placeholder that could be extended with actual
        // expiration tracking logic

        Ok(released)
    }

    // Private helper methods

    fn check_resource_availability(
        &self,
        request: &ResourceRequest,
        usage: &ResourceUsage,
    ) -> HalResult<bool> {
        match request.resource_type {
            ResourceType::Memory => {
                Ok(usage.memory_mb + request.amount <= self.total_limits.max_memory_mb)
            }
            ResourceType::CpuCores => {
                Ok(usage.cpu_cores + request.amount as u32 <= self.total_limits.max_cpu_cores)
            }
            ResourceType::Storage => {
                Ok(usage.storage_mb + request.amount <= self.total_limits.max_storage_mb)
            }
            ResourceType::NetworkBandwidth => Ok(usage.network_bandwidth_mbps + request.amount
                <= self.total_limits.max_network_bandwidth_mbps),
            ResourceType::GpuMemory => {
                Ok(usage.gpu_memory_mb + request.amount <= self.total_limits.max_gpu_memory_mb)
            }
        }
    }

    fn generate_allocation_id(&self, request: &ResourceRequest) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        format!(
            "{:?}_{}_{}_{}",
            request.resource_type, request.requester, request.amount, timestamp
        )
    }

    fn detect_system_limits() -> HalResult<ResourceLimits> {
        // Detect actual system resources, accounting for TEE overhead

        #[cfg(target_os = "linux")]
        {
            let is_tdx = crate::platform::is_intel_tdx_available();
            let is_sev = std::path::Path::new("/dev/sev-guest").exists();

            let memory_mb = Self::get_system_memory_mb().unwrap_or(8192);
            let cpu_cores = Self::get_system_cpu_cores().unwrap_or(4);
            let storage_mb = Self::get_available_storage_mb().unwrap_or(102400);

            // Account for TEE memory encryption overhead
            // TDX typically has 5-10% memory overhead for encryption
            // SEV-SNP has similar overhead
            let adjusted_memory_mb = if is_tdx || is_sev {
                let overhead_percent = if is_tdx { 8 } else { 6 };
                memory_mb * (100 - overhead_percent) / 100
            } else {
                memory_mb
            };

            log::info!(
                "Detected system limits: {}MB RAM, {} CPU cores (TEE: TDX={}, SEV={})",
                adjusted_memory_mb,
                cpu_cores,
                is_tdx,
                is_sev
            );

            Ok(ResourceLimits {
                max_memory_mb: adjusted_memory_mb,
                max_cpu_cores: cpu_cores,
                max_storage_mb: storage_mb,
                max_network_bandwidth_mbps: 1000, // 1 Gbps default
                max_gpu_memory_mb: if is_tdx { 0 } else { 8192 }, // TDX has no GPU passthrough
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(ResourceLimits {
                max_memory_mb: 8192,
                max_cpu_cores: 4,
                max_storage_mb: 102400,
                max_network_bandwidth_mbps: 1000,
                max_gpu_memory_mb: 8192,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn get_system_memory_mb() -> Option<u64> {
        // Read from /proc/meminfo
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return Some(kb / 1024); // Convert KB to MB
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn get_system_cpu_cores() -> Option<u32> {
        std::thread::available_parallelism()
            .ok()
            .map(|p| p.get() as u32)
    }

    #[cfg(target_os = "linux")]
    fn get_available_storage_mb() -> Option<u64> {
        // This is a simplified version - in practice you'd check available disk space
        Some(102400) // 100GB default
    }
}

/// Resource utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStatistics {
    pub memory_utilization_percent: f64,
    pub cpu_utilization_percent: f64,
    pub storage_utilization_percent: f64,
    pub network_utilization_percent: f64,
    pub gpu_memory_utilization_percent: f64,
    pub total_allocations: usize,
}

impl Default for ResourceInterface {
    fn default() -> Self {
        Self::new().expect("Failed to create default resource interface")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_limits() -> ResourceLimits {
        ResourceLimits {
            max_memory_mb: 1024,
            max_cpu_cores: 4,
            max_storage_mb: 10240,
            max_network_bandwidth_mbps: 100,
            max_gpu_memory_mb: 2048,
        }
    }

    #[tokio::test]
    async fn test_resource_allocation() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        // Request memory
        let result = resource_interface
            .request_additional_memory(512, "test_app")
            .await
            .unwrap();
        assert!(!result.allocation_id.is_empty());
        assert_eq!(result.granted_amount, 512);

        // Check usage
        let usage = resource_interface.list_current_allocation().await.unwrap();
        assert_eq!(usage.memory_mb, 512);
    }

    #[tokio::test]
    async fn test_resource_limits() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        // Try to allocate more than available
        let result = resource_interface
            .request_additional_memory(2048, "greedy_app")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resource_release() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        // Allocate resource
        let allocation = resource_interface
            .request_additional_cpu(2, "test_app")
            .await
            .unwrap();

        // Check usage
        let usage = resource_interface.list_current_allocation().await.unwrap();
        assert_eq!(usage.cpu_cores, 2);

        // Release resource
        resource_interface
            .release_resource(&allocation.allocation_id)
            .await
            .unwrap();

        // Check usage again
        let usage = resource_interface.list_current_allocation().await.unwrap();
        assert_eq!(usage.cpu_cores, 0);
    }

    #[tokio::test]
    async fn test_allocation_listing() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        // Create multiple allocations
        let _alloc1 = resource_interface
            .request_additional_memory(256, "app1")
            .await
            .unwrap();
        let _alloc2 = resource_interface
            .request_additional_cpu(1, "app2")
            .await
            .unwrap();
        let _alloc3 = resource_interface
            .request_storage(1024, "app1")
            .await
            .unwrap();

        // List all allocations
        let all_allocations = resource_interface.list_allocations().await.unwrap();
        assert_eq!(all_allocations.len(), 3);

        // List allocations by requester
        let app1_allocations = resource_interface
            .list_allocations_by_requester("app1")
            .await
            .unwrap();
        assert_eq!(app1_allocations.len(), 2);
    }

    #[tokio::test]
    async fn test_resource_statistics() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        // Allocate some resources
        let _alloc1 = resource_interface
            .request_additional_memory(512, "app1")
            .await
            .unwrap(); // 50% of 1024
        let _alloc2 = resource_interface
            .request_additional_cpu(2, "app2")
            .await
            .unwrap(); // 50% of 4

        let stats = resource_interface.get_resource_statistics().await.unwrap();
        assert_eq!(stats.memory_utilization_percent, 50.0);
        assert_eq!(stats.cpu_utilization_percent, 50.0);
        assert_eq!(stats.total_allocations, 2);
    }

    #[tokio::test]
    async fn test_allocation_info() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        let allocation = resource_interface
            .request_additional_memory(256, "test_app")
            .await
            .unwrap();

        let info = resource_interface
            .get_allocation_info(&allocation.allocation_id)
            .await
            .unwrap();
        assert_eq!(info.allocation_id, allocation.allocation_id);
        assert_eq!(info.amount, 256);
        assert_eq!(info.requester, "test_app");
    }

    #[tokio::test]
    async fn test_gpu_memory_allocation() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        let allocation = resource_interface
            .request_gpu_memory(1024, "gpu_app")
            .await
            .unwrap();
        assert_eq!(allocation.granted_amount, 1024);

        let usage = resource_interface.list_current_allocation().await.unwrap();
        assert_eq!(usage.gpu_memory_mb, 1024);
    }

    #[tokio::test]
    async fn test_network_bandwidth_allocation() {
        let resource_interface = ResourceInterface::with_limits(create_test_limits());

        let allocation = resource_interface
            .request_network_bandwidth(50, "network_app")
            .await
            .unwrap();
        assert_eq!(allocation.granted_amount, 50);

        let usage = resource_interface.list_current_allocation().await.unwrap();
        assert_eq!(usage.network_bandwidth_mbps, 50);
    }
}
