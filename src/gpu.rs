// GPU interface implementation - Requirement 4

use crate::error::{HalError, HalResult};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// GPU adapter handle
pub type GpuAdapterHandle = u64;

/// GPU device handle
pub type GpuDeviceHandle = u64;

/// GPU compute pipeline handle
pub type GpuPipelineHandle = u64;

/// GPU compute pass handle
pub type GpuComputePassHandle = u64;

/// GPU interface for compute workloads
#[derive(Debug)]
pub struct GpuInterface {
    adapters: Arc<RwLock<HashMap<GpuAdapterHandle, GpuAdapter>>>,
    devices: Arc<RwLock<HashMap<GpuDeviceHandle, GpuDevice>>>,
    pipelines: Arc<RwLock<HashMap<GpuPipelineHandle, GpuComputePipeline>>>,
    compute_passes: Arc<RwLock<HashMap<GpuComputePassHandle, GpuComputePass>>>,
    next_handle: Arc<RwLock<u64>>,
}

/// GPU adapter information
#[derive(Debug, Clone)]
struct GpuAdapter {
    #[allow(dead_code)]
    handle: GpuAdapterHandle,
    name: String,
    vendor: String,
    device_type: GpuDeviceType,
    features: GpuFeatures,
    limits: GpuLimits,
}

/// GPU device
#[derive(Debug, Clone)]
struct GpuDevice {
    #[allow(dead_code)]
    handle: GpuDeviceHandle,
    #[allow(dead_code)]
    adapter_handle: GpuAdapterHandle,
    #[allow(dead_code)]
    enabled_features: GpuFeatures,
    #[allow(dead_code)]
    queue_family_index: u32,
}

/// GPU compute pipeline
#[derive(Debug, Clone)]
struct GpuComputePipeline {
    #[allow(dead_code)]
    handle: GpuPipelineHandle,
    device_handle: GpuDeviceHandle,
    #[allow(dead_code)]
    shader_code: Vec<u8>,
    #[allow(dead_code)]
    entry_point: String,
    #[allow(dead_code)]
    workgroup_size: [u32; 3],
}

/// GPU compute pass
#[derive(Debug, Clone)]
struct GpuComputePass {
    #[allow(dead_code)]
    handle: GpuComputePassHandle,
    #[allow(dead_code)]
    device_handle: GpuDeviceHandle,
    #[allow(dead_code)]
    pipeline_handle: GpuPipelineHandle,
    dispatch_size: [u32; 3],
}

/// GPU device types
#[derive(Debug, Clone, PartialEq)]
pub enum GpuDeviceType {
    IntegratedGpu,
    DiscreteGpu,
    VirtualGpu,
    Cpu,
    Other,
}

/// GPU features
#[derive(Debug, Clone)]
pub struct GpuFeatures {
    pub compute_shaders: bool,
    pub storage_buffers: bool,
    pub texture_binding_arrays: bool,
    pub push_constants: bool,
    pub indirect_compute_dispatch: bool,
    pub multi_draw_indirect: bool,
    pub shader_f64: bool,
    pub shader_int64: bool,
}

/// GPU limits
#[derive(Debug, Clone)]
pub struct GpuLimits {
    pub max_texture_dimension_1d: u32,
    pub max_texture_dimension_2d: u32,
    pub max_texture_dimension_3d: u32,
    pub max_texture_array_layers: u32,
    pub max_bind_groups: u32,
    pub max_dynamic_uniform_buffers_per_pipeline_layout: u32,
    pub max_dynamic_storage_buffers_per_pipeline_layout: u32,
    pub max_sampled_textures_per_shader_stage: u32,
    pub max_samplers_per_shader_stage: u32,
    pub max_storage_buffers_per_shader_stage: u32,
    pub max_storage_textures_per_shader_stage: u32,
    pub max_uniform_buffers_per_shader_stage: u32,
    pub max_uniform_buffer_binding_size: u64,
    pub max_storage_buffer_binding_size: u64,
    pub min_uniform_buffer_offset_alignment: u32,
    pub min_storage_buffer_offset_alignment: u32,
    pub max_vertex_buffers: u32,
    pub max_vertex_attributes: u32,
    pub max_vertex_buffer_array_stride: u32,
    pub max_compute_workgroup_storage_size: u32,
    pub max_compute_invocations_per_workgroup: u32,
    pub max_compute_workgroup_size_x: u32,
    pub max_compute_workgroup_size_y: u32,
    pub max_compute_workgroup_size_z: u32,
    pub max_compute_workgroups_per_dimension: u32,
}

/// GPU buffer description
#[derive(Debug, Clone)]
pub struct GpuBufferDescriptor {
    pub label: Option<String>,
    pub size: u64,
    pub usage: GpuBufferUsage,
    pub mapped_at_creation: bool,
}

/// GPU buffer usage flags
#[derive(Debug, Clone)]
pub struct GpuBufferUsage {
    pub map_read: bool,
    pub map_write: bool,
    pub copy_src: bool,
    pub copy_dst: bool,
    pub index: bool,
    pub vertex: bool,
    pub uniform: bool,
    pub storage: bool,
    pub indirect: bool,
    pub query_resolve: bool,
}

impl GpuInterface {
    /// Create a new GPU interface
    pub fn new() -> Self {
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
            devices: Arc::new(RwLock::new(HashMap::new())),
            pipelines: Arc::new(RwLock::new(HashMap::new())),
            compute_passes: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(RwLock::new(1)),
        }
    }

    /// Get available GPU adapters
    ///
    /// Note: Intel TDX has limited GPU support compared to AMD SEV-SNP.
    /// TDX does not support direct GPU passthrough due to security constraints.
    /// Virtual GPU adapters and software rasterizers are available.
    pub async fn get_gpu_adapters(&self) -> HalResult<Vec<GpuAdapterHandle>> {
        // In a real implementation, this would enumerate actual GPU adapters
        // For now, we'll simulate with a few common adapter types

        let mut adapters = self.adapters.write().await;
        let mut next_handle = self.next_handle.write().await;

        if adapters.is_empty() {
            // Check if we're running in Intel TDX
            let is_tdx = crate::platform::is_intel_tdx_available();

            // Create simulated adapters based on platform
            let adapters_data = if is_tdx {
                // Intel TDX: Limited GPU support, mainly software rasterization
                vec![
                    (
                        "Intel Software Rasterizer (TDX)",
                        "Intel",
                        GpuDeviceType::Cpu,
                    ),
                    (
                        "Virtual GPU Adapter (TDX)",
                        "Generic",
                        GpuDeviceType::VirtualGpu,
                    ),
                ]
            } else {
                // AMD SEV-SNP or other: Full GPU support
                vec![
                    ("AMD Radeon RX 7900 XTX", "AMD", GpuDeviceType::DiscreteGpu),
                    (
                        "NVIDIA GeForce RTX 4090",
                        "NVIDIA",
                        GpuDeviceType::DiscreteGpu,
                    ),
                    (
                        "Intel Iris Xe Graphics",
                        "Intel",
                        GpuDeviceType::IntegratedGpu,
                    ),
                    ("Software Rasterizer", "Mesa", GpuDeviceType::Cpu),
                ]
            };

            for (name, vendor, device_type) in adapters_data {
                let handle = *next_handle;
                *next_handle += 1;

                let features = GpuFeatures {
                    compute_shaders: true,
                    storage_buffers: true,
                    texture_binding_arrays: device_type != GpuDeviceType::Cpu,
                    push_constants: true,
                    indirect_compute_dispatch: device_type == GpuDeviceType::DiscreteGpu,
                    multi_draw_indirect: device_type == GpuDeviceType::DiscreteGpu,
                    shader_f64: device_type == GpuDeviceType::DiscreteGpu,
                    shader_int64: device_type == GpuDeviceType::DiscreteGpu,
                };

                let limits = match device_type {
                    GpuDeviceType::DiscreteGpu => self.get_high_end_limits(),
                    GpuDeviceType::IntegratedGpu | GpuDeviceType::VirtualGpu => {
                        self.get_integrated_limits()
                    }
                    _ => self.get_basic_limits(),
                };

                let adapter = GpuAdapter {
                    handle,
                    name: name.to_string(),
                    vendor: vendor.to_string(),
                    device_type,
                    features,
                    limits,
                };

                adapters.insert(handle, adapter);

                log::info!("Discovered GPU adapter: {} ({})", name, vendor);
            }
        }

        Ok(adapters.keys().copied().collect())
    }

    /// Create GPU device from adapter
    pub async fn create_gpu_device(
        &self,
        adapter_handle: GpuAdapterHandle,
    ) -> HalResult<GpuDeviceHandle> {
        let adapters = self.adapters.read().await;
        let adapter = adapters
            .get(&adapter_handle)
            .ok_or_else(|| HalError::NotFound("GPU adapter not found".to_string()))?;

        let mut devices = self.devices.write().await;
        let mut next_handle = self.next_handle.write().await;

        let device_handle = *next_handle;
        *next_handle += 1;

        let device = GpuDevice {
            handle: device_handle,
            adapter_handle,
            enabled_features: adapter.features.clone(),
            queue_family_index: 0,
        };

        devices.insert(device_handle, device);
        Ok(device_handle)
    }

    /// Read GPU adapter features
    pub async fn read_gpu_adapter_features(
        &self,
        adapter_handle: GpuAdapterHandle,
    ) -> HalResult<GpuFeatures> {
        let adapters = self.adapters.read().await;
        let adapter = adapters
            .get(&adapter_handle)
            .ok_or_else(|| HalError::NotFound("GPU adapter not found".to_string()))?;

        Ok(adapter.features.clone())
    }

    /// Set GPU adapter features (for device creation)
    pub async fn set_gpu_adapter_features(
        &self,
        adapter_handle: GpuAdapterHandle,
        features: GpuFeatures,
    ) -> HalResult<()> {
        let mut adapters = self.adapters.write().await;
        let adapter = adapters
            .get_mut(&adapter_handle)
            .ok_or_else(|| HalError::NotFound("GPU adapter not found".to_string()))?;

        // Validate that requested features are supported
        if features.compute_shaders && !adapter.features.compute_shaders {
            return Err(HalError::NotSupported(
                "Compute shaders not supported".to_string(),
            ));
        }
        if features.shader_f64 && !adapter.features.shader_f64 {
            return Err(HalError::NotSupported(
                "64-bit float shaders not supported".to_string(),
            ));
        }

        adapter.features = features;
        Ok(())
    }

    /// Create GPU compute pipeline
    pub async fn create_gpu_compute_pipeline(
        &self,
        device_handle: GpuDeviceHandle,
        shader_code: &[u8],
        entry_point: &str,
        workgroup_size: [u32; 3],
    ) -> HalResult<GpuPipelineHandle> {
        let devices = self.devices.read().await;
        let _device = devices
            .get(&device_handle)
            .ok_or_else(|| HalError::NotFound("GPU device not found".to_string()))?;

        // Validate workgroup size
        if workgroup_size[0] == 0 || workgroup_size[1] == 0 || workgroup_size[2] == 0 {
            return Err(HalError::InvalidParameter(
                "Workgroup size dimensions must be > 0".to_string(),
            ));
        }

        let mut pipelines = self.pipelines.write().await;
        let mut next_handle = self.next_handle.write().await;

        let pipeline_handle = *next_handle;
        *next_handle += 1;

        let pipeline = GpuComputePipeline {
            handle: pipeline_handle,
            device_handle,
            shader_code: shader_code.to_vec(),
            entry_point: entry_point.to_string(),
            workgroup_size,
        };

        pipelines.insert(pipeline_handle, pipeline);
        Ok(pipeline_handle)
    }

    /// Create GPU compute pass
    pub async fn create_gpu_compute_pass(
        &self,
        device_handle: GpuDeviceHandle,
        pipeline_handle: GpuPipelineHandle,
    ) -> HalResult<GpuComputePassHandle> {
        let devices = self.devices.read().await;
        let _device = devices
            .get(&device_handle)
            .ok_or_else(|| HalError::NotFound("GPU device not found".to_string()))?;

        let pipelines = self.pipelines.read().await;
        let pipeline = pipelines
            .get(&pipeline_handle)
            .ok_or_else(|| HalError::NotFound("GPU pipeline not found".to_string()))?;

        if pipeline.device_handle != device_handle {
            return Err(HalError::InvalidParameter(
                "Pipeline does not belong to the specified device".to_string(),
            ));
        }

        let mut compute_passes = self.compute_passes.write().await;
        let mut next_handle = self.next_handle.write().await;

        let pass_handle = *next_handle;
        *next_handle += 1;

        let compute_pass = GpuComputePass {
            handle: pass_handle,
            device_handle,
            pipeline_handle,
            dispatch_size: [1, 1, 1],
        };

        compute_passes.insert(pass_handle, compute_pass);
        Ok(pass_handle)
    }

    /// Dispatch compute work
    pub async fn dispatch_compute(
        &self,
        compute_pass_handle: GpuComputePassHandle,
        workgroups_x: u32,
        workgroups_y: u32,
        workgroups_z: u32,
    ) -> HalResult<()> {
        let mut compute_passes = self.compute_passes.write().await;
        let compute_pass = compute_passes
            .get_mut(&compute_pass_handle)
            .ok_or_else(|| HalError::NotFound("GPU compute pass not found".to_string()))?;

        if workgroups_x == 0 || workgroups_y == 0 || workgroups_z == 0 {
            return Err(HalError::InvalidParameter(
                "Workgroup counts must be > 0".to_string(),
            ));
        }

        compute_pass.dispatch_size = [workgroups_x, workgroups_y, workgroups_z];

        // In a real implementation, this would submit the compute work to the GPU
        // For now, we'll simulate the operation
        log::info!(
            "Dispatching compute work: {}x{}x{} workgroups on pass {}",
            workgroups_x,
            workgroups_y,
            workgroups_z,
            compute_pass_handle
        );

        Ok(())
    }

    /// Create GPU buffer
    pub async fn create_gpu_buffer(
        &self,
        device_handle: GpuDeviceHandle,
        descriptor: &GpuBufferDescriptor,
    ) -> HalResult<u64> {
        let devices = self.devices.read().await;
        let _device = devices
            .get(&device_handle)
            .ok_or_else(|| HalError::NotFound("GPU device not found".to_string()))?;

        if descriptor.size == 0 {
            return Err(HalError::InvalidParameter(
                "Buffer size must be > 0".to_string(),
            ));
        }

        // In a real implementation, this would create an actual GPU buffer
        // For now, we'll return a simulated buffer handle
        let mut next_handle = self.next_handle.write().await;
        let buffer_handle = *next_handle;
        *next_handle += 1;

        log::info!(
            "Created GPU buffer: handle={}, size={}, label={:?}",
            buffer_handle,
            descriptor.size,
            descriptor.label
        );

        Ok(buffer_handle)
    }

    /// Write data to GPU buffer
    pub async fn write_gpu_buffer(
        &self,
        buffer_handle: u64,
        offset: u64,
        data: &[u8],
    ) -> HalResult<()> {
        // In a real implementation, this would write to the actual GPU buffer
        log::info!(
            "Writing {} bytes to GPU buffer {} at offset {}",
            data.len(),
            buffer_handle,
            offset
        );

        Ok(())
    }

    /// Read data from GPU buffer
    pub async fn read_gpu_buffer(
        &self,
        buffer_handle: u64,
        offset: u64,
        size: u64,
    ) -> HalResult<Vec<u8>> {
        // In a real implementation, this would read from the actual GPU buffer
        log::info!(
            "Reading {} bytes from GPU buffer {} at offset {}",
            size,
            buffer_handle,
            offset
        );

        // Return simulated data
        Ok(vec![0u8; size as usize])
    }

    /// Get GPU adapter information
    pub async fn get_gpu_adapter_info(
        &self,
        adapter_handle: GpuAdapterHandle,
    ) -> HalResult<GpuAdapterInfo> {
        let adapters = self.adapters.read().await;
        let adapter = adapters
            .get(&adapter_handle)
            .ok_or_else(|| HalError::NotFound("GPU adapter not found".to_string()))?;

        Ok(GpuAdapterInfo {
            name: adapter.name.clone(),
            vendor: adapter.vendor.clone(),
            device_type: adapter.device_type.clone(),
            features: adapter.features.clone(),
            limits: adapter.limits.clone(),
        })
    }

    /// Clean up GPU resources
    pub async fn cleanup_gpu_resources(&self) -> HalResult<()> {
        let mut adapters = self.adapters.write().await;
        let mut devices = self.devices.write().await;
        let mut pipelines = self.pipelines.write().await;
        let mut compute_passes = self.compute_passes.write().await;

        adapters.clear();
        devices.clear();
        pipelines.clear();
        compute_passes.clear();

        log::info!("GPU resources cleaned up");
        Ok(())
    }

    // Private helper methods

    fn get_high_end_limits(&self) -> GpuLimits {
        GpuLimits {
            max_texture_dimension_1d: 16384,
            max_texture_dimension_2d: 16384,
            max_texture_dimension_3d: 2048,
            max_texture_array_layers: 2048,
            max_bind_groups: 8,
            max_dynamic_uniform_buffers_per_pipeline_layout: 12,
            max_dynamic_storage_buffers_per_pipeline_layout: 8,
            max_sampled_textures_per_shader_stage: 16,
            max_samplers_per_shader_stage: 16,
            max_storage_buffers_per_shader_stage: 8,
            max_storage_textures_per_shader_stage: 8,
            max_uniform_buffers_per_shader_stage: 12,
            max_uniform_buffer_binding_size: 65536,
            max_storage_buffer_binding_size: 134217728,
            min_uniform_buffer_offset_alignment: 256,
            min_storage_buffer_offset_alignment: 256,
            max_vertex_buffers: 16,
            max_vertex_attributes: 32,
            max_vertex_buffer_array_stride: 2048,
            max_compute_workgroup_storage_size: 32768,
            max_compute_invocations_per_workgroup: 1024,
            max_compute_workgroup_size_x: 1024,
            max_compute_workgroup_size_y: 1024,
            max_compute_workgroup_size_z: 64,
            max_compute_workgroups_per_dimension: 65535,
        }
    }

    fn get_integrated_limits(&self) -> GpuLimits {
        GpuLimits {
            max_texture_dimension_1d: 8192,
            max_texture_dimension_2d: 8192,
            max_texture_dimension_3d: 1024,
            max_texture_array_layers: 1024,
            max_bind_groups: 4,
            max_dynamic_uniform_buffers_per_pipeline_layout: 8,
            max_dynamic_storage_buffers_per_pipeline_layout: 4,
            max_sampled_textures_per_shader_stage: 8,
            max_samplers_per_shader_stage: 8,
            max_storage_buffers_per_shader_stage: 4,
            max_storage_textures_per_shader_stage: 4,
            max_uniform_buffers_per_shader_stage: 8,
            max_uniform_buffer_binding_size: 32768,
            max_storage_buffer_binding_size: 67108864,
            min_uniform_buffer_offset_alignment: 256,
            min_storage_buffer_offset_alignment: 256,
            max_vertex_buffers: 8,
            max_vertex_attributes: 16,
            max_vertex_buffer_array_stride: 1024,
            max_compute_workgroup_storage_size: 16384,
            max_compute_invocations_per_workgroup: 512,
            max_compute_workgroup_size_x: 512,
            max_compute_workgroup_size_y: 512,
            max_compute_workgroup_size_z: 32,
            max_compute_workgroups_per_dimension: 32767,
        }
    }

    fn get_basic_limits(&self) -> GpuLimits {
        GpuLimits {
            max_texture_dimension_1d: 4096,
            max_texture_dimension_2d: 4096,
            max_texture_dimension_3d: 512,
            max_texture_array_layers: 512,
            max_bind_groups: 2,
            max_dynamic_uniform_buffers_per_pipeline_layout: 4,
            max_dynamic_storage_buffers_per_pipeline_layout: 2,
            max_sampled_textures_per_shader_stage: 4,
            max_samplers_per_shader_stage: 4,
            max_storage_buffers_per_shader_stage: 2,
            max_storage_textures_per_shader_stage: 2,
            max_uniform_buffers_per_shader_stage: 4,
            max_uniform_buffer_binding_size: 16384,
            max_storage_buffer_binding_size: 33554432,
            min_uniform_buffer_offset_alignment: 256,
            min_storage_buffer_offset_alignment: 256,
            max_vertex_buffers: 4,
            max_vertex_attributes: 8,
            max_vertex_buffer_array_stride: 512,
            max_compute_workgroup_storage_size: 8192,
            max_compute_invocations_per_workgroup: 256,
            max_compute_workgroup_size_x: 256,
            max_compute_workgroup_size_y: 256,
            max_compute_workgroup_size_z: 16,
            max_compute_workgroups_per_dimension: 16383,
        }
    }
}

/// GPU adapter information
#[derive(Debug, Clone)]
pub struct GpuAdapterInfo {
    pub name: String,
    pub vendor: String,
    pub device_type: GpuDeviceType,
    pub features: GpuFeatures,
    pub limits: GpuLimits,
}

impl Default for GpuInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gpu_adapter_enumeration() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        assert!(!adapters.is_empty());

        // Should have at least one adapter
        let adapter_handle = adapters[0];
        let info = gpu.get_gpu_adapter_info(adapter_handle).await.unwrap();
        assert!(!info.name.is_empty());
        assert!(!info.vendor.is_empty());
    }

    #[tokio::test]
    async fn test_gpu_device_creation() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];

        let device_handle = gpu.create_gpu_device(adapter_handle).await.unwrap();
        assert!(device_handle > 0);
    }

    #[tokio::test]
    async fn test_compute_pipeline_creation() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];
        let device_handle = gpu.create_gpu_device(adapter_handle).await.unwrap();

        let shader_code = b"#version 450\nlayout(local_size_x = 1) in;\nvoid main() {}";
        let pipeline_handle = gpu
            .create_gpu_compute_pipeline(device_handle, shader_code, "main", [1, 1, 1])
            .await
            .unwrap();

        assert!(pipeline_handle > 0);
    }

    #[tokio::test]
    async fn test_compute_pass_creation_and_dispatch() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];
        let device_handle = gpu.create_gpu_device(adapter_handle).await.unwrap();

        let shader_code = b"compute shader code";
        let pipeline_handle = gpu
            .create_gpu_compute_pipeline(device_handle, shader_code, "main", [8, 8, 1])
            .await
            .unwrap();

        let compute_pass_handle = gpu
            .create_gpu_compute_pass(device_handle, pipeline_handle)
            .await
            .unwrap();

        let result = gpu.dispatch_compute(compute_pass_handle, 16, 16, 1).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_gpu_buffer_operations() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];
        let device_handle = gpu.create_gpu_device(adapter_handle).await.unwrap();

        let buffer_desc = GpuBufferDescriptor {
            label: Some("test_buffer".to_string()),
            size: 1024,
            usage: GpuBufferUsage {
                map_read: true,
                map_write: true,
                copy_src: true,
                copy_dst: true,
                storage: true,
                ..Default::default()
            },
            mapped_at_creation: false,
        };

        let buffer_handle = gpu
            .create_gpu_buffer(device_handle, &buffer_desc)
            .await
            .unwrap();

        let test_data = vec![1u8, 2, 3, 4, 5];
        gpu.write_gpu_buffer(buffer_handle, 0, &test_data)
            .await
            .unwrap();

        let read_data = gpu
            .read_gpu_buffer(buffer_handle, 0, test_data.len() as u64)
            .await
            .unwrap();
        assert_eq!(read_data.len(), test_data.len());
    }

    #[tokio::test]
    async fn test_gpu_features() {
        let gpu = GpuInterface::new();

        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];

        let features = gpu.read_gpu_adapter_features(adapter_handle).await.unwrap();
        assert!(features.compute_shaders);

        // Test feature modification
        let modified_features = GpuFeatures {
            compute_shaders: true,
            storage_buffers: false,
            ..features
        };

        let result = gpu
            .set_gpu_adapter_features(adapter_handle, modified_features)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_operations() {
        let gpu = GpuInterface::new();

        // Try to use invalid handles
        let result = gpu.create_gpu_device(999).await;
        assert!(result.is_err());

        let result = gpu
            .create_gpu_compute_pipeline(999, b"shader", "main", [1, 1, 1])
            .await;
        assert!(result.is_err());

        let result = gpu.dispatch_compute(999, 1, 1, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let gpu = GpuInterface::new();

        // Create some resources
        let adapters = gpu.get_gpu_adapters().await.unwrap();
        let adapter_handle = adapters[0];
        let _device_handle = gpu.create_gpu_device(adapter_handle).await.unwrap();

        // Clean up
        gpu.cleanup_gpu_resources().await.unwrap();

        // Resources should be cleaned up
        let result = gpu.create_gpu_device(adapter_handle).await;
        assert!(result.is_err());
    }
}

impl Default for GpuBufferUsage {
    fn default() -> Self {
        Self {
            map_read: false,
            map_write: false,
            copy_src: false,
            copy_dst: false,
            index: false,
            vertex: false,
            uniform: false,
            storage: false,
            indirect: false,
            query_resolve: false,
        }
    }
}
