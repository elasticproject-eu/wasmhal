// Audit logging for HAL operations

use super::EntityId;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Audit event representing a HAL operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub entity_id: EntityId,
    pub capability: String,
    pub operation: String,
    pub success: bool,
    pub details: Option<String>,
}

impl AuditEvent {
    pub fn new(
        entity_id: EntityId,
        capability: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            entity_id,
            capability: capability.into(),
            operation: operation.into(),
            success: true,
            details: None,
        }
    }
    
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }
    
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Audit log storage and management
pub struct AuditLog {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    max_events: usize,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: 10_000, // Keep last 10k events
        }
    }
    
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::with_capacity(max_events))),
            max_events,
        }
    }
    
    /// Log an audit event
    pub fn log(&self, event: AuditEvent) {
        let mut events = self.events.write().unwrap();
        events.push(event);
        
        // Trim old events if we exceed max
        if events.len() > self.max_events {
            let drain_count = events.len() - self.max_events;
            events.drain(0..drain_count);
        }
    }
    
    /// Get all events
    pub fn get_events(&self) -> Vec<AuditEvent> {
        self.events.read().unwrap().clone()
    }
    
    /// Get events for a specific entity
    pub fn get_entity_events(&self, entity_id: &EntityId) -> Vec<AuditEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| &e.entity_id == entity_id)
            .cloned()
            .collect()
    }
    
    /// Get events for a specific capability
    pub fn get_capability_events(&self, capability: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.capability == capability)
            .cloned()
            .collect()
    }
    
    /// Get failed operations
    pub fn get_failed_events(&self) -> Vec<AuditEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| !e.success)
            .cloned()
            .collect()
    }
    
    /// Clear all events
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
    
    /// Get event count
    pub fn count(&self) -> usize {
        self.events.read().unwrap().len()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AuditLog {
    fn clone(&self) -> Self {
        Self {
            events: Arc::clone(&self.events),
            max_events: self.max_events,
        }
    }
}
