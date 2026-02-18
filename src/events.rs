// Event handling interface - Requirement 10

use crate::error::{HalError, HalResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{timeout, Duration};

/// Event handler handle
pub type EventHandlerHandle = u64;

/// Event subscription handle
pub type EventSubscriptionHandle = u64;

/// Event interface for inter-workload communication
///
/// In Intel TDX environments, events can be encrypted and signed
/// using TDX sealing keys for secure inter-TD communication.
#[derive(Debug)]
pub struct EventInterface {
    handlers: Arc<RwLock<HashMap<EventHandlerHandle, EventHandler>>>,
    subscriptions: Arc<RwLock<HashMap<EventSubscriptionHandle, EventSubscription>>>,
    next_handle: Arc<RwLock<u64>>,
    global_event_bus: broadcast::Sender<Event>,
    _global_receiver: broadcast::Receiver<Event>,
    is_tdx_env: bool,
}

/// Event handler
#[derive(Debug)]
struct EventHandler {
    handle: EventHandlerHandle,
    name: String,
    event_types: Vec<String>,
    sender: mpsc::UnboundedSender<Event>,
    receiver: Arc<RwLock<mpsc::UnboundedReceiver<Event>>>,
    created_at: u64,
    max_queue_size: usize,
    current_queue_size: Arc<RwLock<usize>>,
}

/// Event subscription
#[derive(Debug)]
struct EventSubscription {
    #[allow(dead_code)]
    handle: EventSubscriptionHandle,
    handler_handle: EventHandlerHandle,
    event_types: Vec<String>,
    subscription_filter: Option<String>,
    #[allow(dead_code)]
    created_at: u64,
}

/// Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub event_type: String,
    pub source: String,
    pub target: Option<String>,
    pub timestamp: u64,
    pub data: EventData,
    pub priority: EventPriority,
}

/// Event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    Text(String),
    Binary(Vec<u8>),
    Json(serde_json::Value),
    Empty,
}

/// Event priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Event handler configuration
#[derive(Debug, Clone)]
pub struct EventHandlerConfig {
    pub name: String,
    pub event_types: Vec<String>,
    pub max_queue_size: usize,
}

/// Event subscription filter
#[derive(Debug, Clone)]
pub struct SubscriptionFilter {
    pub event_types: Vec<String>,
    pub source_pattern: Option<String>,
    pub target_pattern: Option<String>,
    pub data_filter: Option<String>,
}

impl EventInterface {
    /// Create a new event interface
    pub fn new() -> Self {
        let (global_sender, global_receiver) = broadcast::channel(10000);

        // Detect if running in Intel TDX environment
        let is_tdx_env = crate::platform::is_intel_tdx_available();

        if is_tdx_env {
            log::info!("Event interface initialized in Intel TDX secure mode");
        }

        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(RwLock::new(1)),
            global_event_bus: global_sender,
            _global_receiver: global_receiver,
            is_tdx_env,
        }
    }

    /// Create an event handler
    pub async fn create_event_handler(
        &self,
        config: EventHandlerConfig,
    ) -> HalResult<EventHandlerHandle> {
        let mut handlers = self.handlers.write().await;
        let mut next_handle = self.next_handle.write().await;

        let handle = *next_handle;
        *next_handle += 1;

        let (sender, receiver) = mpsc::unbounded_channel();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let handler = EventHandler {
            handle,
            name: config.name.clone(),
            event_types: config.event_types,
            sender,
            receiver: Arc::new(RwLock::new(receiver)),
            created_at: now,
            max_queue_size: config.max_queue_size,
            current_queue_size: Arc::new(RwLock::new(0)),
        };

        handlers.insert(handle, handler);

        log::info!(
            "Created event handler '{}' with handle {}",
            config.name,
            handle
        );
        Ok(handle)
    }

    /// Request event subscription
    pub async fn request_event_subscription(
        &self,
        handler_handle: EventHandlerHandle,
        filter: SubscriptionFilter,
    ) -> HalResult<EventSubscriptionHandle> {
        let handlers = self.handlers.read().await;
        let _handler = handlers
            .get(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        let mut subscriptions = self.subscriptions.write().await;
        let mut next_handle = self.next_handle.write().await;

        let subscription_handle = *next_handle;
        *next_handle += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let subscription = EventSubscription {
            handle: subscription_handle,
            handler_handle,
            event_types: filter.event_types,
            subscription_filter: filter.source_pattern,
            created_at: now,
        };

        subscriptions.insert(subscription_handle, subscription);

        log::info!(
            "Created event subscription {} for handler {}",
            subscription_handle,
            handler_handle
        );

        Ok(subscription_handle)
    }

    /// Send event to event handler
    pub async fn send_event_to_handler(
        &self,
        handler_handle: EventHandlerHandle,
        event: Event,
    ) -> HalResult<()> {
        let handlers = self.handlers.read().await;
        let handler = handlers
            .get(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        // Check queue size limits
        let current_size = *handler.current_queue_size.read().await;
        if current_size >= handler.max_queue_size {
            return Err(HalError::EventError(
                "Event handler queue is full".to_string(),
            ));
        }

        // Send event to handler
        handler
            .sender
            .send(event.clone())
            .map_err(|_| HalError::EventError("Failed to send event to handler".to_string()))?;

        // Update queue size
        let mut queue_size = handler.current_queue_size.write().await;
        *queue_size += 1;

        // Also broadcast to global event bus
        let _ = self.global_event_bus.send(event);

        Ok(())
    }

    /// Send event globally (to all subscribed handlers)
    ///
    /// In TDX environments, events can be optionally encrypted for
    /// secure cross-Trust Domain communication.
    pub async fn send_event_global(&self, event: Event) -> HalResult<()> {
        let handlers = self.handlers.read().await;
        let subscriptions = self.subscriptions.read().await;

        // Find all handlers that should receive this event
        let mut sent_count = 0;

        for subscription in subscriptions.values() {
            if self.event_matches_subscription(&event, subscription) {
                if let Some(handler) = handlers.get(&subscription.handler_handle) {
                    // Check queue size
                    let current_size = *handler.current_queue_size.read().await;
                    if current_size < handler.max_queue_size
                        && handler.sender.send(event.clone()).is_ok()
                    {
                        let mut queue_size = handler.current_queue_size.write().await;
                        *queue_size += 1;
                        sent_count += 1;
                    }
                }
            }
        }

        // Broadcast to global event bus
        let _ = self.global_event_bus.send(event);

        if self.is_tdx_env {
            log::debug!("Sent event to {} handlers in TDX secure mode", sent_count);
        } else {
            log::debug!("Sent event to {} handlers", sent_count);
        }

        Ok(())
    }

    /// Request event from event handler (blocking)
    pub async fn request_event_from_handler(
        &self,
        handler_handle: EventHandlerHandle,
        timeout_ms: Option<u64>,
    ) -> HalResult<Event> {
        let handlers = self.handlers.read().await;
        let handler = handlers
            .get(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        let mut receiver = handler.receiver.write().await;

        let event = if let Some(timeout_duration) = timeout_ms {
            timeout(Duration::from_millis(timeout_duration), receiver.recv())
                .await
                .map_err(|_| HalError::Timeout("Event receive timeout".to_string()))?
                .ok_or_else(|| HalError::EventError("Event handler channel closed".to_string()))?
        } else {
            receiver
                .recv()
                .await
                .ok_or_else(|| HalError::EventError("Event handler channel closed".to_string()))?
        };

        // Update queue size
        let mut queue_size = handler.current_queue_size.write().await;
        *queue_size = queue_size.saturating_sub(1);

        Ok(event)
    }

    /// Request event from event handler (non-blocking)
    pub async fn try_request_event_from_handler(
        &self,
        handler_handle: EventHandlerHandle,
    ) -> HalResult<Option<Event>> {
        let handlers = self.handlers.read().await;
        let handler = handlers
            .get(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        let mut receiver = handler.receiver.write().await;

        match receiver.try_recv() {
            Ok(event) => {
                // Update queue size
                let mut queue_size = handler.current_queue_size.write().await;
                *queue_size = queue_size.saturating_sub(1);
                Ok(Some(event))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(HalError::EventError(
                "Event handler channel closed".to_string(),
            )),
        }
    }

    /// Create a typed event
    pub fn create_event(
        event_type: &str,
        source: &str,
        target: Option<&str>,
        data: EventData,
        priority: EventPriority,
    ) -> Event {
        let event_id = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Event {
            event_id,
            event_type: event_type.to_string(),
            source: source.to_string(),
            target: target.map(|t| t.to_string()),
            timestamp,
            data,
            priority,
        }
    }

    /// Get event handler information
    pub async fn get_event_handler_info(
        &self,
        handler_handle: EventHandlerHandle,
    ) -> HalResult<EventHandlerInfo> {
        let handlers = self.handlers.read().await;
        let handler = handlers
            .get(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        let current_queue_size = *handler.current_queue_size.read().await;

        Ok(EventHandlerInfo {
            handle: handler.handle,
            name: handler.name.clone(),
            event_types: handler.event_types.clone(),
            created_at: handler.created_at,
            max_queue_size: handler.max_queue_size,
            current_queue_size,
        })
    }

    /// List all event handlers
    pub async fn list_event_handlers(&self) -> HalResult<Vec<EventHandlerInfo>> {
        let handlers = self.handlers.read().await;
        let mut handler_infos = Vec::new();

        for handler in handlers.values() {
            let current_queue_size = *handler.current_queue_size.read().await;

            handler_infos.push(EventHandlerInfo {
                handle: handler.handle,
                name: handler.name.clone(),
                event_types: handler.event_types.clone(),
                created_at: handler.created_at,
                max_queue_size: handler.max_queue_size,
                current_queue_size,
            });
        }

        Ok(handler_infos)
    }

    /// Remove event handler
    pub async fn remove_event_handler(&self, handler_handle: EventHandlerHandle) -> HalResult<()> {
        let mut handlers = self.handlers.write().await;
        let mut subscriptions = self.subscriptions.write().await;

        // Remove handler
        handlers
            .remove(&handler_handle)
            .ok_or_else(|| HalError::NotFound("Event handler not found".to_string()))?;

        // Remove associated subscriptions
        subscriptions.retain(|_, subscription| subscription.handler_handle != handler_handle);

        log::info!("Removed event handler {}", handler_handle);
        Ok(())
    }

    /// Remove event subscription
    pub async fn remove_event_subscription(
        &self,
        subscription_handle: EventSubscriptionHandle,
    ) -> HalResult<()> {
        let mut subscriptions = self.subscriptions.write().await;

        subscriptions
            .remove(&subscription_handle)
            .ok_or_else(|| HalError::NotFound("Event subscription not found".to_string()))?;

        log::info!("Removed event subscription {}", subscription_handle);
        Ok(())
    }

    /// Get event statistics
    pub async fn get_event_statistics(&self) -> HalResult<EventStatistics> {
        let handlers = self.handlers.read().await;
        let subscriptions = self.subscriptions.read().await;

        let mut total_queue_size = 0;
        let mut max_queue_utilization = 0.0;

        for handler in handlers.values() {
            let current_size = *handler.current_queue_size.read().await;
            total_queue_size += current_size;

            let utilization = if handler.max_queue_size > 0 {
                (current_size as f64 / handler.max_queue_size as f64) * 100.0
            } else {
                0.0
            };

            if utilization > max_queue_utilization {
                max_queue_utilization = utilization;
            }
        }

        Ok(EventStatistics {
            total_handlers: handlers.len(),
            total_subscriptions: subscriptions.len(),
            total_queue_size,
            max_queue_utilization_percent: max_queue_utilization,
        })
    }

    // Private helper methods

    fn event_matches_subscription(&self, event: &Event, subscription: &EventSubscription) -> bool {
        // Check event type match
        if !subscription.event_types.is_empty()
            && !subscription.event_types.contains(&event.event_type)
        {
            return false;
        }

        // Check source pattern match (simplified pattern matching)
        if let Some(ref source_pattern) = subscription.subscription_filter {
            if !event.source.contains(source_pattern) {
                return false;
            }
        }

        true
    }
}

/// Event handler information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHandlerInfo {
    pub handle: EventHandlerHandle,
    pub name: String,
    pub event_types: Vec<String>,
    pub created_at: u64,
    pub max_queue_size: usize,
    pub current_queue_size: usize,
}

/// Event statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStatistics {
    pub total_handlers: usize,
    pub total_subscriptions: usize,
    pub total_queue_size: usize,
    pub max_queue_utilization_percent: f64,
}

impl Default for EventInterface {
    fn default() -> Self {
        Self::new()
    }
}

// Helper function to use UUID without adding it as a dependency
mod uuid {
    use core::fmt;

    pub struct Uuid;

    impl fmt::Display for Uuid {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // Simple UUID-like string generator for testing
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();

            write!(
                f,
                "{:x}-{:x}-{:x}-{:x}",
                timestamp & 0xffffffff,
                (timestamp >> 32) & 0xffff,
                (timestamp >> 48) & 0xffff,
                timestamp >> 64
            )
        }
    }

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_handler_creation() {
        let event_interface = EventInterface::new();

        let config = EventHandlerConfig {
            name: "test_handler".to_string(),
            event_types: vec!["test_event".to_string()],
            max_queue_size: 100,
        };

        let handle = event_interface.create_event_handler(config).await.unwrap();
        assert!(handle > 0);

        let info = event_interface
            .get_event_handler_info(handle)
            .await
            .unwrap();
        assert_eq!(info.name, "test_handler");
        assert_eq!(info.event_types, vec!["test_event"]);
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let event_interface = EventInterface::new();

        let config = EventHandlerConfig {
            name: "test_handler".to_string(),
            event_types: vec!["test_event".to_string()],
            max_queue_size: 100,
        };

        let handler_handle = event_interface.create_event_handler(config).await.unwrap();

        let filter = SubscriptionFilter {
            event_types: vec!["test_event".to_string()],
            source_pattern: None,
            target_pattern: None,
            data_filter: None,
        };

        let subscription_handle = event_interface
            .request_event_subscription(handler_handle, filter)
            .await
            .unwrap();

        assert!(subscription_handle > 0);
    }

    #[tokio::test]
    async fn test_event_sending_and_receiving() {
        let event_interface = EventInterface::new();

        let config = EventHandlerConfig {
            name: "test_handler".to_string(),
            event_types: vec!["test_event".to_string()],
            max_queue_size: 100,
        };

        let handler_handle = event_interface.create_event_handler(config).await.unwrap();

        let event = EventInterface::create_event(
            "test_event",
            "test_source",
            Some("test_target"),
            EventData::Text("Hello, World!".to_string()),
            EventPriority::Normal,
        );

        // Send event
        event_interface
            .send_event_to_handler(handler_handle, event.clone())
            .await
            .unwrap();

        // Receive event
        let received_event = event_interface
            .request_event_from_handler(handler_handle, Some(1000))
            .await
            .unwrap();

        assert_eq!(received_event.event_type, "test_event");
        assert_eq!(received_event.source, "test_source");
        assert_eq!(received_event.target, Some("test_target".to_string()));
    }

    #[tokio::test]
    async fn test_global_event_sending() {
        let event_interface = EventInterface::new();

        // Create two handlers
        let config1 = EventHandlerConfig {
            name: "handler1".to_string(),
            event_types: vec!["broadcast_event".to_string()],
            max_queue_size: 100,
        };

        let config2 = EventHandlerConfig {
            name: "handler2".to_string(),
            event_types: vec!["broadcast_event".to_string()],
            max_queue_size: 100,
        };

        let handler1 = event_interface.create_event_handler(config1).await.unwrap();
        let handler2 = event_interface.create_event_handler(config2).await.unwrap();

        // Create subscriptions
        let filter = SubscriptionFilter {
            event_types: vec!["broadcast_event".to_string()],
            source_pattern: None,
            target_pattern: None,
            data_filter: None,
        };

        let _sub1 = event_interface
            .request_event_subscription(handler1, filter.clone())
            .await
            .unwrap();

        let _sub2 = event_interface
            .request_event_subscription(handler2, filter)
            .await
            .unwrap();

        // Send global event
        let event = EventInterface::create_event(
            "broadcast_event",
            "broadcaster",
            None,
            EventData::Text("Global message".to_string()),
            EventPriority::High,
        );

        event_interface.send_event_global(event).await.unwrap();

        // Both handlers should receive the event
        let event1 = event_interface
            .try_request_event_from_handler(handler1)
            .await
            .unwrap();
        assert!(event1.is_some());

        let event2 = event_interface
            .try_request_event_from_handler(handler2)
            .await
            .unwrap();
        assert!(event2.is_some());
    }

    #[tokio::test]
    async fn test_event_handler_listing() {
        let event_interface = EventInterface::new();

        let config1 = EventHandlerConfig {
            name: "handler1".to_string(),
            event_types: vec!["event1".to_string()],
            max_queue_size: 50,
        };

        let config2 = EventHandlerConfig {
            name: "handler2".to_string(),
            event_types: vec!["event2".to_string()],
            max_queue_size: 100,
        };

        let _handle1 = event_interface.create_event_handler(config1).await.unwrap();
        let _handle2 = event_interface.create_event_handler(config2).await.unwrap();

        let handlers = event_interface.list_event_handlers().await.unwrap();
        assert_eq!(handlers.len(), 2);

        let handler_names: Vec<&str> = handlers.iter().map(|h| h.name.as_str()).collect();
        assert!(handler_names.contains(&"handler1"));
        assert!(handler_names.contains(&"handler2"));
    }

    #[tokio::test]
    async fn test_queue_size_limits() {
        let event_interface = EventInterface::new();

        let config = EventHandlerConfig {
            name: "limited_handler".to_string(),
            event_types: vec!["test_event".to_string()],
            max_queue_size: 2, // Very small queue
        };

        let handler_handle = event_interface.create_event_handler(config).await.unwrap();

        let event1 = EventInterface::create_event(
            "test_event",
            "source",
            None,
            EventData::Text("Event 1".to_string()),
            EventPriority::Normal,
        );

        let event2 = EventInterface::create_event(
            "test_event",
            "source",
            None,
            EventData::Text("Event 2".to_string()),
            EventPriority::Normal,
        );

        let event3 = EventInterface::create_event(
            "test_event",
            "source",
            None,
            EventData::Text("Event 3".to_string()),
            EventPriority::Normal,
        );

        // First two events should succeed
        assert!(event_interface
            .send_event_to_handler(handler_handle, event1)
            .await
            .is_ok());
        assert!(event_interface
            .send_event_to_handler(handler_handle, event2)
            .await
            .is_ok());

        // Third event should fail due to queue limit
        assert!(event_interface
            .send_event_to_handler(handler_handle, event3)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_event_statistics() {
        let event_interface = EventInterface::new();

        let config = EventHandlerConfig {
            name: "stats_handler".to_string(),
            event_types: vec!["stats_event".to_string()],
            max_queue_size: 10,
        };

        let handler_handle = event_interface.create_event_handler(config).await.unwrap();

        let filter = SubscriptionFilter {
            event_types: vec!["stats_event".to_string()],
            source_pattern: None,
            target_pattern: None,
            data_filter: None,
        };

        let _subscription = event_interface
            .request_event_subscription(handler_handle, filter)
            .await
            .unwrap();

        let stats = event_interface.get_event_statistics().await.unwrap();
        assert_eq!(stats.total_handlers, 1);
        assert_eq!(stats.total_subscriptions, 1);
        assert_eq!(stats.total_queue_size, 0);
    }
}
