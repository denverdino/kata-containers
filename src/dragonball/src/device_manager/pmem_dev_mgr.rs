// Copyright 2026 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io;
use std::ops::Range;

use dbs_virtio_devices::{self as virtio, pmem::Pmem};
use serde_derive::{Deserialize, Serialize};
use slog::{error, info};

use crate::address_space_manager::GuestAddressSpaceImpl;
#[cfg(target_arch = "x86_64")]
use crate::api::v1::ConfidentialVmType;
use crate::config_manager::{ConfigItem, DeviceConfigInfos};
use crate::device_manager::{
    DeviceManager, DeviceMgrError, DeviceOpContext, DeviceVirtioRegionHandler,
};

const USE_SHARED_IRQ: bool = true;
const USE_GENERIC_IRQ: bool = false;

/// Errors associated with virtio-pmem configuration.
#[derive(Debug, thiserror::Error)]
pub enum PmemDeviceError {
    /// Invalid PMEM snapshot state.
    #[error("pmem snapshot error: {0}")]
    Snapshot(#[from] virtio::Error),
    /// The device ID is already configured.
    #[error("the virtio-pmem ID was already added to a different device")]
    DeviceAlreadyExists,
    /// The device cannot be added after boot.
    #[error("the update operation is not allowed after boot")]
    UpdateNotAllowedPostBoot,
    /// The backing file cannot be opened.
    #[error("failed to open virtio-pmem backing file: {0}")]
    OpenBackingFile(#[source] io::Error),
    /// The virtio-pmem device cannot be created.
    #[error("failed to create virtio-pmem device: {0}")]
    CreateDevice(#[source] virtio::Error),
    /// The device cannot be registered.
    #[error("failed to register virtio-pmem device: {0}")]
    RegisterDevice(#[source] DeviceMgrError),
    /// Required VM state is unavailable.
    #[error("device manager error: {0}")]
    DeviceManager(#[source] DeviceMgrError),
}

/// Configuration for a virtio-pmem device.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct PmemDeviceConfigInfo {
    /// Unique device identifier.
    pub id: String,
    /// Host backing file path.
    pub path: String,
    /// Optional byte range within the backing file.
    pub file_range: Option<Range<u64>>,
    /// Expose the device read-only.
    pub read_only: bool,
    /// Use a shared interrupt.
    pub use_shared_irq: Option<bool>,
    /// Use generic interrupts.
    pub use_generic_irq: Option<bool>,
}

impl ConfigItem for PmemDeviceConfigInfo {
    type Err = PmemDeviceError;

    fn id(&self) -> &str {
        &self.id
    }

    fn check_conflicts(&self, other: &Self) -> Result<(), Self::Err> {
        if self.id == other.id {
            Err(PmemDeviceError::DeviceAlreadyExists)
        } else {
            Ok(())
        }
    }
}

/// Stores virtio-pmem device configurations.
#[derive(Clone, Default)]
pub struct PmemDeviceMgr {
    pub(crate) info_list: DeviceConfigInfos<PmemDeviceConfigInfo>,
    restore_bindings: Vec<RestorePmemBinding>,
}

impl PmemDeviceMgr {
    /// Returns whether no virtio-pmem devices are configured.
    pub fn is_empty(&self) -> bool {
        self.info_list.is_empty()
    }

    /// Adds a cold-plug virtio-pmem configuration.
    pub fn insert_or_update_device(
        &mut self,
        ctx: DeviceOpContext,
        config: PmemDeviceConfigInfo,
    ) -> Result<(), PmemDeviceError> {
        if ctx.is_hotplug {
            error!(ctx.logger(), "virtio-pmem does not support hotplug";
                "subsystem" => "pmem_dev_mgr",
                "id" => &config.id,
            );
            return Err(PmemDeviceError::UpdateNotAllowedPostBoot);
        }

        info!(ctx.logger(), "add virtio-pmem device configuration";
            "subsystem" => "pmem_dev_mgr",
            "id" => &config.id,
        );
        self.info_list.insert_or_update(&config)?;
        Ok(())
    }

    /// Attaches all configured virtio-pmem devices.
    pub fn attach_devices(&mut self, ctx: &mut DeviceOpContext) -> Result<(), PmemDeviceError> {
        let epoll_mgr = ctx
            .get_epoll_mgr()
            .map_err(PmemDeviceError::DeviceManager)?;
        let vm_as = ctx.get_vm_as().map_err(PmemDeviceError::DeviceManager)?;
        let address_space = ctx
            .get_address_space()
            .map_err(PmemDeviceError::DeviceManager)?;
        #[cfg(not(target_arch = "x86_64"))]
        let f_access_platform = false;
        #[cfg(target_arch = "x86_64")]
        let f_access_platform = ctx.get_confidential_vm_type() == Some(ConfidentialVmType::TDX);

        for info in self.info_list.iter_mut() {
            let mut options = OpenOptions::new();
            options.read(true).write(!info.config.read_only);
            let file = options
                .open(&info.config.path)
                .map_err(PmemDeviceError::OpenBackingFile)?;
            let handler = DeviceVirtioRegionHandler {
                vm_as: vm_as.clone(),
                address_space: address_space.clone(),
            };
            let device = Pmem::<GuestAddressSpaceImpl>::new(
                info.config.id.clone(),
                file,
                info.config.file_range.clone(),
                info.config.read_only,
                Box::new(handler),
                epoll_mgr.clone(),
                f_access_platform,
            )
            .map_err(PmemDeviceError::CreateDevice)?;
            let mmio_dev = DeviceManager::create_mmio_virtio_device(
                Box::new(device),
                ctx,
                info.config.use_shared_irq.unwrap_or(USE_SHARED_IRQ),
                info.config.use_generic_irq.unwrap_or(USE_GENERIC_IRQ),
            )
            .map_err(PmemDeviceError::RegisterDevice)?;
            info.set_device(mmio_dev);
        }
        Ok(())
    }
}

/// Read-only PMEM inventory and MMIO transport state. RAM is stored separately.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PmemDeviceMgrState {
    /// Devices in stable attachment order.
    pub devices: Vec<super::persist::VirtioDevState<PmemDeviceConfigInfo, virtio::pmem::PmemState>>,
}

impl<'a> dbs_snapshot::Persist<'a> for PmemDeviceMgr {
    type State = PmemDeviceMgrState;
    type SaveArgs = ();
    type RestoreArgs = ();
    type Error = PmemDeviceError;
    fn save_state(&mut self, _: ()) -> Result<Self::State, Self::Error> {
        let mut devices = Vec::new();
        for info in self.info_list.iter() {
            if !info.config.read_only {
                return Err(virtio::Error::InvalidInput.into());
            }
            let device = info.device.as_ref().ok_or(virtio::Error::InvalidInput)?;
            let (device_info, transport) =
                super::persist::save_device_state::<Pmem<GuestAddressSpaceImpl>>(device, ())?;
            devices.push(super::persist::VirtioDevState {
                config: info.config.clone(),
                device_info,
                transport,
            });
        }
        Ok(PmemDeviceMgrState { devices })
    }
    fn restore_state(&mut self, state: &Self::State, _: ()) -> Result<(), Self::Error> {
        self.validate_snapshot(state)?;
        for (info, saved) in self.info_list.iter().zip(&state.devices) {
            super::persist::restore_device_state::<Pmem<GuestAddressSpaceImpl>>(
                info.device.as_ref().ok_or(virtio::Error::InvalidInput)?,
                &saved.device_info,
                &saved.transport,
                self.restore_bindings
                    .iter()
                    .find(|binding| binding.id == info.config.id)
                    .map(|binding| (binding.saved_backing, binding.current_backing)),
            )?;
        }
        Ok(())
    }
}

impl PmemDeviceMgr {
    pub(crate) fn bind_restore(
        &mut self,
        binding: &RestorePmemBinding,
    ) -> Result<(), PmemDeviceError> {
        if self.restore_bindings.iter().any(|old| old.id == binding.id)
            || !self
                .info_list
                .iter()
                .any(|info| info.config.id == binding.id && info.config.read_only)
            || binding.saved_backing.2 != binding.current_backing.2
        {
            return Err(virtio::Error::InvalidInput.into());
        }
        self.restore_bindings.push(binding.clone());
        Ok(())
    }

    pub(crate) fn output_aliases_backing(
        &self,
        output: &std::fs::File,
    ) -> Result<bool, PmemDeviceError> {
        for info in self.info_list.iter() {
            let device = info.device.as_ref().ok_or(virtio::Error::InvalidInput)?;
            let transport = device
                .as_any()
                .downcast_ref::<super::DbsMmioV2Device>()
                .ok_or(virtio::Error::InvalidInput)?;
            let mut state = transport.state();
            let inner = state
                .get_inner_device_mut()
                .as_any_mut()
                .downcast_mut::<Pmem<GuestAddressSpaceImpl>>()
                .ok_or(virtio::Error::InvalidInput)?;
            if inner.aliases_backing(output)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn validate_snapshot(
        &self,
        state: &PmemDeviceMgrState,
    ) -> Result<(), PmemDeviceError> {
        if self.info_list.len() != state.devices.len() {
            return Err(virtio::Error::InvalidInput.into());
        }
        for (info, saved) in self.info_list.iter().zip(&state.devices) {
            let mut expected = info.config.clone();
            expected.path = saved.config.path.clone();
            if !info.config.read_only || expected != saved.config {
                return Err(virtio::Error::InvalidInput.into());
            }
            let super::persist::VirtioTransportState::Mmio(transport) = &saved.transport;
            if transport.queues.len() != 1 {
                return Err(virtio::Error::InvalidInput.into());
            }
        }
        Ok(())
    }
}

/// A caller-verified replacement for a read-only PMEM asset with identical bytes.
/// The caller must authenticate content before granting this binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePmemBinding {
    /// Configured device ID.
    pub id: String,
    /// Original backing device, inode and length from authenticated snapshot state.
    pub saved_backing: (u64, u64, u64),
    /// Current opened asset's device, inode and length.
    pub current_backing: (u64, u64, u64),
}
