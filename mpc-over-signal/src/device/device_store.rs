use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use tokio::io::AsyncWriteExt;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::Device;

#[derive(Clone)]
pub struct DeviceStore {
    secrets: Arc<RwLock<Device>>,
}

impl DeviceStore {
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let secrets = Self::device_read(path)
            .await
            .context("cannot read device secrets from file")?;
        Ok(Self {
            secrets: Arc::new(RwLock::new(secrets)),
        })
    }

    pub fn new(secrets: Device) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(secrets)),
        }
    }

    pub async fn read(&self) -> RwLockReadGuard<'_, Device> {
        self.secrets.read().await
    }

    pub async fn write(&self) -> RwLockWriteGuard<'_, Device> {
        self.secrets.write().await
    }

    pub async fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let secrets = self.secrets.read().await;
        Self::device_write(&secrets, path, true).await
    }

    pub async fn save_no_overwrite(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let secrets = self.secrets.read().await;
        Self::device_write(&secrets, path, false).await
    }

    pub async fn reload(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let mut secrets = self.secrets.write().await;
        *secrets = Self::device_read(path).await?;
        Ok(())
    }

    async fn device_read(path: impl AsRef<Path>) -> Result<Device> {
        let device = tokio::fs::read(path).await.context("read file")?;
        serde_json::from_slice(&device).context("parse file")
    }

    async fn device_write(
        secrets: &Device,
        path: impl AsRef<Path>,
        may_overwrite: bool,
    ) -> Result<()> {
        let device_content = serde_json::to_vec_pretty(secrets).context("serialize")?;

        let mut options = tokio::fs::OpenOptions::new();

        #[cfg(unix)]
        options.mode(0o600);
        options.write(true);
        if may_overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }

        let mut device_file = options
            .open(path)
            .await
            .context("cannot create/open file")?;

        device_file
            .write_all(&device_content)
            .await
            .context("write to secrets file")?;

        Ok(())
    }
}
