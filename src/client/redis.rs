use redis::{Client, RedisError};
use std::time::Duration;
use tracing::info;

use crate::config::ServiceConfig;

pub type RedisClient = redis::Client;
pub trait RedisClientBuilder: Sized {
    fn build_from_config(config: &ServiceConfig) -> Result<Self, RedisError>;
}

pub trait RedisClientExt: RedisClientBuilder {
    fn ping(&self) -> impl std::future::Future<Output = Result<Option<String>, RedisError>>;
    fn set(
        &self,
        key: &str,
        value: &str,
        expire: Duration,
    ) -> impl std::future::Future<Output = Result<(), RedisError>>;
    fn exist(&self, key: &str) -> impl std::future::Future<Output = Result<bool, RedisError>>;
    fn get(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>, RedisError>>;
    fn del(&self, key: &str) -> impl std::future::Future<Output = Result<bool, RedisError>>;
    fn ttl(&self, key: &str) -> impl std::future::Future<Output = Result<i64, RedisError>>;
}

impl RedisClientBuilder for RedisClient {
    fn build_from_config(config: &ServiceConfig) -> Result<Self, RedisError> {
        Ok(redis::Client::open(config.redis.get_url())?)
    }
}

impl RedisClientExt for Client {
    async fn ping(&self) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let value: Option<String> = redis::cmd("PING").query_async(&mut conn).await?;
        info!("ping redis server");
        Ok(value)
    }

    async fn set(&self, key: &str, value: &str, expire: Duration) -> Result<(), RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let msg: String = redis::cmd("SET")
            .arg(&[key, value])
            .query_async(&mut conn)
            .await?;
        info!("set key redis: {msg}");
        let msg: i32 = redis::cmd("EXPIRE")
            .arg(&[key, &expire.as_secs().to_string()])
            .query_async(&mut conn)
            .await?;
        info!("set expire time redis: {msg}");
        Ok(())
    }

    async fn exist(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let value: bool = redis::cmd("EXISTS").arg(key).query_async(&mut conn).await?;
        info!("check key exists: {key}");
        Ok(value)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let value: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
        info!("get value: {key}");
        Ok(value)
    }

    async fn del(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let value: i32 = redis::cmd("DEL").arg(key).query_async(&mut conn).await?;
        info!("delete value: {key}");
        Ok(value == 1)
    }
    async fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_multiplexed_async_connection().await?;
        let value: i64 = redis::cmd("TTL").arg(key).query_async(&mut conn).await?;
        info!("get TTL value: {key}");
        Ok(value)
    }
}
