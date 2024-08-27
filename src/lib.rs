pub mod config;
pub mod shvnode;
pub mod brokerimpl;
mod peer;

#[cfg(test)]
mod test;
mod tunnelnode;

mod spawn {
    use log::error;
    use std::future::Future;
    use async_std::task;
    pub fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
    where
        F: Future<Output = shvrpc::Result<()>> + Send + 'static,
    {
        task::spawn(async move {
            if let Err(e) = fut.await {
                error!("{}", e)
            }
        })
    }
}
pub(crate) use spawn::spawn_and_log_error;