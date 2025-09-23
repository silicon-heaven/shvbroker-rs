pub mod config;
pub mod shvnode;
pub mod brokerimpl;
mod peer;

#[cfg(test)]
mod test;
mod tunnelnode;
mod serial;

pub mod spawn {
    use log::error;
    use std::future::Future;

    pub fn spawn_and_log_error<F>(fut: F)
    where
        F: Future<Output = shvrpc::Result<()>> + Send + 'static,
    {
        smol::spawn(async move {
            if let Err(e) = fut.await {
                error!("Task finished with error: {e}")
            }
        }).detach();
    }
}

fn cut_prefix(shv_path: &str, prefix: &str) -> Option<String> {
    if shv_path.starts_with(prefix) && (shv_path.len() == prefix.len() || shv_path[prefix.len() ..].starts_with('/')) {
        let shv_path = &shv_path[prefix.len() ..];
        if let Some(stripped_path) = shv_path.strip_prefix('/') {
            Some(stripped_path.to_string())
        } else {
            Some(shv_path.to_string())
        }
    } else {
        None
    }
}
