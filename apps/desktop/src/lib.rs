//! Cyclar desktop: host and controller share the same authenticated session core.
#![forbid(unsafe_code)]

pub mod api;
pub mod identity;
pub mod packet;
pub mod relay;
pub mod secure;
pub mod transfers;

#[cfg(target_os = "linux")]
pub mod controller;

#[cfg(target_os = "linux")]
pub mod host;

#[cfg(target_os = "linux")]
pub mod x11;
