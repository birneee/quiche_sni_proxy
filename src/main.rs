extern crate core;

use clap::Parser;
use quiche_sni_proxy::{run_proxy, Args};

fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let args = Args::parse();
    run_proxy(args, None);
}

