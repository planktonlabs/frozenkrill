use std::time::Duration;

use indicatif::ProgressBar;

pub fn get_prefixed_progress_bar(len: usize, prefix: &str, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len.try_into().expect("to be able to convert"));
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.dim.bold}{prefix:>19.cyan.bold} [{bar:50}] {pos}/{len} {wide_msg}",
        )
        .expect("to be a good template")
        .progress_chars("=> ")
        .tick_chars("/|\\- "),
    );
    pb.enable_steady_tick(Duration::from_millis(150));
    pb.set_prefix(prefix.to_owned());
    pb.set_message(message.to_owned());
    pb
}

pub fn get_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::with_template("{spinner:.cyan} {wide_msg}")
            .expect("to be a good template")
            .tick_strings(&[
                "●     ",
                "●●    ",
                "●●●   ",
                "●●●●  ",
                "●●●●● ",
                "●●●●●●",
                "●●●●●●",
            ]),
    );
    pb.enable_steady_tick(Duration::from_millis(150));
    pb.set_message(message.to_owned());
    pb
}
