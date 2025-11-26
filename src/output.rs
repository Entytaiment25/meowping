use crate::colors::Colorize;
use std::collections::VecDeque;

pub fn print_with_prefix(minimal: bool, message: String) {
    if minimal {
        println!("{}", message);
    } else {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    }
}

pub fn print_statistics(protocol: &str, count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;

    let good_times: Vec<u128> = times.iter().copied().filter(|&t| t > 0).collect();

    let (min_time, max_time, avg_time) = if !good_times.is_empty() {
        let min = (*good_times.iter().min().unwrap() as f32) / 1000.0;
        let max = (*good_times.iter().max().unwrap() as f32) / 1000.0;
        let avg = (good_times.iter().sum::<u128>() as f32) / (good_times.len() as f32) / 1000.0;
        (min, max, avg)
    } else {
        (0.0, 0.0, 0.0)
    };

    let loss_percentage = if count > 0 {
        ((failed as f32) / (count as f32)) * 100.0
    } else {
        0.0
    };

    println!("\n{} Ping statistics:", protocol);
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({} loss)",
        count.to_string().bright_blue(),
        successes.to_string().bright_blue(),
        failed.to_string().bright_blue(),
        format!("{:.2}%", loss_percentage).bright_blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).bright_blue(),
        format!("{:.2}ms", max_time).bright_blue(),
        format!("{:.2}ms", avg_time).bright_blue()
    );
}

pub fn color_time(time_ms: f64) -> String {
    let msg = format!("{:.2}ms", time_ms);
    match time_ms {
        t if t >= 250.0 => msg.orange(),
        t if t >= 100.0 => msg.yellow(),
        _ => msg.green(),
    }
}
