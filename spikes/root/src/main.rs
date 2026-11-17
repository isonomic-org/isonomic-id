// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Two ways to root an identity, run through the same tests.
//!
//! `cargo run --release -p root-spike` prints the results table and the
//! timings. `cargo test -p root-spike` pins the findings.

mod account;
mod eth;
mod keylog;
mod scenarios;
mod timings;

fn main() {
    let columns = [
        (
            "A  smart account, changes on a chain",
            scenarios::smart_account(false),
        ),
        (
            "A' smart account, changes signed offline",
            scenarios::smart_account(true),
        ),
        ("C  key log with a bound account", scenarios::key_log()),
    ];
    for (n, test) in scenarios::TESTS.iter().enumerate() {
        println!("\n{}. {test}", n + 1);
        for (name, outcomes) in &columns {
            let mark = if outcomes[n].pass { "PASS" } else { "FAIL" };
            println!("   {mark}  {name}: {}", outcomes[n].note);
        }
    }
    println!();
    timings::print();
}

#[cfg(test)]
mod tests {
    use super::scenarios::{key_log, smart_account, Outcome};

    fn marks(outcomes: &[Outcome]) -> String {
        outcomes
            .iter()
            .map(|o| if o.pass { 'P' } else { 'F' })
            .collect()
    }

    /// The findings the decision rests on. If one of these changes, the
    /// decision memo is out of date.
    #[test]
    fn findings() {
        assert_eq!(marks(&smart_account(false)), "PFFFFPFFPF");
        assert_eq!(marks(&smart_account(true)), "PPPPPPFFPF");
        assert_eq!(marks(&key_log()), "PPPPPPFPPP");
    }
}
