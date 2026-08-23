use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = gitveil::cli::parse();
    match gitveil::cli::run(cli) {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(error) => {
            eprintln!("gitveil: {error}");
            ExitCode::from(gitveil::cli::error_exit_code(error.category()))
        }
    }
}
