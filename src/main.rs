mod cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let arguments = cli::command().get_matches();
    let diagnostic = arguments.subcommand_name() == Some("doctor");
    match cli::execute(&arguments).await {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            if diagnostic
                && arguments
                    .subcommand()
                    .is_some_and(|(_, matches)| matches.get_flag("json"))
            {
                println!(
                    "{}",
                    serde_json::to_string(&otunnel::diagnostic::Report::new(
                        vec![otunnel::diagnostic::Check::fail(
                            "config_validation",
                            format!("{error:#}")
                        )],
                        Default::default(),
                        String::new(),
                    ))
                    .expect("diagnostic report")
                );
            } else {
                eprintln!("otunnel: {error:#}");
            }
            std::process::ExitCode::from(if diagnostic { 2 } else { 1 })
        }
    }
}
