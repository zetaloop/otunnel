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
                    serde_json::json!({"checks":[{"name":"configuration","passed":false,"detail":format!("{error:#}")}],"channels":{}})
                );
            } else {
                eprintln!("otunnel: {error:#}");
            }
            std::process::ExitCode::from(if diagnostic { 2 } else { 1 })
        }
    }
}
