use anyhow::{anyhow, bail, Result};
use reqwest::blocking::{Client, RequestBuilder};
use serde_json::json;

use crate::args::EvalArgs;

/// Posts the report to the configured GitHub PR.
///
/// Updates an existing previous comment by `github-actions[bot]` (matching the
/// prover output marker) if present, otherwise posts a new one.
pub(crate) fn post_to_github_pr(args: &EvalArgs, message: &str) -> Result<()> {
    if args.github_token.trim().is_empty() {
        bail!("--github-token is required when --post-to-gh is set");
    }
    if args.pr_number.trim().is_empty() {
        bail!("--pr-number is required when --post-to-gh is set");
    }

    let client = Client::new();
    let comments_url = format!(
        "https://api.github.com/repos/{}/issues/{}/comments",
        args.github_repo, args.pr_number
    );

    let comments_response =
        set_github_headers(client.get(&comments_url), &args.github_token).send()?;
    if !comments_response.status().is_success() {
        let status = comments_response.status();
        let body = comments_response.text().unwrap_or_default();
        bail!("failed to fetch PR comments ({status}): {body}");
    }

    let comments: Vec<serde_json::Value> = comments_response
        .json()
        .map_err(|e| anyhow!("failed to decode PR comments response: {e}"))?;

    let bot_comment = comments.iter().find(|comment| {
        let is_actions_bot = comment["user"]["login"].as_str() == Some("github-actions[bot]");
        let has_perf_marker = comment["body"]
            .as_str()
            .map(|body| body.contains("SP1 Execution Results"))
            .unwrap_or(false);
        is_actions_bot && has_perf_marker
    });

    let request = if let Some(existing_comment) = bot_comment {
        let comment_url = existing_comment["url"]
            .as_str()
            .ok_or_else(|| anyhow!("existing bot comment did not include url field"))?;
        client.patch(comment_url)
    } else {
        client.post(&comments_url)
    };

    let response = set_github_headers(request, &args.github_token)
        .json(&json!({ "body": message }))
        .send()?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        bail!("failed to post/update PR comment ({status}): {body}");
    }

    Ok(())
}

fn set_github_headers(builder: RequestBuilder, token: &str) -> RequestBuilder {
    builder
        .header("Authorization", format!("Bearer {token}"))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "strata-asm-prover-perf")
}

pub(crate) fn format_github_message(results_text: &[String]) -> String {
    let mut message = String::new();
    for line in results_text {
        message.push_str(&line.replace('*', "**"));
        message.push('\n');
    }
    message
}
