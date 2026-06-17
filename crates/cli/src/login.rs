use std::time::{Duration, Instant};

use qrcode::{QrCode, render::unicode::Dense1x2};
use rustylink_api::{BaseResponse, ThirdPartyLoginInfo, ThirdPartyTokenCheckResult};
use rustylink_core::{AppContext, auth};
use snafu::{OptionExt as _, ResultExt as _, ensure};

use crate::{
    args::{LoginSubcommand, QrAuthArgs},
    error::{CliError, Result, cli_error},
    output::print_json,
};

pub async fn handle(ctx: &mut AppContext, command: LoginSubcommand) -> Result<()> {
    match command {
        LoginSubcommand::Password(args) => {
            let response = auth::login_password(
                ctx,
                args.scene,
                args.account_type,
                args.account,
                args.password,
            )
            .await
            .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::OtpSend(args) => {
            let response = auth::send_code(
                ctx,
                args.scene,
                args.account_type,
                args.login_type,
                args.account,
            )
            .await
            .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::OtpVerify(args) => {
            let response = auth::verify_code(
                ctx,
                args.scene,
                args.account_type,
                args.login_type,
                args.account,
                args.code,
            )
            .await
            .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::MfaVerify(args) => {
            let response = auth::verify_mfa(
                ctx,
                args.scene,
                args.mfa_type,
                args.account,
                args.code,
                args.password,
            )
            .await
            .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::QrAuth(args) => handle_qr_auth(ctx, args).await?,
    }
    Ok(())
}

async fn handle_qr_auth(ctx: &mut AppContext, args: QrAuthArgs) -> Result<()> {
    ensure!(
        args.poll_interval_ms > 0,
        cli_error::InvalidPollIntervalSnafu
    );

    let links = auth::third_party_login_links(ctx)
        .await
        .context(cli_error::AuthSnafu)?;
    let providers = links
        .response
        .data
        .clone()
        .filter(|providers| !providers.is_empty())
        .context(cli_error::MissingThirdPartyProvidersSnafu)?;
    let provider = select_third_party_provider(&providers, &args)?;
    let provider_label = third_party_provider_label(&provider);
    let login_url =
        third_party_login_url(&provider).context(cli_error::MissingThirdPartyLoginUrlSnafu {
            provider: provider_label.clone(),
        })?;

    eprintln!("Provider: {provider_label}");
    eprintln!("URL: {login_url}");
    if !args.no_qr {
        print_terminal_qr(&login_url);
    }

    if let Some(callback) = callback_from_args(&args, &provider)? {
        return submit_oauth_callback(ctx, &args, &provider, callback).await;
    }

    let token =
        non_empty(provider.token.as_deref()).context(cli_error::MissingThirdPartyTokenSnafu {
            provider: provider_label,
        })?;
    let response = poll_third_party_login_token(
        ctx,
        token,
        Duration::from_millis(args.poll_interval_ms),
        Duration::from_secs(args.poll_timeout_seconds),
    )
    .await?;
    print_json(&response)?;
    Ok(())
}

fn select_third_party_provider(
    providers: &[ThirdPartyLoginInfo], args: &QrAuthArgs,
) -> Result<ThirdPartyLoginInfo> {
    if let Some(index) = args.index {
        if index == 0 {
            return cli_error::InvalidThirdPartySelectionSnafu {
                value: index.to_string(),
                max: providers.len(),
            }
            .fail();
        }
        return providers.get(index - 1).cloned().context(
            cli_error::InvalidThirdPartySelectionSnafu {
                value: index.to_string(),
                max: providers.len(),
            },
        );
    }

    if let Some(alias_key) = non_empty(args.alias_key.as_deref()) {
        if let Some(provider) = providers.iter().find(|provider| {
            provider.alias_key.as_deref() == Some(alias_key)
                || provider.alias.as_deref() == Some(alias_key)
        }) {
            return Ok(provider.clone());
        }
        return cli_error::InvalidThirdPartySelectionSnafu {
            value: alias_key.to_string(),
            max: providers.len(),
        }
        .fail();
    }

    if let Some(alias) = non_empty(args.alias.as_deref()) {
        if let Some(provider) = providers
            .iter()
            .find(|provider| provider_matches(provider, alias))
        {
            return Ok(provider.clone());
        }
        return cli_error::InvalidThirdPartySelectionSnafu {
            value: alias.to_string(),
            max: providers.len(),
        }
        .fail();
    }

    if providers.len() == 1 {
        return Ok(providers[0].clone());
    }

    cli_error::AmbiguousThirdPartyProviderSnafu {
        count: providers.len(),
    }
    .fail()
}

fn provider_matches(provider: &ThirdPartyLoginInfo, value: &str) -> bool {
    [
        provider.alias.as_deref(),
        provider.alias_key.as_deref(),
        provider.name.as_deref(),
        provider.full_title.as_deref(),
        provider.abbreviation.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|candidate| candidate == value)
}

fn third_party_provider_label(provider: &ThirdPartyLoginInfo) -> String {
    first_non_empty([
        provider.full_title.as_deref(),
        provider.name.as_deref(),
        provider.alias.as_deref(),
        provider.alias_key.as_deref(),
        provider.abbreviation.as_deref(),
    ])
    .unwrap_or_else(|| "third-party provider".to_string())
}

fn third_party_login_url(provider: &ThirdPartyLoginInfo) -> Option<String> {
    first_non_empty([
        provider.login_url.as_deref(),
        provider.url.as_deref(),
        provider.link.as_deref(),
    ])
}

fn print_terminal_qr(value: &str) {
    match QrCode::new(value.as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .build();
            eprintln!("{rendered}");
        }
        Err(error) => {
            eprintln!("Could not render QR code: {error}");
        }
    }
}

#[derive(Clone, Debug)]
struct OAuthCallbackInput {
    code: String,
    state: String,
}

fn callback_from_args(
    args: &QrAuthArgs, provider: &ThirdPartyLoginInfo,
) -> Result<Option<OAuthCallbackInput>> {
    if let Some(callback_url) = non_empty(args.callback_url.as_deref()) {
        return parse_oauth_callback_input(callback_url).map(Some);
    }

    match non_empty(args.code.as_deref()) {
        Some(code) => {
            let state = non_empty(args.state.as_deref())
                .or_else(|| non_empty(provider.state.as_deref()))
                .context(cli_error::MissingOAuthCallbackParamSnafu { param: "state" })?;
            Ok(Some(OAuthCallbackInput {
                code: code.to_string(),
                state: state.to_string(),
            }))
        }
        None if non_empty(args.state.as_deref()).is_some() => {
            cli_error::MissingOAuthCallbackParamSnafu { param: "code" }.fail()
        }
        None => Ok(None),
    }
}

fn parse_oauth_callback_input(value: &str) -> Result<OAuthCallbackInput> {
    let value = value.trim();
    let mut code = None;
    let mut state = None;

    match url::Url::parse(value) {
        Ok(url) => {
            collect_callback_pairs(url.query(), &mut code, &mut state);
            collect_callback_pairs(url.fragment(), &mut code, &mut state);
        }
        Err(_) if value.contains('=') => {
            collect_callback_pairs(
                Some(value.trim_start_matches('?').trim_start_matches('#')),
                &mut code,
                &mut state,
            );
        }
        Err(source) => {
            return Err(CliError::InvalidOAuthCallbackInput {
                value: value.to_string(),
                source,
            });
        }
    }

    Ok(OAuthCallbackInput {
        code: code.context(cli_error::MissingOAuthCallbackParamSnafu { param: "code" })?,
        state: state.context(cli_error::MissingOAuthCallbackParamSnafu { param: "state" })?,
    })
}

fn collect_callback_pairs(
    params: Option<&str>, code: &mut Option<String>, state: &mut Option<String>,
) {
    let Some(params) = params else {
        return;
    };
    for (key, value) in url::form_urlencoded::parse(params.as_bytes()) {
        match key.as_ref() {
            "code" if code.is_none() => *code = Some(value.into_owned()),
            "state" if state.is_none() => *state = Some(value.into_owned()),
            _ => {}
        }
    }
}

async fn submit_oauth_callback(
    ctx: &mut AppContext, args: &QrAuthArgs, provider: &ThirdPartyLoginInfo,
    callback: OAuthCallbackInput,
) -> Result<()> {
    let provider_label = third_party_provider_label(provider);
    let alias_key = non_empty(args.alias_key.as_deref())
        .or_else(|| non_empty(provider.alias_key.as_deref()))
        .context(cli_error::MissingThirdPartyAliasKeySnafu {
            provider: provider_label,
        })?
        .to_string();
    let response = auth::oauth_callback(ctx, Some(alias_key), callback.code, Some(callback.state))
        .await
        .context(cli_error::AuthSnafu)?;
    print_json(&response)?;
    Ok(())
}

async fn poll_third_party_login_token(
    ctx: &mut AppContext, token: &str, interval: Duration, timeout: Duration,
) -> Result<BaseResponse<ThirdPartyTokenCheckResult>> {
    let started = Instant::now();
    let timeout_seconds = timeout.as_secs();

    loop {
        match auth::check_third_party_login_token(ctx, token.to_string()).await {
            Ok(response) => return Ok(response),
            Err(error) if is_retryable_token_check_error(&error) => {
                let last_error = error.to_string();
                tracing::debug!(%error, "third-party login token not accepted yet");
                if started.elapsed() >= timeout {
                    return cli_error::ThirdPartyPollTimeoutSnafu {
                        timeout_seconds,
                        last_error,
                    }
                    .fail();
                }
            }
            Err(error) => return Err(error).context(cli_error::AuthSnafu),
        }

        tokio::time::sleep(interval).await;
    }
}

fn is_retryable_token_check_error(error: &auth::Error) -> bool {
    matches!(
        error,
        auth::Error::Api { source }
            if matches!(source.as_ref(), rustylink_api::Error::ApiStatus { .. })
    )
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find_map(trim_non_empty)
        .map(ToOwned::to_owned)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(trim_non_empty)
}

fn trim_non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
