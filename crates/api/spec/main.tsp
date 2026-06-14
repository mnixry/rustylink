import "@typespec/http";
import "@typespec/rest";

using TypeSpec.Http;
using TypeSpec.Rest;

@service(#{
  title: "Rustylink static-evidence API",
})
@server("{baseUrl}", "Tenant base URL", {
  baseUrl: string,
})
namespace Rustylink;

alias JsonObject = Record<unknown>;

model CommonDeviceQuery {
  @query os?: string;
  @query os_version?: string;
  @query app_version?: string;
  @query brand?: string;
  @query("model") device_model?: string;
  @query did?: string;
  @query build_number?: string;
  @query os_version_patch?: string;
  @query timestamp?: string;
  @query client_source?: string;
}

model BaseResponse<T> {
  code: int32;
  message?: string;
  data?: T;
  extra?: JsonObject;
}

model ActivateRequest {
  code: string;
}

model ActivateInfo {
  activate_host?: string;
  activate_backup_domain?: string;
  activate_enable_backup_domain?: boolean;
  tenant_name?: string;
  raw?: JsonObject;
}

model PasswordLoginRequest {
  login_scene: string;
  account_type: string;
  account: string;
  password: string;
}

model SendCodeRequest {
  login_scene: string;
  account_type: string;
  login_type: string;
  account: string;
}

model VerifyCodeRequest {
  login_scene: string;
  account_type: string;
  login_type: string;
  account: string;
  code: string;
}

model VerifyMfaRequest {
  login_scene: string;
  mfa_type: string;
  account: string;
  code?: string;
  password?: string;
}

model OAuthCallbackRequest {
  alias_key: string;
  code: string;
  state: string;
  code_verifier: string;
}

model LoginResult {
  token?: string;
  uid?: string;
  need_mfa?: boolean;
  mfa_token?: string;
  raw?: JsonObject;
}

model LoginSetting {
  is_v1_login?: boolean;
  raw?: JsonObject;
}

model TenantConfig {
  signing_config?: SigningConfig;
  raw?: JsonObject;
}

model SigningConfig {
  enable?: boolean;
  algorithms?: string[];
  rules?: SigningRule[];
}

model SigningRule {
  urls?: string[];
  enable_signing?: boolean;
  signing_input_params?: int32;
  max_time_desync?: int32;
}

model UserInfo {
  uid?: string;
  name?: string;
  email?: string;
  mobile?: string;
  raw?: JsonObject;
}

model VpnSetting {
  enable?: boolean;
  mode?: string;
  export_id?: int32;
  raw?: JsonObject;
}

model VpnLocation {
  id?: int32;
  name?: string;
  is_auto?: boolean;
  dots?: VpnDot[];
  raw?: JsonObject;
}

model VpnDot {
  id?: int32;
  api_ip?: string;
  api_port?: int32;
  vpn_ip?: string;
  vpn_port?: int32;
  protocol_mode?: int32;
  timeout?: int32;
  raw?: JsonObject;
}

model VpnConnRequest {
  mode?: string;
  public_key: string;
  otp?: string;
  export_id: int32;
  sign_token?: string;
  not_auto?: boolean;
}

model VpnConnResponse {
  ip: string;
  ipv6?: string;
  ip_mask?: int32;
  public_key: string;
  preshared_key?: string;
  sign_token?: string;
  protocol_version?: string;
  setting: VpnConnSetting;
  raw?: JsonObject;
}

model VpnConnSetting {
  vpn_mtu: int32;
  vpn_dns?: string;
  vpn_dns_backup?: string;
  vpn_dns_domain_split?: string[];
  vpn_route_full?: string[];
  vpn_route_split?: string[];
  v6_route_full?: string[];
  v6_route_split?: string[];
  vpn_dynamic_domain_route_split?: string;
  v6_vpn_dynamic_domain_route_split?: string;
  vpn_wildcard_dynamic_domain_route_split?: string;
  suffix_wildcard_dynamic_domain_route_split?: string;
  dynamic_domain?: string;
  central_dns?: string;
  ip_nats?: string;
}

model SecurityReportRequest {
  status: string;
  items: SecurityReportItem[];
  raw?: JsonObject;
}

model SecurityReportItem {
  name: string;
  level: int32;
  passed: boolean;
  message?: string;
}

@route("/activation/match")
@post
op activate(@body body: ActivateRequest): BaseResponse<ActivateInfo>;

@route("/api/login/v2/password")
@post
op loginByPassword(...CommonDeviceQuery, @body body: PasswordLoginRequest): BaseResponse<LoginResult>;

@route("/api/login/v2/code/send")
@post
op sendLoginCode(...CommonDeviceQuery, @body body: SendCodeRequest): BaseResponse<string>;

@route("/api/login/v2/code/verify")
@post
op verifyLoginCode(...CommonDeviceQuery, @body body: VerifyCodeRequest): BaseResponse<LoginResult>;

@route("/api/login/v2/mfa/verify")
@post
op verifyMfa(...CommonDeviceQuery, @body body: VerifyMfaRequest): BaseResponse<LoginResult>;

@route("/api/login/v2/oauth/callback")
@post
op oauthCallback(...CommonDeviceQuery, @body body: OAuthCallbackRequest): BaseResponse<LoginResult>;

@route("/api/login/setting")
@get
op getLoginSetting(...CommonDeviceQuery): BaseResponse<LoginSetting>;

@route("/api/user/info")
@get
op getUserInfo(...CommonDeviceQuery): BaseResponse<UserInfo>;

@route("/api/tenant/config")
@get
op getTenantConfig(...CommonDeviceQuery): BaseResponse<TenantConfig>;

@route("/api/vpn/setting")
@get
op getVpnSetting(...CommonDeviceQuery): BaseResponse<VpnSetting>;

@route("/api/vpn/locations")
@get
op getVpnLocations(...CommonDeviceQuery): BaseResponse<VpnLocation[]>;

@route("/vpn/conn")
@post
op vpnConn(...CommonDeviceQuery, @body body: VpnConnRequest): BaseResponse<VpnConnResponse>;

@route("/api/security/report")
@post
op reportSecurity(...CommonDeviceQuery, @body body: SecurityReportRequest): BaseResponse<string>;
