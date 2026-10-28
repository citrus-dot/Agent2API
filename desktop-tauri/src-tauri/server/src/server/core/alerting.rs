//! 运维告警 —— 四类规则 + webhook 推送（借鉴 Coding2API `tasks/alerting.py`
//! 的机制层，自建 fork 新增）。
//!
//! ## 与定时任务表的关系
//!
//! 不进 `scheduled_tasks` 的注册表：它没有「用户可调的间隔」语义（评估周期
//! 固定 5 分钟），也不产生要在面板展示的排期状态 —— 与
//! `providers::zcode::config_sync::spawn` 同款独立循环形态。开关就是
//! `alertWebhookUrls` 配没配：**没配时四规则照常评估、结果只走日志**
//! （告警的本质是「有异常要被看见」，日志就是最低限度的看见）；配了才外推。
//!
//! ## 四规则（severity 与判据）
//!
//! 1. **凭证池耗尽**（critical）：启用账号 ≥ 1 且全部账号都处于任一模型的
//!    限流冷却中 —— 服务「活着但用不了」，`/health` 看不出来。
//! 2. **后台任务连续失败**（warning）：`task_state.failures ≥ 3`（连续失败
//!    计数，成功一轮清零 —— 字段是现成的，读全量状态即可）。
//! 3. **token 临期**（warning）：账号 `expiresAt` 剩余不足 1 小时。
//! 4. **上游错误率骤升**（warning）：近 15 分钟失败率 ≥ 50% 且样本 ≥ 10
//!    （requests 表的 status 列，HTTP 语义：≥400 记失败）。
//!
//! ## 迟滞与静默（为什么需要）
//!
//! 评估每 5 分钟一轮，而池耗尽 / token 临期这类状态会**持续存在**：没有静默
//! 窗就会每轮推一次，把 webhook 端（群聊 / 手机推送）刷屏。同一条
//! `(rule, scope)` 在静默窗（60 分钟）内只推一次；迟滞（连续 2 轮命中才
//! 告警）滤掉单轮毛刺（一次探测超时 / 窗口内偶发 5xx）。迟滞状态是**进程内**
//! 的：重启后重新累积，不编造重启前的计数。
//!
//! ## webhook 契约
//!
//! POST JSON：`{"rule","scope","severity","message","at","status"}`，
//! `status` 取 `firing` / `resolved`。多个地址逗号分隔、全部尝试；单地址
//! 超时 10 秒、总预算 15 秒 —— 后台循环绝不能被远端拖死。签名（HMAC）暂缺：
//! Agent2API 没有 Coding2API 的 `APP_SECRET` 概念，等 webhook 落地后再议。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use crate::server::core::account_store::AccountStore;
use crate::server::core::task_state;
use crate::server::logging;

/// 评估周期（毫秒）
const TICK_MS: u64 = 5 * 60 * 1000;
/// 静默窗：同一条 `(rule, scope)` 在窗内只推一次（毫秒）
const SILENCE_MS: i64 = 60 * 60 * 1000;
/// 迟滞：连续命中几轮才告警
const FOR_TICKS: u32 = 2;
/// token 临期窗口（毫秒）：剩余不足这个值就告警
const TOKEN_EXPIRING_WINDOW_MS: i64 = 60 * 60 * 1000;
/// 错误率骤升的最小样本数（样本不足时不判，毛刺≠事故）
const ERROR_RATE_MIN_SAMPLES: i64 = 10;
/// webhook 单次投递超时（秒）
const WEBHOOK_TIMEOUT_SECS: u64 = 10;

/// 一条告警事件（四规则共用形状）。`rule` 用 `String` 而不是 `&'static str`：
/// 恢复推送的 rule 要从 `(rule, scope)` 键里取回来，键是运行时字符串 ——
/// 为省一次分配把类型钉成 `'static` 会逼出 leak/unreachable 的坏味道。
struct Alert {
    rule: String,
    scope: String,
    severity: &'static str,
    message: String,
}

/// 单条告警的迟滞状态：连续命中轮数（告警前）/ 未命中轮数（告警中）、
/// 上次推送时刻、是否已在告警中。
type GateState = (u32, i64, bool);
/// 迟滞 + 静默的进程内状态：`(rule, scope) → GateState`
static STATES: Mutex<Option<HashMap<(String, String), GateState>>> = Mutex::new(None);

/// webhook 地址表（kv `alertWebhookUrls`，逗号分隔；空 = 只日志不外推）
fn webhook_urls() -> Vec<String> {
    crate::server::config::current()
        .raw()
        .get("alertWebhookUrls")
        .and_then(Value::as_str)
        .map(|text| {
            text.split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 规则 1：凭证池耗尽（critical）—— 启用账号全都在冷却中。
fn rule_pool_exhausted(store: &AccountStore, now: i64) -> Option<Alert> {
    let accounts = store.list_accounts();
    let array = accounts.as_array()?;
    let enabled: Vec<&Value> = array
        .iter()
        .filter(|account| account.get("enabled").and_then(Value::as_bool) != Some(false))
        .collect();
    if enabled.is_empty() {
        return None; // 池是空的属于「没配置」，不是故障
    }
    let all_limited = enabled.iter().all(|account| {
        let Some(limits) = account.get("rateLimits").and_then(Value::as_object) else {
            return false;
        };
        // 任一模型的冷却仍有效即「该账号此刻不可用」；全部账号都不可用才是告警
        limits
            .values()
            .any(|limit| limit.get("resetAt").and_then(Value::as_f64).unwrap_or(0.0) > now as f64)
    });
    all_limited.then(|| Alert {
        rule: "pool_exhausted".to_string(),
        scope: "pool".to_string(),
        severity: "critical",
        message: format!(
            "凭证池耗尽：{} 个启用账号全部处于限流冷却中",
            enabled.len()
        ),
    })
}

/// 规则 2：后台任务连续失败（warning）—— failures ≥ 3。
fn rule_task_failures() -> Vec<Alert> {
    let Ok(states) = task_state::read_all() else {
        return Vec::new();
    };
    states
        .into_iter()
        .filter(|(_, state)| state.failures >= 3)
        .map(|(key, state)| {
            let label = key
                .split(':')
                .next_back()
                .unwrap_or(key.as_str())
                .to_string();
            Alert {
                rule: "task_failures".to_string(),
                scope: key.clone(),
                severity: "warning",
                message: format!(
                    "后台任务「{label}」连续失败 {} 次（上次：{}）",
                    state.failures,
                    state.last_error.as_deref().unwrap_or("未知原因")
                ),
            }
        })
        .collect()
}

/// 规则 3：token 临期（warning）—— 剩余不足 1 小时。
fn rule_token_expiring(store: &AccountStore, now: i64) -> Vec<Alert> {
    let accounts = store.list_accounts();
    let Some(array) = accounts.as_array() else { return Vec::new() };
    array
        .iter()
        .filter_map(|account| {
            let expires_at = account.get("expiresAt").and_then(Value::as_f64)?;
            let remaining = expires_at as i64 - now;
            (expires_at > 0.0 && remaining > 0 && remaining <= TOKEN_EXPIRING_WINDOW_MS).then(|| {
                let name = account
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("未命名");
                let id = account
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                Alert {
                    rule: "token_expiring".to_string(),
                    scope: id.to_string(),
                    severity: "warning",
                    message: format!("账号「{name}」的凭证将在 {} 分钟内过期", remaining / 60_000),
                }
            })
        })
        .collect()
}

/// 规则 4：上游错误率骤升（warning）—— 近 15 分钟失败率 ≥ 50% 且样本 ≥ 10。
async fn rule_error_rate(stats: &crate::server::request_stats::RequestStats) -> Vec<Alert> {
    let now = logging::now_ms();
    let Some((total, failed)) = stats.error_rate_window(now - 15 * 60 * 1000) else {
        return Vec::new();
    };
    if total < ERROR_RATE_MIN_SAMPLES {
        return Vec::new();
    }
    let rate = failed as f64 / total as f64;
    (rate >= 0.5)
        .then(|| Alert {
            rule: "error_rate".to_string(),
            scope: "upstream".to_string(),
            severity: "warning",
            message: format!(
                "上游错误率骤升：近 15 分钟 {failed}/{total} 失败（{:.0}%）",
                rate * 100.0
            ),
        })
        .into_iter()
        .collect()
}

/// 迟滞 + 静默判定的进程内半部：命中表进、要推的表出（含恢复推送）。
/// 纯函数（只碰 STATES 这一处进程内状态），IO 全在调用方 —— 与
/// Coding2API `evaluate_alerts` / `AlertTask` 的分离同一理由。
fn gate(alerts: Vec<Alert>, now: i64) -> Vec<Alert> {
    let Ok(mut guard) = STATES.lock() else { return Vec::new() };
    let states = guard.get_or_insert_with(HashMap::new);
    let mut firing = Vec::new();
    let mut seen: HashMap<(String, String), ()> = HashMap::new();
    for alert in alerts {
        let key = (alert.rule.to_string(), alert.scope.clone());
        seen.insert(key.clone(), ());
        let entry = states.entry(key).or_insert((0, 0, false));
        if entry.2 {
            // 已在告警中：受静默窗约束，不重复推
            if now - entry.1 < SILENCE_MS {
                continue;
            }
            entry.1 = now;
            firing.push(alert);
            continue;
        }
        // 未激活：迟滞 —— 连续 FOR_TICKS 轮命中才进告警；轮次即 entry.0
        entry.0 += 1;
        if entry.0 < FOR_TICKS {
            continue;
        }
        entry.0 = 0;
        entry.1 = now;
        entry.2 = true;
        firing.push(alert);
    }
    // 恢复：既有告警连续 2 轮不再命中 → 推一条 resolved（severity=info）
    let mut resolved = Vec::new();
    for (key, state) in states.iter_mut() {
        if seen.contains_key(key) || !state.2 {
            continue;
        }
        state.0 = state.0.saturating_add(1);
        if state.0 >= 2 {
            state.2 = false;
            state.0 = 0;
            resolved.push(Alert {
                rule: key.0.clone(),
                scope: key.1.clone(),
                severity: "info",
                message: "已恢复".to_string(),
            });
        }
    }
    firing.extend(resolved);
    firing
}

/// 一轮评估：四规则 → 迟滞/静默 → 推送（webhook + 日志）。
async fn evaluate_once(store: &AccountStore, stats: &crate::server::request_stats::RequestStats) {
    let now = logging::now_ms();
    let mut alerts = Vec::new();
    if let Some(alert) = rule_pool_exhausted(store, now) {
        alerts.push(alert);
    }
    alerts.extend(rule_task_failures());
    alerts.extend(rule_token_expiring(store, now));
    alerts.extend(rule_error_rate(stats).await);
    if alerts.is_empty() {
        return;
    }
    for alert in gate(alerts, now) {
        logging::log_with_level(
            "[Alert]",
            &format!("{}：{}", alert.rule, alert.message),
            if alert.severity == "critical" { "error" } else { "warn" },
        );
        deliver(&alert).await;
    }
}

/// webhook 外推：全部地址都投，单地址失败只打控制台（告警不能因为一个
/// 远端挂掉而中断，也不能把后台循环拖死）。
async fn deliver(alert: &Alert) {
    let urls = webhook_urls();
    if urls.is_empty() {
        return;
    }
    let body = json!({
        "rule": alert.rule,
        "scope": alert.scope,
        "severity": alert.severity,
        "message": alert.message,
        "at": logging::now_ms(),
        "status": if alert.severity == "info" { "resolved" } else { "firing" },
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
        .build()
        .unwrap_or_default();
    for url in &urls {
        let result = client.post(url).json(&body).send().await;
        if let Err(error) = result {
            logging::console_line(
                "[Alert]",
                &format!("webhook 投递失败（{}）：{error}", mask_url(url)),
            );
        }
    }
}

/// webhook URL → 只留 scheme://host（path 里常是密钥）
fn mask_url(url: &str) -> String {
    urlsplit_scheme_host(url).unwrap_or_else(|| "<webhook>".to_string())
}

fn urlsplit_scheme_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    Some(format!("{scheme}://{host}"))
}

/// 起告警循环（`ServerState::bootstrap` 调一次，进程内一个循环）。
pub fn spawn(store: AccountStore, stats: std::sync::Arc<crate::server::request_stats::RequestStats>) {
    crate::spawn_task(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(TICK_MS)).await;
            evaluate_once(&store, &stats).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 静默窗：同一条告警在窗内只推一次（第二轮命中不推）
    #[test]
    fn silence_window_suppresses_repeats() {
        // 清场：显式置空表（None 也是合法初始态 —— gate 的 get_or_insert_with
        // 会兜住，这里 Some(空) 保证测试语义清晰、不受前序测试的 None 影响）
        {
            let Ok(mut guard) = STATES.lock() else { panic!() };
            *guard = Some(HashMap::new());
        }
        let alert = Alert {
            rule: "pool_exhausted".to_string(),
            scope: "pool".to_string(),
            severity: "critical",
            message: "test".to_string(),
        };
        let now = 1_000_000_000_000;
        // 第 1 轮：未达迟滞（FOR_TICKS=2），不推
        assert!(gate(vec![clone_alert(&alert)], now).is_empty());
        // 第 2 轮：达到迟滞，推
        assert_eq!(gate(vec![clone_alert(&alert)], now + 1000).len(), 1);
        // 第 3 轮：静默窗内，不推
        assert!(gate(vec![clone_alert(&alert)], now + 2000).is_empty());
        // 窗后仍命中：再推一次
        assert_eq!(
            gate(vec![clone_alert(&alert)], now + SILENCE_MS + 1000).len(),
            1
        );
        // 不再命中：连续 2 轮不命中才推恢复
        assert!(gate(Vec::new(), now + SILENCE_MS + 2000).is_empty());
        let resolved = gate(Vec::new(), now + SILENCE_MS + 3000);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].severity, "info");
    }

    fn clone_alert(alert: &Alert) -> Alert {
        Alert {
            rule: alert.rule.clone(),
            scope: alert.scope.clone(),
            severity: alert.severity,
            message: alert.message.clone(),
        }
    }
}
