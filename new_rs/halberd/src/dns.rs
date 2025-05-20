// src/dns_utils.rs
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};

pub struct SrvEndpoint {
    pub target: String,
    pub ip:     IpAddr,
    pub port:   u16,
}

/// Резолвит SRV-записи `_ramp._tcp.<domain>` и возвращает первую рабочую запись
pub async fn resolve_ramp_srv(domain: &str) -> Result<SrvEndpoint> {
    // Конструктор резолвера – синхронный, ошибок не бросает
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let name = format!("_ramp._tcp.{}", domain);
    let response = resolver
        .srv_lookup(name.clone())
        .await
        .map_err(|e| anyhow!("SRV lookup failed for {}: {}", name, e))?;

    let mut records: Vec<_> = response.iter().collect();
    records.sort_by_key(|srv| (srv.priority(), !srv.weight()));

    for srv in records {
        let target = srv.target().to_utf8();
        let port = srv.port();
        let lookup = resolver
            .lookup_ip(target.clone())
            .await
            .map_err(|e| anyhow!("A/AAAA lookup failed for {}: {}", target, e))?;
        if let Some(ip) = lookup.iter().next() {
            return Ok(SrvEndpoint { target, ip, port });
        }
    }

    Err(anyhow!("No usable SRV records for domain {}", domain))
}

/// Проверяет, что `client_ip` входит в список A/AAAA для `_ramp._tcp.<claimed_domain>`
pub async fn verify_ramp_domain(
    claimed_domain: &str,
    client_ip: IpAddr,
) -> Result<()> {
    // Сначала получаем SRV target
    let SrvEndpoint { target, .. } = resolve_ramp_srv(claimed_domain).await?;

    // Снова создаём резолвер
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let lookup = resolver
        .lookup_ip(target.clone())
        .await
        .map_err(|e| anyhow!("A/AAAA lookup failed for {}: {}", target, e))?;

    if lookup.iter().any(|ip| ip == client_ip) {
        Ok(())
    } else {
        Err(anyhow!(
            "IP {} is not authorized for domain {}",
            client_ip,
            claimed_domain
        ))
    }
}