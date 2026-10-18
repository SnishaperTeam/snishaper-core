# snishaper-core

[中文](README.md) | [English](README_EN.md) | [Русский](README_RU.md)

[![Go Version](https://img.shields.io/badge/Go-1.27%2B-00ADD8?style=flat&logo=go)](https://golang.org) [![License](https://img.shields.io/badge/Лицензия-AGPL--3.0-blue?style=flat&logo=open-source-initiative)](LICENSE) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/SnishaperTeam/snishaper-core/build.yml?style=flat&logo=githubactions&label=CI)](https://github.com/SnishaperTeam/snishaper-core/actions) [![GitHub last commit](https://img.shields.io/github/last-commit/SnishaperTeam/snishaper-core?style=flat&logo=git&label=последний%20коммит)](https://github.com/SnishaperTeam/snishaper-core/commits/main) [![GitHub contributors](https://img.shields.io/github/contributors/SnishaperTeam/snishaper-core?style=flat&label=контрибьюторы)](https://github.com/SnishaperTeam/snishaper-core/graphs/contributors)

**snishaper-core** — основная прокси-библиотека [SniShaper](https://github.com/SnishaperTeam/SniShaper), предоставляющая встраиваемую и тестируемую плоскость данных на Go для сложных сетевых условий: **гибридный прокси-порт**, **движок правил с MITM**, **внедрение ECH**, **фрагментация TLS**, **резолвер DoH** и **плоскость данных TUN**.

Библиотека не имеет глобального изменяемого состояния: по умолчанию молчит, не читает переменные окружения и не вызывает `os.Exit` — всё поведение внедряется через functional options.

---

## Связь с SniShaper

[SniShaper](https://github.com/SnishaperTeam/SniShaper) — десктопное приложение для Windows / Linux (GUI + CLI), построенное на этой библиотеке; оба проекта поддерживаются параллельно:

| | [SniShaper](https://github.com/SnishaperTeam/SniShaper) | snishaper-core (этот репозиторий) |
|---|---|---|
| Роль | Десктопное приложение (GUI + CLI) | Встраиваемая библиотека ядра на Go |
| Ключевые возможности | Интерфейс, системный прокси, трей, режим эволюции | ProxyServer, RuleManager, DoH, сертификаты, TUN |
| Аудитория | Конечные пользователи | Go-разработчики |

SniShaper напрямую зависит от этой библиотеки; форматы файлов правил и семантика конфигураций согласованы между проектами.

---

## Возможности

- **Гибридный прокси-порт**: HTTP CONNECT и SOCKS5 на одном порту.
- **Движок правил с MITM**: группы сайтов, несколько режимов (MITM / Transparent / TLS-RF / QUIC / Migration / Direct), выпуск сертификатов по требованию.
- **Внедрение ECH**: обнаружение через DoH, горячая перезагрузка и восстановление.
- **Фрагментация TLS**: разбиение ClientHello с доставкой OOB.
- **Умная маршрутизация**: суффиксное сопоставление GFWList и автоматическая маршрутизация.
- **Шифрованный DNS**: резолвер DoH с отказоустойчивостью между узлами.
- **Пул IP Cloudflare**: проверки здоровья, замеры задержки, NAT64.
- **Плоскость данных TUN**: прозрачный перехват на базе sing-tun (разделение Handler / Manager).
- **Нулевое глобальное состояние**: без `init()` и изменяемых пакетных переменных; безопасно для нескольких экземпляров и конкурентного встраивания.

---

## Быстрый старт

```go
rm := proxy.NewRuleManager(
    filepath.Join(dir, "config", "settings.json"),
    filepath.Join(dir, "rules", "config.json"),
)
if err := rm.LoadConfig(); err != nil { /* ... */ }

p := proxy.NewProxyServer("127.0.0.1:8080",
    proxy.WithRuleManager(rm),
    proxy.WithLogger(corelog.Std), // по умолчанию молчит; внедрите для логов
)
p.Start()
```

Рабочий пример — образец [`examples/basic`](examples/basic) в этом репозитории:

```powershell
go run ./examples/basic 8080
```

---

## Пакеты

| Пакет | Описание |
|-------|----------|
| `proxy` | ProxyServer (гибридный порт), RuleManager (движок правил), AutoRouter, MITM, исходящие соединения |
| `dohresolver` | Отказоустойчивый DoH с горячим восстановлением ECH-конфигурации |
| `cfpool` | Пул приоритетных IP Cloudflare |
| `netiface` | Выбор физического интерфейса и привязка исходящего трафика (`Selector`) |
| `tlsfrag` | Фрагментация TLS ClientHello и доставка OOB |
| `gfwlist` | Суффиксное сопоставление доменов GFWList |
| `certmanager` | Генерация CA, выпуск MITM-сертификатов, установка доверия в системе |
| `singtun` | Плоскость данных TUN на базе sing-tun |
| `config` | Общие типы конфигурации (`CertVerifyConfig` и др.) |
| `log` | Интерфейс `Logger` и адаптеры `Nop` / `Std` / `Func` |

---

## Документация

- **[docs/DESIGN.md](docs/DESIGN.md)** — проектирование библиотеки, границы пакетов и соглашения деглобализации.
- **[examples/basic](examples/basic)** — минимальный пример встраивания.
- **[SniShaper Wiki](https://github.com/SnishaperTeam/SniShaper/wiki)** — основные режимы, кастомные правила и другая документация прикладного уровня.

---

## Сборка и разработка

Библиотека написана на **Go**, минимальная версия — **1.27**. Порог перед коммитом:

```powershell
go build ./...
go vet ./...
go test ./...
```

`proxy/proxy_integration_test.go` — сквозной smoke-тест, использующий только экспортируемые API.

Руководство по внесению вклада — **[CONTRIBUTING.md](CONTRIBUTING.md)**.

---

## Лицензия

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). Библиотека произведена от SniShaper; производные работы и распространение подчиняются той же лицензии.
