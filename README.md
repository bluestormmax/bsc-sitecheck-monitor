# SiteCheck Monitor

A lightweight WordPress plugin that runs a remote [Sucuri SiteCheck](https://sitecheck.sucuri.net/) malware/blocklist scan on a schedule and emails the results.

Built to replace the Sucuri Security plugin in setups where only the SiteCheck feature is wanted — Sucuri's plugin hooks the WordPress authentication flow and conflicts with Wordfence's 2FA (producing the `An error was encountered while trying to authenticate` lockout). This plugin makes only outbound `wp_remote_get` calls and never touches the login layer, so it coexists cleanly with Wordfence.

## What it does

- Runs a remote SiteCheck scan of the site's home URL on a WP-Cron schedule (hourly / twice daily / daily / weekly).
- Emails a summary — to one or more recipients — either only when something is flagged, or on every scan.
- Surfaces status in a dashboard widget and an admin notice when an issue is detected.
- Provides a manual **Scan now** button (forces a fresh, uncached scan).

## Install / update

Download the latest `bsc-sitecheck-monitor-<version>.zip` from the [Releases](../../releases) page (under **Assets** — _not_ the auto-generated "Source code" zip, which has the wrong folder name and bundles dev files). Then in wp-admin go to **Plugins → Add New → Upload Plugin**, choose the zip, and install. If an older copy is present, WordPress offers **Replace current with uploaded**. Activate, then configure under **Settings → SiteCheck Monitor**.

(For local dev you can instead copy the `bsc-sitecheck-monitor/` folder straight into `wp-content/plugins/`.)

## Configuration

| Setting | Notes |
| --- | --- |
| **Notify** | Comma-separated list of recipient emails. Defaults to the site admin email. |
| **Frequency** | Hourly, twice daily, daily (default), or weekly. |
| **Email me** | Only on flagged issues (default), or every scan. |
| **Fresh scan** | Bypass Sucuri's result cache on each run. Off by default; slower and uses more of the free quota. |

## How it works

It calls the same undocumented JSON endpoint the official Sucuri plugin uses internally:

```
GET https://sitecheck.sucuri.net/?json=1&fromwp=2&scan=<site-url>[&clear=1]
```

The response parser is deliberately defensive — it pulls warnings from the `MALWARE`, `BLACKLIST`, and `WEBAPP` buckets and flattens whatever shape they arrive in, so an upstream schema change degrades to "fewer items parsed" rather than a fatal error.

## Caveats

- **Undocumented endpoint.** Sucuri can change or rate-limit it without notice.
- **Remote-only.** SiteCheck sees what a browser sees, so it's an early-warning tripwire for visible infections and blocklisting — not a replacement for server-side scanning.
- **Fleet use.** First cron runs are staggered by a random 1–60 min offset, and the cache is left on by default to avoid hammering the free endpoint across many sites. Keep "Fresh scan" off when deploying broadly.

## Releasing a new version

The version lives in two places in `bsc-sitecheck-monitor.php` — the `Version:` header and the `Plugin::VERSION` constant. Bump both, following [semver](https://semver.org/) (patch for fixes, minor for backward-compatible features, major for breaking changes), then cut a release:

```bash
# 1. Bump the version in both spots in bsc-sitecheck-monitor.php (e.g. 1.0.1 -> 1.0.2)

# 2. Commit the bump
git commit -am "Bump version to 1.0.2"
git push

# 3. Build the clean, uploadable zip (reads the version from the header)
./build.sh                       # -> dist/bsc-sitecheck-monitor-1.0.2.zip

# 4. Cut the release and attach the zip as a downloadable asset
gh release create v1.0.2 dist/bsc-sitecheck-monitor-1.0.2.zip \
  --title "v1.0.2" \
  --notes "What changed in this release."
```

The release asset is then downloadable from the Releases page and ready to upload via wp-admin (see [Install / update](#install--update)). `build.sh` ships only an explicit allowlist of files (the plugin file + this README) so dev cruft and local config never end up in the zip; build output lands in the git-ignored `dist/` directory.

## Namespace

PHP namespace: `BSC\SiteCheckMonitor` (main class `BSC\SiteCheckMonitor\Plugin`). Runtime identifiers (option keys, cron hook, nonce) use the `bsc_scm_` prefix.

## License

GPL-2.0-or-later.
