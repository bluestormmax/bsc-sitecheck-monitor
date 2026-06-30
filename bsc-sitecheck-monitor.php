<?php
/**
 * Plugin Name:       SiteCheck Monitor
 * Plugin URI:        https://bluestormcreative.com/
 * Description:       Runs a remote Sucuri SiteCheck malware/blocklist scan on a schedule and emails the results. No login-layer hooks, so it won't conflict with Wordfence 2FA.
 * Version:           1.0.0
 * Requires at least: 5.4
 * Requires PHP:      7.4
 * Author:            Blue Storm Creative
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bsc-sitecheck-monitor
 *
 * SiteCheck is Sucuri's free remote scanner. This plugin calls the same
 * undocumented JSON endpoint their own plugin uses:
 *   https://sitecheck.sucuri.net/?json=1&fromwp=2&scan=<url>[&clear=1]
 * It is remote-only (browser-level visibility), so treat it as an early-warning
 * tripwire, not a server-side scanner.
 */

namespace BSC\SiteCheckMonitor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {

	const VERSION       = '1.0.0';
	const OPTION_KEY    = 'bsc_scm_settings';
	const RESULT_KEY    = 'bsc_scm_last_result';
	const CRON_HOOK     = 'bsc_scm_run_scan';
	const ENDPOINT      = 'https://sitecheck.sucuri.net/';
	const NONCE_ACTION  = 'bsc_scm_scan_now';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'cron_schedules', array( $this, 'register_schedules' ) );
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );

		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_post_' . self::NONCE_ACTION, array( $this, 'handle_scan_now' ) );
		add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widget' ) );
		add_action( 'admin_notices', array( $this, 'maybe_show_notice' ) );
	}

	/* ---------------------------------------------------------------------
	 * Defaults & settings
	 * ------------------------------------------------------------------- */

	public function defaults() {
		return array(
			'email'       => get_option( 'admin_email' ),
			'frequency'   => 'daily',   // hourly | twicedaily | daily | weekly
			'notify_mode' => 'issues',  // issues | always
			'force_fresh' => 0,         // 1 = bypass Sucuri's cache each run
		);
	}

	public function get_settings() {
		return wp_parse_args( get_option( self::OPTION_KEY, array() ), $this->defaults() );
	}

	public function register_schedules( $schedules ) {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once Weekly', 'bsc-sitecheck-monitor' ),
			);
		}
		return $schedules;
	}

	/* ---------------------------------------------------------------------
	 * Activation / deactivation
	 * ------------------------------------------------------------------- */

	public static function activate() {
		$self = self::instance();
		// Ensure custom schedules are available before we schedule.
		add_filter( 'cron_schedules', array( $self, 'register_schedules' ) );
		$self->reschedule( $self->get_settings()['frequency'] );
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function uninstall() {
		delete_option( self::OPTION_KEY );
		delete_option( self::RESULT_KEY );
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	private function reschedule( $frequency ) {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		$valid = array( 'hourly', 'twicedaily', 'daily', 'weekly' );
		if ( ! in_array( $frequency, $valid, true ) ) {
			$frequency = 'daily';
		}
		// Stagger the first run by a random offset so a fleet of sites doesn't
		// hammer the endpoint at the same minute.
		$first = time() + wp_rand( 60, 3600 );
		wp_schedule_event( $first, $frequency, self::CRON_HOOK );
	}

	/* ---------------------------------------------------------------------
	 * Settings page
	 * ------------------------------------------------------------------- */

	public function add_settings_page() {
		add_options_page(
			__( 'SiteCheck Monitor', 'bsc-sitecheck-monitor' ),
			__( 'SiteCheck Monitor', 'bsc-sitecheck-monitor' ),
			'manage_options',
			'bsc-sitecheck-monitor',
			array( $this, 'render_settings_page' )
		);
	}

	public function register_settings() {
		register_setting(
			'bsc_scm_group',
			self::OPTION_KEY,
			array( 'sanitize_callback' => array( $this, 'sanitize_settings' ) )
		);
	}

	public function sanitize_settings( $input ) {
		$old   = $this->get_settings();
		$clean = $this->defaults();

		// Allow a comma-separated list of recipients.
		$emails = array_filter( array_map( 'trim', explode( ',', (string) ( $input['email'] ?? '' ) ) ) );
		$emails = array_filter( $emails, 'is_email' );
		$clean['email'] = $emails ? implode( ', ', $emails ) : get_option( 'admin_email' );

		$freq = $input['frequency'] ?? 'daily';
		$clean['frequency'] = in_array( $freq, array( 'hourly', 'twicedaily', 'daily', 'weekly' ), true ) ? $freq : 'daily';

		$mode = $input['notify_mode'] ?? 'issues';
		$clean['notify_mode'] = in_array( $mode, array( 'issues', 'always' ), true ) ? $mode : 'issues';

		$clean['force_fresh'] = empty( $input['force_fresh'] ) ? 0 : 1;

		// Reschedule cron only when the frequency actually changed.
		if ( $old['frequency'] !== $clean['frequency'] ) {
			$this->reschedule( $clean['frequency'] );
		}

		return $clean;
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s      = $this->get_settings();
		$result = get_option( self::RESULT_KEY, array() );
		$next   = wp_next_scheduled( self::CRON_HOOK );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'SiteCheck Monitor', 'bsc-sitecheck-monitor' ); ?></h1>

			<?php $this->render_status_box( $result ); ?>

			<form method="post" action="options.php">
				<?php settings_fields( 'bsc_scm_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="bsc_scm_email"><?php esc_html_e( 'Notify', 'bsc-sitecheck-monitor' ); ?></label></th>
						<td>
							<input name="<?php echo esc_attr( self::OPTION_KEY ); ?>[email]" id="bsc_scm_email" type="text" class="regular-text" value="<?php echo esc_attr( $s['email'] ); ?>" />
							<p class="description"><?php esc_html_e( 'Comma-separate multiple addresses.', 'bsc-sitecheck-monitor' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Frequency', 'bsc-sitecheck-monitor' ); ?></th>
						<td>
							<select name="<?php echo esc_attr( self::OPTION_KEY ); ?>[frequency]">
								<?php
								$freqs = array(
									'hourly'     => __( 'Hourly', 'bsc-sitecheck-monitor' ),
									'twicedaily' => __( 'Twice daily', 'bsc-sitecheck-monitor' ),
									'daily'      => __( 'Daily', 'bsc-sitecheck-monitor' ),
									'weekly'     => __( 'Weekly', 'bsc-sitecheck-monitor' ),
								);
								foreach ( $freqs as $val => $label ) {
									printf( '<option value="%s"%s>%s</option>', esc_attr( $val ), selected( $s['frequency'], $val, false ), esc_html( $label ) );
								}
								?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Email me', 'bsc-sitecheck-monitor' ); ?></th>
						<td>
							<label><input type="radio" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[notify_mode]" value="issues" <?php checked( $s['notify_mode'], 'issues' ); ?> /> <?php esc_html_e( 'Only when something is flagged', 'bsc-sitecheck-monitor' ); ?></label><br />
							<label><input type="radio" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[notify_mode]" value="always" <?php checked( $s['notify_mode'], 'always' ); ?> /> <?php esc_html_e( 'Every scan (including clean results)', 'bsc-sitecheck-monitor' ); ?></label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Fresh scan', 'bsc-sitecheck-monitor' ); ?></th>
						<td>
							<label><input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[force_fresh]" value="1" <?php checked( $s['force_fresh'], 1 ); ?> /> <?php esc_html_e( "Bypass Sucuri's cache on each run (slower; uses more of the free quota)", 'bsc-sitecheck-monitor' ); ?></label>
						</td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>

			<hr />
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::NONCE_ACTION ); ?>" />
				<?php wp_nonce_field( self::NONCE_ACTION ); ?>
				<?php submit_button( __( 'Scan now', 'bsc-sitecheck-monitor' ), 'secondary', 'submit', false ); ?>
				<span class="description" style="margin-left:8px;">
					<?php
					if ( $next ) {
						printf(
							/* translators: %s: human-readable time difference */
							esc_html__( 'Next scheduled scan in %s.', 'bsc-sitecheck-monitor' ),
							esc_html( human_time_diff( time(), $next ) )
						);
					} else {
						esc_html_e( 'No scan scheduled yet.', 'bsc-sitecheck-monitor' );
					}
					?>
				</span>
			</form>
		</div>
		<?php
	}

	private function render_status_box( $result ) {
		if ( empty( $result ) || empty( $result['time'] ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'No scan has run yet.', 'bsc-sitecheck-monitor' ) . '</p></div>';
			return;
		}

		$flagged = ! empty( $result['issues'] );
		$class   = $flagged ? 'notice-error' : 'notice-success';
		$headline = $flagged
			? __( 'SiteCheck flagged one or more issues.', 'bsc-sitecheck-monitor' )
			: __( 'Last scan came back clean.', 'bsc-sitecheck-monitor' );

		echo '<div class="notice ' . esc_attr( $class ) . ' inline"><p><strong>' . esc_html( $headline ) . '</strong><br />';
		printf(
			/* translators: %s: human-readable time difference */
			esc_html__( 'Last scanned %s ago.', 'bsc-sitecheck-monitor' ),
			esc_html( human_time_diff( (int) $result['time'], time() ) )
		);
		echo '</p>';

		if ( $flagged ) {
			echo '<ul style="list-style:disc;margin-left:20px;">';
			foreach ( $result['issues'] as $issue ) {
				echo '<li>' . esc_html( $issue ) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
	}

	/* ---------------------------------------------------------------------
	 * Manual trigger
	 * ------------------------------------------------------------------- */

	public function handle_scan_now() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'bsc-sitecheck-monitor' ) );
		}
		check_admin_referer( self::NONCE_ACTION );

		$this->run_scan( true );

		wp_safe_redirect( add_query_arg(
			array( 'page' => 'bsc-sitecheck-monitor', 'bsc_scm_scanned' => '1' ),
			admin_url( 'options-general.php' )
		) );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Core scan
	 * ------------------------------------------------------------------- */

	public function run_scan( $manual = false ) {
		$settings = $this->get_settings();
		$target   = home_url( '/' );

		$args = array(
			'json'   => 1,
			'fromwp' => 2,
			'scan'   => $target,
		);
		if ( ! empty( $settings['force_fresh'] ) || $manual ) {
			$args['clear'] = 1;
		}

		$url = add_query_arg( array_map( 'rawurlencode', $args ), self::ENDPOINT );

		$response = wp_remote_get( $url, array(
			'timeout'    => 60,
			'user-agent' => 'SiteCheck Monitor/' . self::VERSION . '; ' . home_url( '/' ),
		) );

		if ( is_wp_error( $response ) ) {
			$result = array(
				'time'   => time(),
				'error'  => $response->get_error_message(),
				'issues' => array(),
				'clean'  => false,
			);
			update_option( self::RESULT_KEY, $result, false );
			return $result;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( 200 !== (int) $code || ! is_array( $data ) ) {
			$result = array(
				'time'   => time(),
				'error'  => sprintf( 'Unexpected response (HTTP %d).', (int) $code ),
				'issues' => array(),
				'clean'  => false,
			);
			update_option( self::RESULT_KEY, $result, false );
			return $result;
		}

		$issues = $this->extract_issues( $data );

		$result = array(
			'time'   => time(),
			'target' => $target,
			'issues' => $issues,
			'clean'  => empty( $issues ),
			'error'  => '',
		);
		update_option( self::RESULT_KEY, $result, false );

		$should_email = ( 'always' === $settings['notify_mode'] ) || ! empty( $issues );
		if ( $should_email ) {
			$this->send_email( $result, $settings['email'] );
		}

		return $result;
	}

	/**
	 * Walk the (loosely documented) SiteCheck JSON and pull out anything that
	 * reads as a warning. The shape varies, so this is intentionally defensive:
	 * we look in the buckets that carry problems and flatten them to strings.
	 */
	private function extract_issues( $data ) {
		$issues = array();

		// Malware warnings: data['MALWARE']['WARN'] = [ [..], [..] ].
		if ( isset( $data['MALWARE']['WARN'] ) ) {
			foreach ( $this->flatten( $data['MALWARE']['WARN'] ) as $msg ) {
				$issues[] = 'Malware: ' . $msg;
			}
		}

		// Blocklist warnings: data['BLACKLIST']['WARN'].
		if ( isset( $data['BLACKLIST']['WARN'] ) ) {
			foreach ( $this->flatten( $data['BLACKLIST']['WARN'] ) as $msg ) {
				$issues[] = 'Blocklist: ' . $msg;
			}
		}

		// App-level warnings (e.g. out-of-date CMS/plugins): data['WEBAPP']['WARN'].
		if ( isset( $data['WEBAPP']['WARN'] ) ) {
			foreach ( $this->flatten( $data['WEBAPP']['WARN'] ) as $msg ) {
				$issues[] = 'Warning: ' . $msg;
			}
		}

		// Generic top-level warnings, if present.
		if ( isset( $data['WARN'] ) ) {
			foreach ( $this->flatten( $data['WARN'] ) as $msg ) {
				$issues[] = 'Warning: ' . $msg;
			}
		}

		// De-dupe and trim noise.
		$issues = array_values( array_unique( array_filter( array_map( 'trim', $issues ) ) ) );

		return $issues;
	}

	/**
	 * Recursively flatten nested arrays of strings into a flat list of
	 * readable, single-line messages.
	 */
	private function flatten( $node ) {
		$out = array();
		if ( is_array( $node ) ) {
			$scalars = array();
			foreach ( $node as $child ) {
				if ( is_array( $child ) ) {
					// A warning is often a tuple like [title, detail]; join it.
					$parts = array();
					foreach ( $this->flatten( $child ) as $p ) {
						$parts[] = $p;
					}
					if ( $parts ) {
						$out[] = implode( ' — ', $parts );
					}
				} elseif ( is_scalar( $child ) ) {
					$scalars[] = (string) $child;
				}
			}
			if ( $scalars ) {
				$out[] = implode( ' — ', $scalars );
			}
		} elseif ( is_scalar( $node ) ) {
			$out[] = (string) $node;
		}
		return array_filter( array_map( 'trim', $out ) );
	}

	/* ---------------------------------------------------------------------
	 * Email
	 * ------------------------------------------------------------------- */

	private function send_email( $result, $recipients ) {
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$flagged = ! empty( $result['issues'] );

		$subject = $flagged
			? sprintf( '[SiteCheck] Issues flagged on %s', $site )
			: sprintf( '[SiteCheck] %s is clean', $site );

		$lines   = array();
		$lines[] = sprintf( 'SiteCheck scan for %s', esc_url_raw( $result['target'] ) );
		$lines[] = sprintf( 'Run at %s', wp_date( 'Y-m-d H:i T', $result['time'] ) );
		$lines[] = '';

		if ( $flagged ) {
			$lines[] = 'The following items were flagged:';
			$lines[] = '';
			foreach ( $result['issues'] as $issue ) {
				$lines[] = '  • ' . $issue;
			}
			$lines[] = '';
			$lines[] = 'Heads-up: SiteCheck is a remote scanner and only sees what a visitor sees. Confirm with a server-side scan before acting.';
		} else {
			$lines[] = 'No malware or blocklist issues were detected.';
		}

		$lines[] = '';
		$lines[] = sprintf( 'Full interactive scan: https://sitecheck.sucuri.net/results/%s', rawurlencode( wp_parse_url( $result['target'], PHP_URL_HOST ) ) );

		$body = implode( "\n", $lines );

		$to = array_filter( array_map( 'trim', explode( ',', (string) $recipients ) ) );
		if ( empty( $to ) ) {
			$to = array( get_option( 'admin_email' ) );
		}

		wp_mail( $to, $subject, $body );
	}

	/* ---------------------------------------------------------------------
	 * Dashboard widget + admin notice
	 * ------------------------------------------------------------------- */

	public function add_dashboard_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'bsc_scm_widget',
			__( 'SiteCheck Monitor', 'bsc-sitecheck-monitor' ),
			array( $this, 'render_dashboard_widget' )
		);
	}

	public function render_dashboard_widget() {
		$result = get_option( self::RESULT_KEY, array() );
		if ( empty( $result['time'] ) ) {
			echo '<p>' . esc_html__( 'No scan has run yet.', 'bsc-sitecheck-monitor' ) . '</p>';
		} elseif ( ! empty( $result['error'] ) ) {
			echo '<p><strong>' . esc_html__( 'Last scan failed:', 'bsc-sitecheck-monitor' ) . '</strong> ' . esc_html( $result['error'] ) . '</p>';
		} elseif ( ! empty( $result['issues'] ) ) {
			echo '<p style="color:#b32d2e;"><strong>' . esc_html( sprintf( _n( '%d issue flagged.', '%d issues flagged.', count( $result['issues'] ), 'bsc-sitecheck-monitor' ), count( $result['issues'] ) ) ) . '</strong></p>';
		} else {
			echo '<p style="color:#1a7e34;"><strong>' . esc_html__( 'Clean — no issues detected.', 'bsc-sitecheck-monitor' ) . '</strong></p>';
		}
		echo '<p><a href="' . esc_url( admin_url( 'options-general.php?page=bsc-sitecheck-monitor' ) ) . '">' . esc_html__( 'View details', 'bsc-sitecheck-monitor' ) . '</a></p>';
	}

	public function maybe_show_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$result = get_option( self::RESULT_KEY, array() );
		if ( ! empty( $result['issues'] ) ) {
			$screen = get_current_screen();
			// Don't double up on the settings screen, which already shows the box.
			if ( $screen && 'settings_page_bsc-sitecheck-monitor' === $screen->id ) {
				return;
			}
			echo '<div class="notice notice-error"><p>'
				. esc_html__( 'SiteCheck Monitor flagged a security issue on this site.', 'bsc-sitecheck-monitor' )
				. ' <a href="' . esc_url( admin_url( 'options-general.php?page=bsc-sitecheck-monitor' ) ) . '">'
				. esc_html__( 'Review now', 'bsc-sitecheck-monitor' ) . '</a></p></div>';
		}
	}
}

register_activation_hook( __FILE__, array( Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Plugin::class, 'deactivate' ) );
register_uninstall_hook( __FILE__, array( Plugin::class, 'uninstall' ) );

add_action( 'plugins_loaded', array( Plugin::class, 'instance' ) );
