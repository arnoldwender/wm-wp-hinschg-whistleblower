<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Who may open a report.
 *
 * The plugin DECLARES a capability and checks it. It does not manage who holds it: roles are
 * WordPress's own mechanism and a role manager is a separate tool, so an access-control screen in
 * here would put the same decision in two places and let them disagree.
 *
 * Until 2026-09-19 the desk and the admin routes checked manage_options. That is not a permission
 * an install can take away from an administrator — it is most of what being an administrator means
 * — so on a site where the managing director also administers WordPress, they could read every
 * report, and no role manager could have stopped them. § 8 HinSchG makes the identity of the
 * reporting person and the content of a report confidential towards everyone not entrusted with the
 * channel, and "everyone" includes people inside the organisation with the keys to the website.
 *
 * The capability goes to the administrator role on install and on upgrade, so no install loses its
 * own desk when this lands. Taking it away from administrators — leaving it with the Meldestelle
 * role alone — is the point, and it is the install's decision, not the plugin's.
 *
 * @package WMCyber\HinSchG
 */
final class Capabilities {
	/** Read the decrypted report and its thread. */
	public const READ_CASES = 'wm_hinschg_read_cases';

	/** The role the plugin brings for the people running the channel. */
	public const ROLE = 'wm_hinschg_meldestelle';

	/** Bumped when the set of capabilities changes, so an update re-applies them. */
	public const VERSION_OPTION = 'wm_hinschg_capability_version';
	public const VERSION        = 1;

	/** May the current user open a report? */
	public static function may_read(): bool {
		return current_user_can( self::READ_CASES );
	}

	/**
	 * Create the role and give the capability to administrators.
	 *
	 * Idempotent: add_role() returns null when the role exists, and add_cap() on a role that has the
	 * capability is a no-op. Run from activation AND from the version check, because activation does
	 * not fire on an update — an install that already runs would otherwise be left with a desk
	 * nobody can open.
	 */
	public static function install(): void {
		add_role(
			self::ROLE,
			// Not translated on purpose: WordPress stores role names once, at creation, so a
			// translated name would freeze whatever language the site had at that moment.
			'Meldestelle (HinSchG)',
			[
				'read'            => true,
				self::READ_CASES  => true,
			]
		);

		$administrator = get_role( 'administrator' );
		if ( $administrator instanceof \WP_Role ) {
			$administrator->add_cap( self::READ_CASES );
		}

		update_option( self::VERSION_OPTION, self::VERSION );
	}

	/** Apply the capabilities on an update, where the activation hook does not fire. */
	public static function maybe_upgrade(): void {
		if ( (int) get_option( self::VERSION_OPTION, 0 ) >= self::VERSION ) {
			return;
		}
		self::install();
	}

	/** Role slugs that currently carry the capability. */
	public static function roles_with_access(): array {
		$roles = wp_roles();
		$out   = [];
		foreach ( array_keys( (array) $roles->roles ) as $slug ) {
			$role = get_role( (string) $slug );
			if ( $role instanceof \WP_Role && $role->has_cap( self::READ_CASES ) ) {
				$out[] = (string) $slug;
			}
		}
		return $out;
	}

	/**
	 * User ids that can open a report, whether through a role or a capability set on the user.
	 *
	 * This is what the "do not lock everyone out" guard counts, so it has to see both routes: a
	 * guard that only looked at roles would happily remove the last role while one user still held
	 * the capability directly, and — worse — would allow removing it from the last user.
	 */
	public static function holders(): array {
		$users = get_users( [ 'capability' => self::READ_CASES, 'fields' => 'ID' ] );
		return array_map( 'intval', (array) $users );
	}

	/**
	 * Give the capability to a role.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public static function grant_to_role( string $slug ): array {
		$role = get_role( $slug );
		if ( ! $role instanceof \WP_Role ) {
			/* translators: %s: role slug */
			return [ 'ok' => false, 'message' => sprintf( __( 'Die Rolle %s gibt es nicht.', 'wm-hinschg-whistleblower' ), $slug ) ];
		}
		if ( $role->has_cap( self::READ_CASES ) ) {
			/* translators: %s: role slug */
			return [ 'ok' => true, 'message' => sprintf( __( 'Die Rolle %s darf Meldungen bereits öffnen. Nichts zu tun.', 'wm-hinschg-whistleblower' ), $slug ) ];
		}
		$role->add_cap( self::READ_CASES );
		/* translators: %s: role slug */
		return [ 'ok' => true, 'message' => sprintf( __( 'Die Rolle %s darf Meldungen jetzt öffnen.', 'wm-hinschg-whistleblower' ), $slug ) ];
	}

	/**
	 * Take the capability away from a role — unless that would leave nobody able to open a report.
	 *
	 * The guard is not politeness. This plugin is the only way into the reports, the reports are
	 * encrypted, and § 17 HinSchG runs a seven-day clock on a channel nobody could open any more.
	 * The removal is applied and then MEASURED, rather than predicted: whether a user keeps the
	 * capability through another role is a question only WordPress can answer.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public static function revoke_from_role( string $slug ): array {
		$role = get_role( $slug );
		if ( ! $role instanceof \WP_Role ) {
			/* translators: %s: role slug */
			return [ 'ok' => false, 'message' => sprintf( __( 'Die Rolle %s gibt es nicht.', 'wm-hinschg-whistleblower' ), $slug ) ];
		}
		if ( ! $role->has_cap( self::READ_CASES ) ) {
			/* translators: %s: role slug */
			return [ 'ok' => true, 'message' => sprintf( __( 'Die Rolle %s darf Meldungen ohnehin nicht öffnen. Nichts zu tun.', 'wm-hinschg-whistleblower' ), $slug ) ];
		}

		$role->remove_cap( self::READ_CASES );

		if ( [] === self::holders() ) {
			$role->add_cap( self::READ_CASES );
			return [
				'ok'      => false,
				'message' => __( 'Abgebrochen: danach hätte niemand mehr Meldungen öffnen können. Die Meldestelle muss den Eingang innerhalb von sieben Tagen bestätigen (§ 17 HinSchG), und ohne diese Berechtigung kommt niemand an die Meldungen. Erst jemand anderen berechtigen, dann hier entziehen.', 'wm-hinschg-whistleblower' ),
			];
		}

		/* translators: %s: role slug */
		return [ 'ok' => true, 'message' => sprintf( __( 'Die Rolle %s darf Meldungen nicht mehr öffnen.', 'wm-hinschg-whistleblower' ), $slug ) ];
	}

	/**
	 * Give the capability to one user, independently of their role.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public static function grant_to_user( int $user_id ): array {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			/* translators: %d: user id */
			return [ 'ok' => false, 'message' => sprintf( __( 'Benutzer %d gibt es nicht.', 'wm-hinschg-whistleblower' ), $user_id ) ];
		}
		$user->add_cap( self::READ_CASES );
		/* translators: %s: user login */
		return [ 'ok' => true, 'message' => sprintf( __( '%s darf Meldungen jetzt öffnen.', 'wm-hinschg-whistleblower' ), $user->user_login ) ];
	}

	/**
	 * Take the capability away from one user, under the same guard as a role.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public static function revoke_from_user( int $user_id ): array {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			/* translators: %d: user id */
			return [ 'ok' => false, 'message' => sprintf( __( 'Benutzer %d gibt es nicht.', 'wm-hinschg-whistleblower' ), $user_id ) ];
		}

		$user->remove_cap( self::READ_CASES );

		if ( [] === self::holders() ) {
			$user->add_cap( self::READ_CASES );
			return [
				'ok'      => false,
				'message' => __( 'Abgebrochen: danach hätte niemand mehr Meldungen öffnen können. Erst jemand anderen berechtigen, dann hier entziehen.', 'wm-hinschg-whistleblower' ),
			];
		}

		/* translators: %s: user login */
		return [ 'ok' => true, 'message' => sprintf( __( '%s darf Meldungen nicht mehr öffnen.', 'wm-hinschg-whistleblower' ), $user->user_login ) ];
	}

	/** Uninstall: the role and the capability go with the plugin. */
	public static function remove(): void {
		foreach ( self::roles_with_access() as $slug ) {
			$role = get_role( $slug );
			if ( $role instanceof \WP_Role ) {
				$role->remove_cap( self::READ_CASES );
			}
		}
		remove_role( self::ROLE );
		delete_option( self::VERSION_OPTION );
	}
}
