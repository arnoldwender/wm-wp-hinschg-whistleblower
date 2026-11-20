/**
 * Local WebCrypto Zero-Knowledge Key Custody & Offline Case Decryption for WM HinSchG Desk.
 *
 * 1. Generates an RSA-OAEP-4096 (SHA-1 OAEP digest, matching OpenSSL OPENSSL_PKCS1_OAEP_PADDING)
 *    key pair strictly inside the administrator's browser via window.crypto.subtle.
 * 2. Downloads the PKCS#8 private key (.pem) directly from browser memory via Blob URL — zero
 *    bytes of private key ever touch PHP, HTTP POST, wp_options, or transients.
 * 3. Populates ONLY the SPKI public key PEM into the form field for server-side sealing.
 * 4. When opening a case in offline-custody mode (after PHP has verified wm_hinschg_read_cases and
 *    recorded CASE_OPENED_BY_COMPLIANCE_OFFICER in the audit chain), unwraps the RSA-OAEP AES-256
 *    key and decrypts AES-256-GCM payloads locally in the browser DOM.
 */
(function () {
	'use strict';

	const cfg = window.wmHinschgZkConfig || {};
	const i18n = cfg.i18n || {};

	function arrayBufferToBase64(buffer) {
		const bytes = new Uint8Array(buffer);
		let binary = '';
		for (let i = 0; i < bytes.byteLength; i++) {
			binary += String.fromCharCode(bytes[i]);
		}
		return window.btoa(binary);
	}

	function base64ToUint8Array(b64) {
		const clean = String(b64 || '').replace(/\s+/g, '');
		const binary = window.atob(clean);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) {
			bytes[i] = binary.charCodeAt(i);
		}
		return bytes;
	}

	function formatPem(b64, label) {
		const lines = b64.match(/.{1,64}/g) || [];
		return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----\n';
	}

	function parsePkcs8Pem(pemText) {
		const pemRe = new RegExp('-----BEGIN ' + 'PRIVATE KEY-----([\\s\\S]+?)-----END ' + 'PRIVATE KEY-----');
		const match = String(pemText || '').match(pemRe);
		if (!match) {
			throw new Error(i18n.invalidPem || 'Kein gültiger PKCS#8-Privatschlüssel (BEGIN PRIVATE KEY) erkannt.');
		}
		return base64ToUint8Array(match[1]);
	}

	async function unwrapAndDecryptEnvelope(rsaPrivateKey, env) {
		const iv = base64ToUint8Array(env.iv);
		const ciphertext = base64ToUint8Array(env.payload);
		const tag = base64ToUint8Array(env.tag);

		let aesRaw;
		try {
			aesRaw = await window.crypto.subtle.decrypt(
				{ name: 'RSA-OAEP' },
				rsaPrivateKey,
				base64ToUint8Array(env.key)
			);
		} catch (primaryErr) {
			if (!env.recovery_key) {
				throw primaryErr;
			}
			aesRaw = await window.crypto.subtle.decrypt(
				{ name: 'RSA-OAEP' },
				rsaPrivateKey,
				base64ToUint8Array(env.recovery_key)
			);
		}
		const aesKey = await window.crypto.subtle.importKey(
			'raw',
			aesRaw,
			{ name: 'AES-GCM' },
			false,
			['decrypt']
		);

		const combined = new Uint8Array(ciphertext.length + tag.length);
		combined.set(ciphertext, 0);
		combined.set(tag, ciphertext.length);

		const plainBuffer = await window.crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: iv, tagLength: 128 },
			aesKey,
			combined
		);
		const jsonText = new TextDecoder('utf-8').decode(plainBuffer);
		return JSON.parse(jsonText);
	}

	function bindKeyGenerator(opts) {
		const genBtn = document.getElementById(opts.btnId);
		const pubField = document.getElementById(opts.pubFieldId);
		const statusNode = document.getElementById(opts.statusId);
		const submitBtn = document.getElementById(opts.submitBtnId);
		if (!genBtn || !pubField) {
			return;
		}

		genBtn.addEventListener('click', async function () {
			if (!window.crypto || !window.crypto.subtle) {
				if (statusNode) {
					statusNode.textContent = i18n.noWebCrypto || 'WebCrypto ist nur über HTTPS oder localhost verfügbar.';
				}
				return;
			}
			genBtn.disabled = true;
			if (statusNode) {
				statusNode.textContent = i18n.generating || 'RSA-4096-Schlüsselpaar wird lokal im Browser berechnet …';
			}
			try {
				const keyPair = await window.crypto.subtle.generateKey(
					{
						name: 'RSA-OAEP',
						modulusLength: 4096,
						publicExponent: new Uint8Array([1, 0, 1]),
						hash: 'SHA-1',
					},
					true,
					['encrypt', 'decrypt']
				);

				const spki = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
				const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

				const publicPem = formatPem(arrayBufferToBase64(spki), 'PUBLIC KEY');
				const privatePem = formatPem(arrayBufferToBase64(pkcs8), 'PRIVATE KEY');

				const blob = new Blob([privatePem], { type: 'application/x-pem-file' });
				const url = URL.createObjectURL(blob);
				const link = document.createElement('a');
				link.href = url;
				link.download = opts.filename;
				document.body.appendChild(link);
				link.click();
				document.body.removeChild(link);
				window.setTimeout(function () {
					URL.revokeObjectURL(url);
				}, 1000);

				pubField.value = publicPem;
				if (submitBtn) {
					submitBtn.disabled = false;
				}
				if (statusNode) {
					statusNode.textContent = i18n.generated || 'Privater Schlüssel lokal heruntergeladen. Prüfen und speichern Sie nun den öffentlichen Schlüssel.';
				}
			} catch (err) {
				if (statusNode) {
					statusNode.textContent = (i18n.errorPrefix || 'Fehler: ') + (err && err.message ? err.message : String(err));
				}
			} finally {
				genBtn.disabled = false;
			}
		});
	}

	function initGenerators() {
		bindKeyGenerator({
			btnId: 'wm-hinschg-zk-generate-btn',
			pubFieldId: 'wm-hinschg-zk-public-pem',
			statusId: 'wm-hinschg-zk-status',
			submitBtnId: 'wm-hinschg-zk-save-btn',
			filename: 'hinschg-meldestelle-private-key.pem',
		});
		bindKeyGenerator({
			btnId: 'wm-hinschg-zk-generate-recovery-btn',
			pubFieldId: 'wm-hinschg-zk-recovery-public-pem',
			statusId: 'wm-hinschg-zk-recovery-status',
			submitBtnId: 'wm-hinschg-zk-recovery-save-btn',
			filename: 'hinschg-meldestelle-recovery-private-key.pem',
		});
	}

	function initCaseActions() {
		const panel = document.getElementById('wm-hinschg-case-actions');
		if (!panel) {
			return;
		}
		const caseId = panel.getAttribute('data-case-id') || '';
		const ackBtn = document.getElementById('wm-hinschg-ack-btn');
		const replyText = document.getElementById('wm-hinschg-reply-text');
		const replyFinal = document.getElementById('wm-hinschg-reply-final');
		const replyBtn = document.getElementById('wm-hinschg-reply-btn');
		const statusNode = document.getElementById('wm-hinschg-case-action-status');
		const restBase = String(cfg.restUrl || '').replace(/\/+$/, '');
		const restNonce = String(cfg.restNonce || '');

		function setActionStatus(text, isError) {
			if (!statusNode) {
				return;
			}
			statusNode.textContent = text;
			statusNode.dataset.state = isError ? 'error' : 'ok';
		}

		async function postJson(endpoint, body) {
			const res = await fetch(restBase + endpoint, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': restNonce,
				},
				body: JSON.stringify(body),
			});
			let data = {};
			try {
				data = await res.json();
			} catch (parseErr) {
				data = {};
			}
			if (!res.ok || data.success === false) {
				const retryAfter = res.headers ? res.headers.get('Retry-After') : null;
				const fallback = retryAfter
					? (i18n.retryAfter || 'Audit-Protokoll vorübergehend belegt. Bitte in 2 Sekunden erneut versuchen.')
					: ('HTTP ' + res.status);
				throw new Error(data.message || fallback);
			}
			return data;
		}

		if (ackBtn) {
			ackBtn.addEventListener('click', async function () {
				if (!caseId || !restBase) {
					return;
				}
				ackBtn.disabled = true;
				setActionStatus(i18n.ackSending || 'Eingangsbestätigung wird gespeichert …', false);
				try {
					const data = await postJson('/admin/ack', { case_public_id: caseId });
					panel.setAttribute('data-ack-sent', '1');
					setActionStatus(data.message || i18n.ackDone || 'Eingangsbestätigung gespeichert. Ansicht wird aktualisiert …', false);
					window.setTimeout(function () {
						window.location.reload();
					}, 500);
				} catch (err) {
					if (panel.getAttribute('data-ack-sent') !== '1') {
						ackBtn.disabled = false;
					}
					setActionStatus((i18n.errorPrefix || 'Fehler: ') + (err && err.message ? err.message : String(err)), true);
				}
			});
		}

		if (replyBtn) {
			replyBtn.addEventListener('click', async function () {
				if (!caseId || !restBase) {
					return;
				}
				const message = replyText ? replyText.value.trim() : '';
				if (!message) {
					setActionStatus(i18n.replyEmpty || 'Bitte geben Sie einen Nachrichtentext ein.', true);
					return;
				}
				replyBtn.disabled = true;
				setActionStatus(i18n.replySending || 'Antwort wird verschlüsselt gespeichert …', false);
				try {
					const data = await postJson('/admin/reply', {
						case_public_id: caseId,
						message: message,
						is_final_feedback: Boolean(replyFinal && replyFinal.checked),
					});
					if (replyText) {
						replyText.value = '';
					}
					if (replyFinal) {
						replyFinal.checked = false;
					}
					setActionStatus(data.message || i18n.replyDone || 'Antwort verschlüsselt gespeichert. Ansicht wird aktualisiert …', false);
					window.setTimeout(function () {
						window.location.reload();
					}, 500);
				} catch (err) {
					replyBtn.disabled = false;
					setActionStatus((i18n.errorPrefix || 'Fehler: ') + (err && err.message ? err.message : String(err)), true);
				}
			});
		}
	}

	function initOfflineDecryptor() {
		const box = document.querySelector('[data-wm-hinschg-offline-envelope]');
		const fileInput = document.getElementById('wm-hinschg-zk-keyfile');
		const statusNode = document.getElementById('wm-hinschg-zk-decrypt-status');
		const outputNode = document.getElementById('wm-hinschg-zk-decrypt-output');
		if (!box || !fileInput || !outputNode) {
			return;
		}

		fileInput.addEventListener('change', async function () {
			const file = fileInput.files && fileInput.files[0];
			if (!file) {
				return;
			}
			outputNode.textContent = '';
			if (statusNode) {
				statusNode.textContent = i18n.decrypting || 'Lokale Entschlüsselung im Browser läuft …';
			}
			try {
				const pemText = await file.text();
				const pkcs8Bytes = parsePkcs8Pem(pemText);
				const rsaPriv = await window.crypto.subtle.importKey(
					'pkcs8',
					pkcs8Bytes,
					{ name: 'RSA-OAEP', hash: 'SHA-1' },
					false,
					['decrypt']
				);

				const bundle = JSON.parse(box.getAttribute('data-wm-hinschg-offline-envelope') || '{}');
				const reportPlain = await unwrapAndDecryptEnvelope(rsaPriv, bundle.report);

				const descHeading = document.createElement('h3');
				descHeading.textContent = i18n.reportHeading || 'Meldungstext (lokal im Browser entschlüsselt)';
				const descPara = document.createElement('p');
				descPara.textContent = String(reportPlain.description || '');
				outputNode.appendChild(descHeading);
				outputNode.appendChild(descPara);

				if (Array.isArray(bundle.messages) && bundle.messages.length > 0) {
					const threadHeading = document.createElement('h3');
					threadHeading.textContent = i18n.threadHeading || 'Verlauf';
					outputNode.appendChild(threadHeading);

					for (const item of bundle.messages) {
						const row = document.createElement('p');
						const role = document.createElement('strong');
						role.textContent = item.sender_role === 'compliance_officer'
							? (i18n.officerRole || 'Meldestelle')
							: (i18n.reporterRole || 'Hinweisgebende Person');
						row.appendChild(role);
						row.appendChild(document.createTextNode(' (' + String(item.created_at || '').slice(0, 16) + '): '));

						if (item.envelope && item.envelope.payload) {
							const msgPlain = await unwrapAndDecryptEnvelope(rsaPriv, item.envelope);
							const body = document.createElement('span');
							body.textContent = String(msgPlain.message || '');
							row.appendChild(body);
						} else {
							const legacy = document.createElement('span');
							legacy.textContent = String(item.plain_legacy || '');
							row.appendChild(legacy);
						}
						outputNode.appendChild(row);
					}
				}

				if (statusNode) {
					statusNode.textContent = i18n.decryptedOk || 'Meldung lokal im Browser entschlüsselt. Der private Schlüssel hat den Browser nicht verlassen.';
				}
			} catch (err) {
				if (statusNode) {
					statusNode.textContent = (i18n.decryptFailed || 'Entschlüsselung fehlgeschlagen: ') + (err && err.message ? err.message : String(err));
				}
			}
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function () {
			initGenerators();
			initOfflineDecryptor();
			initCaseActions();
		});
	} else {
		initGenerators();
		initOfflineDecryptor();
		initCaseActions();
	}
})();
