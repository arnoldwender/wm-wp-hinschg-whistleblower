/**
 * WM HinSchG Whistleblower Portal - vanilla JS client, no external libraries.
 * Sends the report and follow-up messages as JSON to the plugin's REST routes; the server encrypts them.
 * Nothing is encrypted in the browser: until 2026-09-15 the buttons said "Ende-zu-Ende verschlüsselt".
 */
document.addEventListener('DOMContentLoaded', () => {
	const app = document.getElementById('wm-whistle-app');
	if (!app) return;

	const categories = wmHinSchGConfig.categories || {};
	const statuses = wmHinSchGConfig.statuses || {};
	// Unknown keys are shown as stored, never replaced by a label that sounds like "done".
	const categoryLabel = (key) => categories[key] || key || '';
	const statusLabel = (key) => statuses[key] || key || '';
	const SUBMIT_LABEL = 'Hinweis absenden';
	const LOAD_LABEL = 'Vorgang laden';
	const REPLY_LABEL = 'Nachricht senden';

	// Everything the server returns is rendered through innerHTML templates below; escape it.
	const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

	const tabSubmit = document.getElementById('tab-submit-btn');
	const tabStatus = document.getElementById('tab-status-btn');
	const panelSubmit = document.getElementById('panel-submit');
	const panelStatus = document.getElementById('panel-status');

	const submitForm = document.getElementById('wm-whistle-submit-form');
	const submitResult = document.getElementById('wm-submit-result');
	const statusForm = document.getElementById('wm-whistle-status-form');
	const statusResult = document.getElementById('wm-status-result');

	// Tab Switching
	if (tabSubmit && tabStatus) {
		tabSubmit.addEventListener('click', () => {
			tabSubmit.classList.add('active');
			tabSubmit.setAttribute('aria-selected', 'true');
			tabStatus.classList.remove('active');
			tabStatus.setAttribute('aria-selected', 'false');

			panelSubmit.style.display = 'block';
			panelStatus.style.display = 'none';
		});

		tabStatus.addEventListener('click', () => {
			tabStatus.classList.add('active');
			tabStatus.setAttribute('aria-selected', 'true');
			tabSubmit.classList.remove('active');
			tabSubmit.setAttribute('aria-selected', 'false');

			panelStatus.style.display = 'block';
			panelSubmit.style.display = 'none';
		});
	}

	// Submit Form Handling
	if (submitForm) {
		submitForm.addEventListener('submit', async (e) => {
			e.preventDefault();
			const submitBtn = submitForm.querySelector('button[type="submit"]');
			submitBtn.disabled = true;
			submitBtn.innerText = 'Wird gesendet …';

			const payload = {
				category: document.getElementById('wm-report-category').value,
				description: document.getElementById('wm-report-description').value,
			};

			try {
				const res = await fetch(wmHinSchGConfig.restUrl + 'report/submit', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-WP-Nonce': wmHinSchGConfig.nonce
					},
					body: JSON.stringify(payload)
				});

				const data = await res.json();
				if (data.success) {
					submitForm.style.display = 'none';
					submitResult.style.display = 'block';
					submitResult.innerHTML = `
						<div style="background: rgba(0, 242, 254, 0.05); border: 1px solid rgba(0, 242, 254, 0.3); border-radius: 8px; padding: 1.5rem;">
							<h3 style="color:#00f2fe; margin-top:0; display:flex; align-items:center; gap:0.5rem;">
								Hinweis eingegangen
							</h3>
							<p style="color:#cbd5e1; font-size: 0.92rem; line-height: 1.5;">
								Ihre Meldung ist gespeichert. Bitte notieren Sie Vorgangs-ID und Zugangsschlüssel: Der Schlüssel wird nur jetzt angezeigt, und ohne ihn können Sie den Vorgang nicht mehr abrufen.
							</p>
							<div style="background:#090d16; padding:1.25rem; border-radius:6px; margin:1.25rem 0; font-family:monospace; border: 1px solid rgba(255,255,255,0.1);">
								<div style="margin-bottom:0.75rem; color:#94a3b8; font-size: 0.9rem;">
									Vorgangs-ID: <strong style="color:#ffffff; font-size: 1.05rem;">${esc(data.case_public_id)}</strong>
								</div>
								<div style="color:#94a3b8; font-size: 0.9rem;">
									Zugangsschlüssel (Token): <strong id="wm-generated-token" style="color:#00f2fe; word-break:break-all;">${esc(data.access_token)}</strong>
								</div>
							</div>
							<div style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem;">
								<button type="button" id="wm-copy-token-btn" style="background:#1e293b; color:#fff; border:1px solid #475569; padding:0.5rem 1rem; border-radius:4px; cursor:pointer; font-size:0.85rem;">
									Schlüssel kopieren
								</button>
								<button type="button" onclick="window.print()" style="background:#00f2fe; color:#0b0f19; font-weight:600; border:none; padding:0.5rem 1rem; border-radius:4px; cursor:pointer; font-size:0.85rem;">
									Zugangsdaten drucken
								</button>
							</div>
							<div style="font-size:0.82rem; color:#f59e0b; background: rgba(245,158,11,0.1); padding: 0.75rem; border-radius: 4px; border-left: 3px solid #f59e0b;">
								<strong>Fristen nach § 17 HinSchG:</strong> Die Meldestelle bestätigt den Eingang spätestens nach sieben Tagen und gibt innerhalb von drei Monaten nach der Bestätigung eine Rückmeldung. Beides sehen Sie unter „Vorgang abrufen“.
							</div>
						</div>
					`;

					document.getElementById('wm-copy-token-btn')?.addEventListener('click', () => {
						navigator.clipboard.writeText(data.access_token);
						const btn = document.getElementById('wm-copy-token-btn');
						btn.innerText = 'Kopiert';
						setTimeout(() => { btn.innerText = 'Schlüssel kopieren'; }, 2500);
					});
				} else {
					alert('Fehler: ' + (data.message || 'Übertragung fehlgeschlagen.'));
					submitBtn.disabled = false;
					submitBtn.innerText = SUBMIT_LABEL;
				}
			} catch (err) {
				alert('Netzwerkfehler: ' + err.message);
				submitBtn.disabled = false;
				submitBtn.innerText = SUBMIT_LABEL;
			}
		});
	}

	// Status Form Handling & 2-Way Chat
	if (statusForm) {
		statusForm.addEventListener('submit', async (e) => {
			e.preventDefault();
			const caseId = document.getElementById('wm-case-id').value.trim();
			const token = document.getElementById('wm-access-token').value.trim();
			const loadBtn = statusForm.querySelector('button[type="submit"]');

			loadBtn.disabled = true;
			loadBtn.innerText = 'Wird geladen …';

			try {
				const res = await fetch(wmHinSchGConfig.restUrl + 'report/status', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-WP-Nonce': wmHinSchGConfig.nonce
					},
					body: JSON.stringify({ case_public_id: caseId, access_token: token })
				});

				const data = await res.json();
				loadBtn.disabled = false;
				loadBtn.innerText = LOAD_LABEL;

				if (data.success) {
					statusResult.style.display = 'block';
					let msgsHtml = '';
					if (data.messages && data.messages.length > 0) {
						msgsHtml = data.messages.map(m => `
							<div style="padding:0.85rem; margin:0.6rem 0; border-radius:6px; background:${m.sender_role === 'compliance_officer' ? 'rgba(0,242,254,0.1)' : 'rgba(255,255,255,0.04)'}; border: 1px solid ${m.sender_role === 'compliance_officer' ? 'rgba(0,242,254,0.2)' : 'rgba(255,255,255,0.08)'};">
								<div style="display:flex; justify-content:space-between; margin-bottom:0.35rem;">
									<strong style="color:${m.sender_role === 'compliance_officer' ? '#00f2fe' : '#38bdf8'}; font-size:0.78rem; text-transform:uppercase;">
										${m.sender_role === 'compliance_officer' ? 'Meldestelle' : 'Sie'}
									</strong>
									<span style="font-size:0.75rem; color:#64748b;">${esc(m.created_at)}</span>
								</div>
								<p style="margin:0; font-size:0.9rem; color:#e2e8f0; line-height:1.4;">${m.unreadable ? '<em>[Diese Nachricht kann mit dem aktuellen Schlüssel der Meldestelle nicht geöffnet werden.]</em>' : esc(m.message)}</p>
							</div>
						`).join('');
					} else {
						msgsHtml = '<p style="color:#94a3b8; font-size:0.88rem; padding: 0.5rem 0;">Noch keine Rückmeldungen der internen Meldestelle vorhanden.</p>';
					}

					statusResult.innerHTML = `
						<div style="background: #0b0f19; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 1.5rem;">
							<div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.75rem; margin-bottom: 1rem;">
								<div>
									<h3 style="color:#ffffff; margin:0; font-size:1.15rem;">Vorgang: <span style="color:#00f2fe;">${esc(data.case_public_id)}</span></h3>
									<span style="font-size:0.8rem; color:#94a3b8;">Kategorie: ${esc(categoryLabel(data.category))}</span>
								</div>
								<div>
									<span style="background: rgba(0,242,254,0.15); color: #00f2fe; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase;">
										Status: ${esc(statusLabel(data.status))}
									</span>
								</div>
							</div>

							<div style="margin: 1rem 0;">
								<h4 style="color:#94a3b8; font-size:0.85rem; text-transform:uppercase; margin-bottom:0.5rem;">Verlauf &amp; Korrespondenz</h4>
								<div id="wm-messages-container" style="max-height: 350px; overflow-y: auto;">${msgsHtml}</div>
							</div>

							<!-- 2-Way Follow-up Form -->
							<form id="wm-followup-form" style="margin-top: 1.25rem; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 1rem;">
								<label for="wm-followup-msg" style="display:block; font-size:0.85rem; color:#cbd5e1; margin-bottom:0.5rem; font-weight:500;">
									Nachricht an die Meldestelle
								</label>
								<textarea id="wm-followup-msg" rows="3" style="width:100%; background:#1e293b; color:#fff; border:1px solid #334155; border-radius:4px; padding:0.6rem; font-size:0.88rem; box-sizing:border-box;" placeholder="Ergänzungen oder Antworten auf Rückfragen" required></textarea>
								<button type="submit" style="margin-top:0.6rem; background:#00f2fe; color:#0b0f19; font-weight:600; border:none; padding:0.5rem 1.25rem; border-radius:4px; cursor:pointer; font-size:0.85rem;">
									Nachricht senden
								</button>
							</form>
						</div>
					`;

					// Attach 2-way reply handler
					document.getElementById('wm-followup-form')?.addEventListener('submit', async (ev) => {
						ev.preventDefault();
						const replyMsg = document.getElementById('wm-followup-msg').value.trim();
						if (!replyMsg) return;

						const replyBtn = ev.target.querySelector('button[type="submit"]');
						replyBtn.disabled = true;
						replyBtn.innerText = 'Sende...';

						try {
							const replyRes = await fetch(wmHinSchGConfig.restUrl + 'report/chat', {
								method: 'POST',
								headers: {
									'Content-Type': 'application/json',
									'X-WP-Nonce': wmHinSchGConfig.nonce
								},
								body: JSON.stringify({
									case_public_id: caseId,
									access_token: token,
									message: replyMsg
								})
							});
							const replyData = await replyRes.json();
							if (replyData.success) {
								document.getElementById('wm-followup-msg').value = '';
								statusForm.dispatchEvent(new Event('submit'));
							} else {
								alert('Fehler beim Senden: ' + (replyData.message || 'Fehler'));
								replyBtn.disabled = false;
								replyBtn.innerText = REPLY_LABEL;
							}
						} catch (rErr) {
							alert('Netzwerkfehler: ' + rErr.message);
							replyBtn.disabled = false;
							replyBtn.innerText = REPLY_LABEL;
						}
					});

				} else {
					alert('Fehler: ' + (data.message || 'Authentifizierung fehlgeschlagen.'));
				}
			} catch (err) {
				alert('Netzwerkfehler: ' + err.message);
				loadBtn.disabled = false;
				loadBtn.innerText = LOAD_LABEL;
			}
		});
	}
});
