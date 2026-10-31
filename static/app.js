function escapeHtml(value) { const node = document.createElement('span'); node.textContent = String(value ?? ''); return node.innerHTML; }
function focusScanner() { switchTab('scanner'); document.getElementById('targetUrl').focus({preventScroll:true}); document.getElementById('scanForm').scrollIntoView({behavior:'smooth',block:'center'}); }
async function apiFetch(url, options) { const response = await fetch(url, options); if (!response.ok) { let data = {}; try { data = await response.json(); } catch {} throw new Error(typeof data.detail === 'string' ? data.detail : 'Zahtjev nije uspio. Pokušajte ponovno.'); } return response; }

        let currentScanResult = null;

        function switchTab(tabId) {
            ['scanner', 'docs', 'profile', 'monitor'].forEach(id => {
                document.getElementById(`tab-${id}`).classList.add('hidden');
                const btn = document.getElementById(`tab-${id}-btn`);
                btn.setAttribute('aria-current', 'false');
                btn.className = "nav-btn px-4 py-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 flex items-center gap-2 relative";
            });
            document.getElementById(`tab-${tabId}`).classList.remove('hidden');
            const activeBtn = document.getElementById(`tab-${tabId}-btn`);
            activeBtn.setAttribute('aria-current', 'page');
            activeBtn.className = "nav-btn px-4 py-2 rounded-lg bg-slate-800 text-white flex items-center gap-2 relative";
        }

        async function handleScan(e) {
            e.preventDefault();
            const urlInput = document.getElementById('targetUrl').value;
            const submitBtn = document.getElementById('scanSubmitBtn');
            const loading = document.getElementById('scanLoading');
            const results = document.getElementById('scanResults');

            submitBtn.disabled = true;
            loading.classList.remove('hidden');
            results.classList.add('hidden');

            const formData = new FormData();
            formData.append('target_url', urlInput);

            try {
                const response = await apiFetch('/api/scan', { method: 'POST', body: formData });
                if (!response.ok) {
                    const err = await response.json();
                    alert(err.detail || 'Došlo je do greške prilikom skeniranja.');
                    return;
                }
                const data = await response.json();
                currentScanResult = data;
                renderScanResults(data);
            } catch (err) {
                alert('Greška pri povezivanju sa serverom: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                loading.classList.add('hidden');
            }
        }

        function renderScanResults(data) {
            const results = document.getElementById('scanResults');
            results.classList.remove('hidden');

            document.getElementById('resDomain').textContent = data.domain || data.url;
            document.getElementById('resTimestamp').textContent = 'Vrijeme revizije: ' + data.scan_timestamp;
            document.getElementById('scoreVal').textContent = data.compliance_score;

            const circle = document.getElementById('scoreCircle');
            const badge = document.getElementById('complianceBadge');
            if (data.compliance_score >= 80) {
                circle.className = "w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-bold text-white shadow-md bg-emerald-600";
                badge.className = "text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800";
                badge.textContent = "Visoka usklađenost";
            } else if (data.compliance_score >= 50) {
                circle.className = "w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-bold text-white shadow-md bg-amber-500";
                badge.className = "text-xs font-semibold px-2.5 py-1 rounded-full bg-amber-100 text-amber-800";
                badge.textContent = "Potrebna dorada";
            } else {
                circle.className = "w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-bold text-white shadow-md bg-red-600";
                badge.className = "text-xs font-semibold px-2.5 py-1 rounded-full bg-red-100 text-red-800";
                badge.textContent = "Prioritet za pregled";
            }

            document.getElementById('highRiskCount').textContent = data.summary?.high || 0;
            document.getElementById('medRiskCount').textContent = data.summary?.medium || 0;
            document.getElementById('lowRiskCount').textContent = data.summary?.low || 0;

            document.getElementById('downloadPdfBtn').href = data.pdf_download_url;

            document.getElementById('sslIcon').innerHTML = data.ssl_valid ? '<i class="fa-solid fa-circle-check text-emerald-500 text-lg"></i>' : '<i class="fa-solid fa-circle-xmark text-red-500 text-lg"></i>';
            document.getElementById('sslStatus').textContent = data.ssl_valid ? 'Valjan SSL/TLS' : 'Nevaljan ili Nedostaje';
            document.getElementById('sslDetails').textContent = data.ssl_details;

            document.getElementById('privacyIcon').innerHTML = data.privacy_policy_found ? '<i class="fa-solid fa-circle-check text-emerald-500 text-lg"></i>' : '<i class="fa-solid fa-circle-xmark text-red-500 text-lg"></i>';
            document.getElementById('privacyStatus').textContent = data.privacy_policy_found ? 'Pravila Postoje' : 'Dokument Nije Pronađen';
            document.getElementById('privacyDetails').textContent = data.privacy_policy_url || 'Nema poveznice na stranici';

            document.getElementById('cookieIcon').innerHTML = data.cookie_banner_found ? '<i class="fa-solid fa-circle-check text-emerald-500 text-lg"></i>' : '<i class="fa-solid fa-triangle-exclamation text-amber-500 text-lg"></i>';
            document.getElementById('cookieStatus').textContent = data.cookie_banner_found ? 'Cookie Banner Prisutan' : 'Banner Nije Detektiran';
            document.getElementById('cookieDetails').textContent = `${data.cookies_detected?.length || 0} kolačića učitano odmah`;

            document.getElementById('trackerIcon').innerHTML = (data.trackers_detected?.length > 0) ? '<i class="fa-solid fa-radar text-amber-500 text-lg"></i>' : '<i class="fa-solid fa-circle-check text-emerald-500 text-lg"></i>';
            document.getElementById('trackerStatus').textContent = `${data.trackers_detected?.length || 0} trackera detektirano`;
            document.getElementById('trackerDetails').textContent = data.trackers_detected?.join(', ') || 'Nema detektiranih analitičkih skripti';

            const risksList = document.getElementById('risksList');
            risksList.innerHTML = '';

            if (!data.risks || data.risks.length === 0) {
                risksList.innerHTML = '<p class="text-sm text-slate-500 italic">Nisu pronađeni prepoznati rizici.</p>';
            } else {
                data.risks.forEach(rawRisk => {
                    const r = Object.fromEntries(Object.entries(rawRisk).map(([key, value]) => [key, escapeHtml(value)]));
                    const isHigh = r.risk_level === 'Visok';
                    const isMed = r.risk_level === 'Srednji';
                    const cardBg = isHigh ? 'bg-red-50/50 border-red-200' : (isMed ? 'bg-amber-50/50 border-amber-200' : 'bg-blue-50/50 border-blue-200');
                    const badgeClass = isHigh ? 'bg-red-100 text-red-700 border-red-200' : (isMed ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-blue-100 text-blue-700 border-blue-200');

                    const itemHtml = `
                        <div class="border rounded-xl p-5 ${cardBg} transition">
                            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                                <h4 class="font-bold text-slate-900 text-base">${r.title}</h4>
                                <span class="text-xs font-bold px-2.5 py-1 rounded-full border ${badgeClass} w-fit">
                                    RIZIK: ${r.risk_level.toUpperCase()}
                                </span>
                            </div>
                            <div class="text-xs text-slate-500 mb-3 space-x-2">
                                <span class="font-medium text-slate-700">Kategorija:</span> <span>${r.category}</span>
                                <span>&bull;</span>
                                <span class="font-medium text-slate-700">GDPR Pravilo:</span> <span class="font-mono text-slate-700">${r.gdpr_article}</span>
                                <span>&bull;</span>
                                <span class="font-medium text-slate-700">Utjecaj:</span> <span>${r.impact}</span>
                                <span>&bull;</span>
                                <span class="font-medium text-slate-700">Vjerojatnost:</span> <span>${r.probability}</span>
                            </div>
                            <p class="text-xs text-slate-700 leading-relaxed mb-3">${r.description}</p>
                            <div class="bg-white/80 rounded-lg p-3 border border-slate-200/60 text-xs">
                                <span class="font-bold text-emerald-800"><i class="fa-solid fa-circle-check mr-1"></i> Preporuka za sanaciju:</span>
                                <span class="text-slate-800 ml-1">${r.recommendation}</span>
                            </div>
                        </div>
                    `;
                    risksList.insertAdjacentHTML('beforeend', itemHtml);
                });
            }
        }

        function transferScanToDocs() { switchTab('docs'); }

        let generatingDocument = false;
        async function requestDocGeneration(docType) {
            if (generatingDocument) return;
            generatingDocument = true;
            const buttons = document.querySelectorAll('[onclick^="requestDocGeneration"]');
            buttons.forEach(button => { button.disabled = true; button.setAttribute('aria-busy', 'true'); });
            const formData = new FormData();
            formData.append('doc_type', docType);
            if (currentScanResult && currentScanResult.scan_id) {
                formData.append('scan_id', currentScanResult.scan_id);
            }
            try {
                const response = await apiFetch('/api/generate-doc', { method: 'POST', body: formData });
                const data = await response.json();
                if (data.status === 'success') {
                    document.getElementById('docResultArea').classList.remove('hidden');
                    document.getElementById('docResultTitle').textContent = data.title;
                    document.getElementById('docPdfDownload').href = data.pdf_url;
                    document.getElementById('docMdDownload').href = data.md_url;
                    document.getElementById('docMarkdownPreview').textContent = data.markdown_content;
                    document.getElementById('docResultArea').scrollIntoView({ behavior: 'smooth' });
                }
            } catch (err) {
                alert('Greška pri generiranju dokumenta: ' + err.message);
            } finally {
                generatingDocument = false;
                buttons.forEach(button => { button.disabled = false; button.removeAttribute('aria-busy'); });
            }
        }

        async function saveProfile() {
            const profile = {
                name: document.getElementById('prof_name').value,
                id_number: document.getElementById('prof_id_number').value,
                address: document.getElementById('prof_address').value,
                website: document.getElementById('prof_website').value,
                email: document.getElementById('prof_email').value,
                phone: document.getElementById('prof_phone').value,
                dpo_name: document.getElementById('prof_dpo_name').value,
                dpo_email: document.getElementById('prof_dpo_email').value,
                data_purposes: document.getElementById('prof_purposes').value.split('\n').filter(x => x.trim()),
                third_parties: document.getElementById('prof_third_parties').value.split('\n').filter(x => x.trim()),
                data_retention_period: document.getElementById('prof_retention').value
            };
            try {
                const res = await apiFetch('/api/profile', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(profile)
                });
                const data = await res.json();
                alert(data.message || 'Podaci kompanije uspješno spremljeni!');
            } catch (err) {
                alert('Greška pri spremanju profila: ' + err.message);
            }
        }

        async function saveRegulatorySettings(e) {
            e.preventDefault();
            const settings = {
                check_frequency: document.getElementById('reg_frequency').value,
                notification_type: document.getElementById('reg_type').value,
                notification_email: document.getElementById('reg_email').value,
                is_active: document.getElementById('reg_active').checked
            };
            try {
                const res = await apiFetch('/api/regulatory/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
                const data = await res.json();
                alert(data.message || 'Postavke monitora uspješno spremljene!');
            } catch (err) {
                alert('Greška pri spremanju postavki: ' + err.message);
            }
        }

        async function checkRegulatoryUpdatesNow() {
            const btn = document.getElementById('checkUpdatesBtn');
            btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Provjeravam...';
            try {
                const res = await apiFetch('/api/regulatory/check-now', { method: 'POST' });
                location.reload();
            } catch (err) {
                alert('Greška pri provjeri ažuriranja: ' + err.message);
            } finally {
                btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Provjeri Sada';
            }
        }

        async function markAsRead(id, btnElem) {
            try {
                await apiFetch(`/api/regulatory/mark-read/${id}`, { method: 'POST' });
                const parentCard = btnElem.closest('.border');
                parentCard.classList.remove('bg-brand-50/40', 'border-brand-200');
                parentCard.classList.add('bg-white', 'border-slate-200', 'opacity-90');
                btnElem.remove();
                const badge = document.getElementById('unread-badge');
                let count = parseInt(badge.textContent) - 1;
                if (count <= 0) { badge.classList.add('hidden'); } else { badge.textContent = count; }
            } catch (err) { console.error(err); }
        }
