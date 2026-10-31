/**
 * GDPR Sentinel - Klijentska aplikacijska logika (static/app.js)
 * Upravlja prikazom tablice Pre-Consent kolačića, interaktivnim stablom otkrivenih
 * podstranica, ROPA evidencijom i ugrađenim PDF preglednikom.
 */

(function () {
    "use strict";

    const state = {
        scans: [],
        activeScan: null,
        cookieFilter: "all",
        subpageSearch: "",
    };

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function showToast(message, isError = false) {
        const toast = document.getElementById("status-toast");
        const inner = document.getElementById("status-toast-inner");
        const text = document.getElementById("status-toast-text");
        if (!toast || !inner || !text) return;

        text.textContent = message;
        toast.classList.remove("hidden");
        if (isError) {
            inner.className = "px-4 py-2.5 rounded-xl border border-rose-500/40 bg-rose-500/15 text-rose-200 text-xs flex items-center justify-between";
        } else {
            inner.className = "px-4 py-2.5 rounded-xl border border-sky-500/40 bg-sky-500/10 text-sky-200 text-xs flex items-center justify-between";
        }
    }

    function refreshIcons() {
        if (window.lucide && typeof window.lucide.createIcons === "function") {
            window.lucide.createIcons();
        }
    }

    function getRiskBadgeStyle(riskLevel) {
        const level = String(riskLevel || "MEDIUM").toUpperCase();
        if (level === "LOW") {
            return "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
        }
        if (level === "MEDIUM") {
            return "bg-amber-500/15 text-amber-300 border border-amber-500/30";
        }
        if (level === "HIGH") {
            return "bg-orange-500/15 text-orange-300 border border-orange-500/30";
        }
        return "bg-rose-500/20 text-rose-300 border border-rose-500/40";
    }

    // ------------------------------------------------------------------------
    // BOČNA LISTA UČITANIH DOMENA IZ data/scans/*.json
    // ------------------------------------------------------------------------

    function renderSidebarDomains() {
        const listEl = document.getElementById("domains-list");
        const countEl = document.getElementById("loaded-domains-count");
        const filterInput = document.getElementById("sidebar-domain-filter");
        if (!listEl) return;

        const query = (filterInput ? filterInput.value : "").trim().toLowerCase();
        const filtered = state.scans.filter((s) => {
            const dom = String(s.domain || "").toLowerCase();
            const sid = String(s.id || s.scan_id || "").toLowerCase();
            return !query || dom.includes(query) || sid.includes(query);
        });

        if (countEl) countEl.textContent = String(state.scans.length);

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div class="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                    Nema pronađenih domena. Unesite domenu u gornju traku za početak.
                </div>`;
            return;
        }

        listEl.innerHTML = filtered
            .map((scan) => {
                const isSelected = state.activeScan && state.activeScan.id === scan.id;
                const score = scan.score ?? 0;
                const pagesCount = scan.pages_audit?.total_pages_crawled ?? scan.pages_scanned_count ?? 1;
                const preViolations = scan.cookie_audit?.preconsent_violations_count ?? 0;

                return `
                <button
                    type="button"
                    data-scan-id="${escapeHtml(scan.id)}"
                    class="domain-item-btn w-full text-left p-3 rounded-xl border transition cursor-pointer ${
                        isSelected
                            ? "bg-sky-500/15 border-sky-400/50 shadow-md shadow-sky-500/10"
                            : "bg-slate-900/70 hover:bg-slate-800/80 border-slate-800/90"
                    }"
                >
                    <div class="flex items-center justify-between gap-2">
                        <span class="font-semibold text-xs text-white truncate">${escapeHtml(scan.domain)}</span>
                        <span class="text-[11px] font-mono font-bold px-2 py-0.5 rounded ${getRiskBadgeStyle(scan.risk_level)}">
                            ${score}/100
                        </span>
                    </div>
                    <div class="flex items-center justify-between text-[11px] text-slate-400 mt-1.5">
                        <span>Podstranica: <strong class="text-sky-300">${pagesCount}</strong></span>
                        <span>Pre-Consent: <strong class="${preViolations > 0 ? "text-rose-400" : "text-emerald-400"}">${preViolations}</strong></span>
                        <span class="font-mono text-[10px] text-slate-500">#${escapeHtml(scan.id)}</span>
                    </div>
                </button>`;
            })
            .join("");

        listEl.querySelectorAll(".domain-item-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
                const targetId = btn.getAttribute("data-scan-id");
                const found = state.scans.find((s) => String(s.id) === String(targetId));
                if (found) {
                    setActiveScan(found);
                }
            });
        });
    }

    // ------------------------------------------------------------------------
    // 1. PRIKAZ INTERAKTIVNE TABLICE PRE-CONSENT KOLAČIĆA
    // ------------------------------------------------------------------------

    function renderCookiesTable(scan) {
        const tbody = document.getElementById("cookies-table-body");
        const tabBadge = document.getElementById("badge-tab-cookies");
        if (!tbody) return;

        const cookieAudit = scan.cookie_audit || {
            total_cookies: 0,
            preconsent_violations_count: 0,
            all_cookies_table: [],
        };
        const allRows = cookieAudit.all_cookies_table || [];

        if (tabBadge) {
            tabBadge.textContent = `${cookieAudit.preconsent_violations_count}/${cookieAudit.total_cookies}`;
        }

        const filteredRows = allRows.filter((c) => {
            if (state.cookieFilter === "violations") return Boolean(c.is_violation);
            if (state.cookieFilter === "Nužni") return c.category === "Nužni";
            if (state.cookieFilter === "non-essential") return c.category !== "Nužni";
            return true;
        });

        if (filteredRows.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-8 px-4 text-center text-slate-400">
                        Za odabrani filtar nema pronađenih kolačića na domeni <strong>${escapeHtml(scan.domain)}</strong>.
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = filteredRows
            .map((c) => {
                const statusBadge = c.is_violation
                    ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold text-[11px]">
                           PREKRŠAJ (Prije privole)
                       </span>`
                    : `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-medium text-[11px]">
                           ${escapeHtml(c.status_label)}
                       </span>`;

                const secBadge = c.secure
                    ? `<span class="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-mono text-[10px]">Secure:DA</span>`
                    : `<span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 font-mono text-[10px]">Secure:NE</span>`;

                const httpBadge = c.http_only
                    ? `<span class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 font-mono text-[10px]">HttpOnly:DA</span>`
                    : `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">HttpOnly:NE</span>`;

                const sameSiteBadge = `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">SameSite:${escapeHtml(c.same_site)}</span>`;

                return `
                <tr class="hover:bg-slate-900/70 transition ${c.is_violation ? "bg-rose-950/15" : ""}">
                    <td class="py-3 px-3.5">
                        <div class="font-mono font-bold text-white">${escapeHtml(c.name)}</div>
                        <div class="text-[11px] text-slate-400 mt-0.5">${escapeHtml(c.description)}</div>
                    </td>
                    <td class="py-3 px-3.5">
                        <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-medium">${escapeHtml(c.category)}</span>
                    </td>
                    <td class="py-3 px-3.5">${statusBadge}</td>
                    <td class="py-3 px-3.5 space-x-1">${secBadge} ${httpBadge} ${sameSiteBadge}</td>
                    <td class="py-3 px-3.5 font-mono text-[11px] text-slate-300">${escapeHtml(c.expires)}</td>
                    <td class="py-3 px-3.5">
                        <a href="${escapeHtml(c.found_on_url)}" target="_blank" rel="noopener noreferrer" class="text-sky-400 hover:underline font-mono text-[11px] break-all">
                            ${escapeHtml(c.found_on_url)}
                        </a>
                    </td>
                </tr>`;
            })
            .join("");
    }

    // ------------------------------------------------------------------------
    // 2. PRIKAZ STABLA I TABLICE OTKRIVENIH PODSTRANICA
    // ------------------------------------------------------------------------

    function renderSubpagesTreeAndTable(scan) {
        const legalCardsEl = document.getElementById("legal-pages-cards");
        const treeContainer = document.getElementById("subpages-tree-container");
        const tbody = document.getElementById("subpages-table-body");
        const tabBadge = document.getElementById("badge-tab-subpages");

        const pagesAudit = scan.pages_audit || {
            total_pages_crawled: 0,
            pages_table: [],
            legal_pages_coverage: {},
        };
        const allPages = pagesAudit.pages_table || [];
        if (tabBadge) tabBadge.textContent = String(allPages.length);

        // 2.1 Kartice pravne pokrivenosti
        if (legalCardsEl) {
            const coverage = pagesAudit.legal_pages_coverage || {};
            legalCardsEl.innerHTML = Object.entries(coverage)
                .map(([roleName, foundUrl]) => {
                    const isFound = foundUrl && foundUrl !== "NIJE PRONAĐENO";
                    return `
                    <div class="p-3.5 rounded-xl border ${
                        isFound
                            ? "bg-emerald-950/20 border-emerald-500/30"
                            : "bg-rose-950/20 border-rose-500/30"
                    }">
                        <div class="flex items-center justify-between text-xs font-semibold ${
                            isFound ? "text-emerald-300" : "text-rose-300"
                        }">
                            <span>${escapeHtml(roleName)}</span>
                            <span>${isFound ? "PRONAĐENO ✓" : "NEDOSTAJE ✕"}</span>
                        </div>
                        <div class="mt-1.5 text-[11px] font-mono truncate ${
                            isFound ? "text-sky-300" : "text-slate-500"
                        }">
                            ${
                                isFound
                                    ? `<a href="${escapeHtml(foundUrl)}" target="_blank" rel="noopener noreferrer" class="hover:underline">${escapeHtml(foundUrl)}</a>`
                                    : "Nije otkriveno na domeni"
                            }
                        </div>
                    </div>`;
                })
                .join("");
        }

        // Filtriranje prema tražilici podstranica
        const q = state.subpageSearch.trim().toLowerCase();
        const filteredPages = allPages.filter((p) => {
            if (!q) return true;
            return (
                String(p.url || "").toLowerCase().includes(q) ||
                String(p.legal_role || "").toLowerCase().includes(q) ||
                String(p.title || "").toLowerCase().includes(q)
            );
        });

        // 2.2 Vizualno stablo grupirano po dubini (Depth 0, Depth 1, Depth 2+)
        if (treeContainer) {
            const byDepth = {};
            filteredPages.forEach((p) => {
                const d = Number(p.depth || 0);
                if (!byDepth[d]) byDepth[d] = [];
                byDepth[d].push(p);
            });

            const depths = Object.keys(byDepth)
                .map(Number)
                .sort((a, b) => a - b);

            if (depths.length === 0) {
                treeContainer.innerHTML = `<div class="text-xs text-slate-500 py-4">Nema podstranica koje odgovaraju pretrazi.</div>`;
            } else {
                treeContainer.innerHTML = depths
                    .map((depthLevel) => {
                        const groupPages = byDepth[depthLevel];
                        const levelLabel =
                            depthLevel === 0
                                ? "Dubina 0 — Korijenska (Root) stranica"
                                : `Dubina ${depthLevel} — Otkrivene interne rute (${groupPages.length})`;

                        const nodesHtml = groupPages
                            .map((node) => {
                                const isLegal = node.legal_role && !["Javna podstranica", "Početna stranica (Root)"].includes(node.legal_role);
                                return `
                                <div class="tree-node flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-xl bg-slate-900/90 border ${
                                    isLegal ? "border-sky-500/40" : "border-slate-800"
                                }">
                                    <div class="flex items-center gap-2.5 min-w-0">
                                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                            node.status_code < 400
                                                ? "bg-emerald-500/15 text-emerald-300"
                                                : "bg-rose-500/20 text-rose-300"
                                        }">
                                            HTTP ${escapeHtml(node.status_code)}
                                        </span>
                                        <a href="${escapeHtml(node.url)}" target="_blank" rel="noopener noreferrer" class="font-mono text-xs text-sky-300 hover:underline truncate">
                                            ${escapeHtml(node.url)}
                                        </a>
                                        <span class="text-[11px] text-slate-400 truncate hidden sm:inline">
                                            — ${escapeHtml(node.title)}
                                        </span>
                                    </div>
                                    <div class="flex items-center gap-2 text-[11px]">
                                        <span class="px-2 py-0.5 rounded-md ${
                                            isLegal
                                                ? "bg-sky-500/20 text-sky-200 border border-sky-500/30 font-semibold"
                                                : "bg-slate-800 text-slate-300"
                                        }">
                                            ${escapeHtml(node.legal_role)}
                                        </span>
                                        <span class="px-2 py-0.5 rounded bg-slate-800/90 text-slate-300 font-mono">
                                            Kolačići: ${escapeHtml(node.cookies_set)}
                                        </span>
                                        <span class="px-2 py-0.5 rounded bg-slate-800/90 text-slate-300 font-mono">
                                            Obrasci: ${escapeHtml(node.forms_count)}
                                        </span>
                                    </div>
                                </div>`;
                            })
                            .join("");

                        return `
                        <div class="tree-depth-group pl-4 border-l-2 border-sky-500/40 space-y-2">
                            <div class="text-xs font-semibold text-sky-300 uppercase tracking-wider">
                                ${escapeHtml(levelLabel)}
                            </div>
                            <div class="grid grid-cols-1 gap-2">
                                ${nodesHtml}
                            </div>
                        </div>`;
                    })
                    .join("");
            }
        }

        // 2.3 Strukturirana tablica podstranica
        if (tbody) {
            tbody.innerHTML = filteredPages
                .map(
                    (p) => `
                <tr class="hover:bg-slate-900/70 transition">
                    <td class="py-2.5 px-3 font-mono text-slate-400">${escapeHtml(p.index)}</td>
                    <td class="py-2.5 px-3.5">
                        <a href="${escapeHtml(p.url)}" target="_blank" rel="noopener noreferrer" class="font-mono text-sky-400 hover:underline break-all">
                            ${escapeHtml(p.url)}
                        </a>
                        <div class="text-[11px] text-slate-400">${escapeHtml(p.title)}</div>
                    </td>
                    <td class="py-2.5 px-3">
                        <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-medium">${escapeHtml(p.legal_role)}</span>
                    </td>
                    <td class="py-2.5 px-3 font-mono text-emerald-300">${escapeHtml(p.status_code)}</td>
                    <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(p.depth)}</td>
                    <td class="py-2.5 px-3 font-mono text-slate-200">${escapeHtml(p.cookies_set)}</td>
                    <td class="py-2.5 px-3 font-mono text-slate-200">${escapeHtml(p.forms_count)}</td>
                </tr>`
                )
                .join("");
        }
    }

    // ------------------------------------------------------------------------
    // 3. PRIKAZ ROPA TABLICE I UTVRĐENIH NESUKLADNOSTI
    // ------------------------------------------------------------------------

    function renderRopaAndIssues(scan) {
        const ropaBody = document.getElementById("ropa-table-body");
        const issuesContainer = document.getElementById("issues-list-container");
        const tabBadge = document.getElementById("badge-tab-ropa");

        const ropaEntries = scan.ropa_entries || [];
        const issues = scan.issues || [];
        if (tabBadge) tabBadge.textContent = String(ropaEntries.length);

        if (ropaBody) {
            ropaBody.innerHTML = ropaEntries
                .map(
                    (r) => `
                <tr class="hover:bg-slate-900/70 transition">
                    <td class="py-3 px-3 font-mono font-bold text-sky-300">${escapeHtml(r.activity_id)}</td>
                    <td class="py-3 px-3.5">
                        <div class="font-semibold text-white">${escapeHtml(r.name)}</div>
                        <div class="text-[11px] text-slate-400 mt-0.5">${escapeHtml(r.purpose)}</div>
                    </td>
                    <td class="py-3 px-3.5 text-slate-300">${escapeHtml(r.legal_basis)}</td>
                    <td class="py-3 px-3.5 text-slate-300">${escapeHtml(r.data_categories)}</td>
                    <td class="py-3 px-3.5">
                        <div class="text-slate-200">${escapeHtml(r.recipients)}</div>
                        <div class="text-[11px] text-amber-300 mt-0.5">${escapeHtml(r.third_country_transfer)}</div>
                    </td>
                    <td class="py-3 px-3.5 font-mono text-[11px] text-slate-400">${escapeHtml(r.source_pages)}</td>
                </tr>`
                )
                .join("");
        }

        if (issuesContainer) {
            if (issues.length === 0) {
                issuesContainer.innerHTML = `
                    <div class="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-xs">
                        Nisu utvrđene kritične GDPR nesukladnosti na ovoj domeni.
                    </div>`;
            } else {
                issuesContainer.innerHTML = issues
                    .map(
                        (iss) => `
                    <div class="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div>
                            <div class="flex items-center gap-2">
                                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded ${getRiskBadgeStyle(iss.severity)}">
                                    ${escapeHtml(iss.severity)}
                                </span>
                                <span class="font-semibold text-xs text-white">${escapeHtml(iss.title)}</span>
                            </div>
                            <p class="text-xs text-slate-400 mt-1">${escapeHtml(iss.description)}</p>
                        </div>
                        <div class="text-[11px] font-mono text-sky-300 shrink-0">
                            ${escapeHtml(iss.gdpr_article)}
                        </div>
                    </div>`
                    )
                    .join("");
            }
        }
    }

    // ------------------------------------------------------------------------
    // POSTAVLJANJE AKTIVNOG SKENA NA NADZORNOJ PLOČI
    // ------------------------------------------------------------------------

    function setActiveScan(scan) {
        state.activeScan = scan;
        renderSidebarDomains();

        document.getElementById("active-domain-title").textContent = scan.domain || "Nepoznata domena";
        const riskBadge = document.getElementById("active-risk-badge");
        riskBadge.textContent = `${scan.risk_label_hr || scan.risk_level} (${scan.score}/100)`;
        riskBadge.className = `text-xs font-mono uppercase px-2.5 py-1 rounded-full ${getRiskBadgeStyle(scan.risk_level)}`;

        document.getElementById("active-scan-meta").textContent =
            `ID skena: #${scan.id} | URL: ${scan.url || "https://" + scan.domain} | Skenirano: ${scan.scan_date || scan.timestamp || "upravo"}`;

        // KPI kartice
        document.getElementById("kpi-score").textContent = `${scan.score ?? 0} / 100`;
        document.getElementById("kpi-ssl-status").textContent =
            `TLS/SSL: ${scan.https ? "Valjan ✓" : "Neispravan ✕"} | HTTP->HTTPS: ${scan.http_to_https_redirect ? "DA" : "NE"}`;

        const preCount = scan.cookie_audit?.preconsent_violations_count ?? 0;
        const totCookies = scan.cookie_audit?.total_cookies ?? scan.cookies_count ?? 0;
        document.getElementById("kpi-preconsent-cookies").textContent = String(preCount);
        document.getElementById("kpi-total-cookies").textContent = `Ukupno detektiranih kolačića: ${totCookies}`;

        const pagesCount = scan.pages_audit?.total_pages_crawled ?? scan.pages_scanned_count ?? 1;
        document.getElementById("kpi-pages-count").textContent = String(pagesCount);
        document.getElementById("kpi-legal-coverage").textContent =
            `Privatnost: ${scan.has_privacy_policy ? "DA" : "NE"} | Kolačići: ${scan.has_cookie_policy ? "DA" : "NE"}`;

        const trackersCount = (scan.trackers || []).length;
        document.getElementById("kpi-trackers-count").textContent = `${trackersCount} trackera / ${(scan.ropa_entries || []).length} ROPA`;
        document.getElementById("kpi-cmp-status").textContent =
            `CMP Banner: ${scan.has_cookie_banner ? "Detektiran ✓" : "Nedostaje ✕"}`;

        renderCookiesTable(scan);
        renderSubpagesTreeAndTable(scan);
        renderRopaAndIssues(scan);
        refreshIcons();
    }

    // ------------------------------------------------------------------------
    // MODALNI PREGLEDNIK PDF IZVJEŠTAJA (output/pdf/*.pdf)
    // ------------------------------------------------------------------------

    async function openPdfPreview(docType = "pregled") {
        if (!state.activeScan) {
            showToast("Najprije odaberite ili skenirajte domenu.", true);
            return;
        }

        const modal = document.getElementById("pdf-preview-modal");
        const iframe = document.getElementById("pdf-preview-iframe");
        const titleEl = document.getElementById("pdf-modal-title");
        const downloadBtn = document.getElementById("pdf-modal-download-btn");

        try {
            const resp = await fetch("/api/generate-pdf", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scan_id: state.activeScan.id,
                    doc_type: docType,
                }),
            });
            const data = await resp.json();
            if (data.status === "ok") {
                const pdfUrl = data.pdf_url || `/output/pdf/${docType}.pdf?t=${Date.now()}`;
                iframe.src = pdfUrl;
                titleEl.textContent = `PDF Pregled: ${docType}.pdf — Domena: ${state.activeScan.domain}`;
                downloadBtn.href = `/output/pdf/${docType}.pdf?download=1&t=${Date.now()}`;
                modal.classList.remove("hidden");
            } else {
                showToast(data.message || "Greška pri generiranju PDF-a.", true);
            }
        } catch (err) {
            showToast(`Greška pri komunikaciji s PDF generatorom: ${err}`, true);
        }
    }

    function closePdfPreview() {
        const modal = document.getElementById("pdf-preview-modal");
        const iframe = document.getElementById("pdf-preview-iframe");
        if (modal) modal.classList.add("hidden");
        if (iframe) iframe.src = "about:blank";
    }

    // ------------------------------------------------------------------------
    // INICIJALIZACIJA DOGAĐAJA I UČITAVANJE POČETNOG STANJA
    // ------------------------------------------------------------------------

    document.addEventListener("DOMContentLoaded", () => {
        // 1. Učitaj inicijalne skenove iz ugrađenog JSON bloka
        try {
            const rawJson = document.getElementById("initial-scans-json")?.textContent || "[]";
            state.scans = JSON.parse(rawJson);
        } catch (e) {
            state.scans = [];
        }

        if (state.scans.length > 0) {
            setActiveScan(state.scans[0]);
        } else {
            renderSidebarDomains();
        }

        // 2. Navigacija između kartica (Tabs)
        document.querySelectorAll(".tab-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
                const targetTab = btn.getAttribute("data-tab");
                document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active-tab"));
                btn.classList.add("active-tab");

                document.querySelectorAll(".tab-pane").forEach((pane) => {
                    if (pane.id === targetTab) {
                        pane.classList.remove("hidden");
                    } else {
                        pane.classList.add("hidden");
                    }
                });
            });
        });

        // 3. Filtri tablice kolačića
        document.querySelectorAll(".cookie-filter-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
                state.cookieFilter = btn.getAttribute("data-cookie-filter") || "all";
                document.querySelectorAll(".cookie-filter-btn").forEach((b) => b.classList.remove("active-filter"));
                btn.classList.add("active-filter");
                if (state.activeScan) renderCookiesTable(state.activeScan);
            });
        });

        // 4. Pretraga stabla i tablice podstranica
        const subSearch = document.getElementById("subpages-search-input");
        if (subSearch) {
            subSearch.addEventListener("input", () => {
                state.subpageSearch = subSearch.value;
                if (state.activeScan) renderSubpagesTreeAndTable(state.activeScan);
            });
        }

        // 5. Filtriranje bočne liste domena
        const sidebarFilter = document.getElementById("sidebar-domain-filter");
        if (sidebarFilter) {
            sidebarFilter.addEventListener("input", renderSidebarDomains);
        }

        // 6. Pokretanje novog skeniranja domene
        const scanForm = document.getElementById("scan-form");
        if (scanForm) {
            scanForm.addEventListener("submit", async (ev) => {
                ev.preventDefault();
                const domInput = document.getElementById("domain-input");
                const maxPages = document.getElementById("max-pages-select")?.value || 12;
                const maxDepth = document.getElementById("max-depth-select")?.value || 2;
                const btnSubmit = document.getElementById("btn-scan-submit");

                const domainVal = (domInput?.value || "").trim();
                if (!domainVal) return;

                btnSubmit.disabled = true;
                showToast(`Pokrećem dubinsko BFS pretraživanje domene ${domainVal}...`);

                try {
                    const resp = await fetch("/api/scan", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            domain: domainVal,
                            max_pages: Number(maxPages),
                            max_depth: Number(maxDepth),
                        }),
                    });
                    const data = await resp.json();
                    if (data.status === "ok" && data.scan) {
                        const existingIdx = state.scans.findIndex((s) => s.id === data.scan.id || s.domain === data.scan.domain);
                        if (existingIdx >= 0) {
                            state.scans[existingIdx] = data.scan;
                        } else {
                            state.scans.unshift(data.scan);
                        }
                        setActiveScan(data.scan);
                        showToast(data.message || "Skeniranje i PDF izvještaji uspješno ažurirani.");
                    } else {
                        showToast(data.message || "Greška pri skeniranju domene.", true);
                    }
                } catch (err) {
                    showToast(`Mrežna greška pri skeniranju: ${err}`, true);
                } finally {
                    btnSubmit.disabled = false;
                }
            });
        }

        // 7. Ponovno skeniranje trenutno odabrane domene
        const btnRescanActive = document.getElementById("btn-rescan-active");
        if (btnRescanActive) {
            btnRescanActive.addEventListener("click", () => {
                if (!state.activeScan) return;
                const domInput = document.getElementById("domain-input");
                if (domInput) domInput.value = state.activeScan.domain;
                scanForm?.requestSubmit();
            });
        }

        // 8. Masovno ponovno skeniranje svih učitanih domena iz data/scans/*.json
        const btnRescanAll = document.getElementById("btn-rescan-all");
        if (btnRescanAll) {
            btnRescanAll.addEventListener("click", async () => {
                btnRescanAll.disabled = true;
                showToast("Pokrećem masovno skeniranje svih učitanih domena iz data/scans/...");
                try {
                    const maxPages = document.getElementById("max-pages-select")?.value || 12;
                    const maxDepth = document.getElementById("max-depth-select")?.value || 2;
                    const resp = await fetch("/api/rescan-all", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            max_pages: Number(maxPages),
                            max_depth: Number(maxDepth),
                        }),
                    });
                    const data = await resp.json();
                    if (data.status === "ok" && Array.isArray(data.scans)) {
                        state.scans = data.scans;
                        if (state.scans.length > 0) setActiveScan(state.scans[0]);
                        showToast(data.message);
                    } else {
                        showToast(data.message || "Greška pri masovnom skeniranju.", true);
                    }
                } catch (err) {
                    showToast(`Greška: ${err}`, true);
                } finally {
                    btnRescanAll.disabled = false;
                }
            });
        }

        // 9. Ručno osvježavanje svih 5 PDF izvještaja
        const btnRegenPdfs = document.getElementById("btn-regenerate-pdfs");
        if (btnRegenPdfs) {
            btnRegenPdfs.addEventListener("click", async () => {
                if (!state.activeScan) return;
                showToast(`Generiram sve PDF izvještaje za ${state.activeScan.domain}...`);
                const resp = await fetch("/api/generate-pdf", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ scan_id: state.activeScan.id, doc_type: "all" }),
                });
                const data = await resp.json();
                showToast(data.message || "PDF izvještaji osvježeni.", data.status !== "ok");
            });
        }

        // 10. Modal za uređivanje profila voditelja obrade (company_profile.json)
        const compModal = document.getElementById("company-modal");
        document.getElementById("btn-open-company-modal")?.addEventListener("click", () => compModal?.classList.remove("hidden"));
        document.getElementById("btn-close-company-modal")?.addEventListener("click", () => compModal?.classList.add("hidden"));
        document.getElementById("btn-cancel-company")?.addEventListener("click", () => compModal?.classList.add("hidden"));

        document.getElementById("company-form")?.addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const payload = {
                company_name: document.getElementById("comp-name")?.value || "",
                address: document.getElementById("comp-address")?.value || "",
                oib: document.getElementById("comp-oib")?.value || "",
                email: document.getElementById("comp-email")?.value || "",
                dpo_name: document.getElementById("comp-dpo")?.value || "",
                phone: document.getElementById("comp-phone")?.value || "",
            };
            const resp = await fetch("/api/company-profile", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await resp.json();
            compModal?.classList.add("hidden");
            showToast(data.message || "Profil spremljen.");
        });

        refreshIcons();
    });

    window.SentinelApp = {
        openPdfPreview,
        closePdfPreview,
    };
})();
