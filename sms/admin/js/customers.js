// ═══ customers.js — Dashboard, Customer CRUD, Filters, Modals ═══

    // ─── Dashboard ───────────────────────────────────────────
    async function loadDashboard() {
      try {
        const [dashResp, statsResp] = await Promise.all([
          fetch(`${WORKER_BASE}/admin/dashboard`, { headers: authHeaders() }),
          fetch(`${WORKER_BASE}/admin/stats`, { headers: authHeaders() }),
        ]);
        const dash = await dashResp.json();
        const stats = await statsResp.json();

        // KPIs
        document.getElementById("kpiTotal").textContent = dash.kpis.total_customers;
        document.getElementById("kpiSubscribed").textContent = dash.kpis.total_subscribed;
        document.getElementById("kpiConversion").textContent = dash.kpis.conversion_rate + "%";
        document.getElementById("kpiConversionSub").textContent = dash.kpis.converted_from_invite + " of " + dash.kpis.total_invited + " invited";
        document.getElementById("kpiMessages").textContent = dash.kpis.messages_this_month;
        document.getElementById("kpiPriority").textContent = dash.kpis.priority_customers > 0 ? "★ " + dash.kpis.priority_customers + " priority" : "";

        // Alerts
        const alertsEl = document.getElementById("dashAlerts");
        let alertHtml = "";
        if (dash.alerts.failed_sms > 0) {
          const details = dash.alerts.failed_sms_details || [];
          alertHtml += `<div class="alert-card" id="alertFailedSms">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;">
                <span class="count">${dash.alerts.failed_sms}</span> failed SMS this week
                <span class="alert-toggle" onclick="document.getElementById('failedSmsDetails').classList.toggle('open');this.textContent=this.textContent==='▼'?'▲':'▼'">▼</span>
              </div>
              <div class="alert-expand" id="failedSmsDetails">
                ${details.map(d => `<div class="alert-expand-item">
                  <div>
                    <strong>${esc(d.name || 'Unknown')}</strong>
                    <span style="color:var(--dim);margin-left:6px;">${esc(d.phone || '')}</span>
                    ${d.error_code ? `<span style="color:var(--red);margin-left:6px;font-size:12px;">${d.error_code}${TWILIO_ERRORS[d.error_code] ? ' — ' + TWILIO_ERRORS[d.error_code] : ''}</span>` : ''}
                  </div>
                  <span style="color:var(--dim);font-size:11px;">${new Date(d.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</span>
                </div>`).join('')}
              </div>
            </div>
            <span class="alert-dismiss" onclick="this.closest('.alert-card').style.display='none'" title="Dismiss">&times;</span>
          </div>`;
        }
        if (dash.alerts.new_from_stripe > 0)
          alertHtml += `<div class="alert-card info clickable" onclick="document.getElementById('recentActivity').scrollIntoView({behavior:'smooth'})"><div><span class="count">${dash.alerts.new_from_stripe}</span> new customer${dash.alerts.new_from_stripe !== 1 ? 's' : ''} from Stripe payments this week <span style="font-size:11px;color:var(--dim);margin-left:4px;">View ↓</span></div></div>`;
        if (dash.alerts.new_from_web > 0)
          alertHtml += `<div class="alert-card info"><div><span class="count">${dash.alerts.new_from_web}</span> new subscriber${dash.alerts.new_from_web !== 1 ? 's' : ''} from web form this week</div></div>`;
        if (dash.alerts.new_from_quick_subscribe > 0)
          alertHtml += `<div class="alert-card info"><div><span class="count">${dash.alerts.new_from_quick_subscribe}</span> new one-click subscriber${dash.alerts.new_from_quick_subscribe !== 1 ? 's' : ''} this week</div></div>`;
        alertsEl.innerHTML = alertHtml || "";

        // Actions
        const actionsEl = document.getElementById("dashActions");
        const actions = dash.actions;
        actionsEl.innerHTML = `
          ${actions.ready_to_invite > 0 ? `<div class="action-card">
            <div class="action-info"><div class="action-label">Ready to Invite</div><div class="action-desc">Has email + mobile, never invited</div></div>
            <div class="action-count">${actions.ready_to_invite}</div>
            <button class="btn-primary" onclick="dashAction('invite-ready')">Invite All</button>
            <button class="btn-secondary" onclick="dashAction('print-qr-ready')" style="margin-left:6px;">Print QR</button>
          </div>` : ''}
          ${actions.mobile_no_email > 0 ? `<div class="action-card">
            <div class="action-info"><div class="action-label">Mobile, No Email</div><div class="action-desc">Personal text from your phone, or print QR for invoices</div></div>
            <div class="action-count">${actions.mobile_no_email}</div>
            <button class="btn-success" onclick="dashAction('personal-text')">Text List</button>
            <button class="btn-secondary" onclick="dashAction('print-qr-no-email')" style="margin-left:6px;">Print QR</button>
          </div>` : ''}
          ${actions.stale_invites > 0 ? `<div class="action-card">
            <div class="action-info"><div class="action-label">Stale Invites (30+ days)</div><div class="action-desc">Invited but never subscribed</div></div>
            <div class="action-count">${actions.stale_invites}</div>
            <button class="btn-secondary" onclick="dashAction('re-invite')">Re-Invite</button>
          </div>` : ''}
          ${actions.email_only_no_mobile > 0 ? `<div class="action-card">
            <div class="action-info"><div class="action-label">Email Only, No Mobile</div><div class="action-desc">Can invite by email, links to web form</div></div>
            <div class="action-count">${actions.email_only_no_mobile}</div>
            <button class="btn-secondary" onclick="dashAction('invite-email-only')">Invite All</button>
          </div>` : ''}
          ${actions.needs_outreach > 0 ? `<div class="action-card">
            <div class="action-info"><div class="action-label">Needs Outreach</div><div class="action-desc">No email + no mobile — call or snail mail</div></div>
            <div class="action-count">${actions.needs_outreach}</div>
            <button class="btn-secondary" onclick="dashAction('export-outreach')">Export List</button>
            <button class="btn-secondary" onclick="dashAction('print-qr-generic')" style="margin-left:6px;">Print QR</button>
          </div>` : ''}
          ${actions.ready_to_invite === 0 && actions.mobile_no_email === 0 && actions.stale_invites === 0 && actions.email_only_no_mobile === 0 && actions.needs_outreach === 0 ? '<div class="empty">No actions needed right now!</div>' : ''}
        `;

        // Source breakdown
        const sourceEl = document.getElementById("sourceBreakdown");
        const sourceNames = { admin: "Admin Added", import: "Imported", payment: "Stripe Payment", web: "Web Form", "quick-subscribe": "One-Click", unknown: "Unknown" };
        sourceEl.innerHTML = dash.source_breakdown.map(s =>
          `<div class="store-chip"><strong>${s.count}</strong> ${sourceNames[s.source] || s.source}</div>`
        ).join("");

        // Store breakdown
        const storeEl = document.getElementById("storeBreakdown");
        if (stats.store_breakdown && stats.store_breakdown.length > 0) {
          storeEl.innerHTML = stats.store_breakdown.map(s =>
            `<div class="store-chip"><strong>${s.count}</strong> ${STORE_NAMES[s.store] || s.store || "No Store"}</div>`
          ).join("");
        } else {
          storeEl.innerHTML = '<div class="empty">No customers yet.</div>';
        }

        // Recent activity
        const activityEl = document.getElementById("recentActivity");
        if (dash.recent_activity.length > 0) {
          activityEl.innerHTML = dash.recent_activity.map(c => {
            const sourceLabel = sourceNames[c.source] || c.source || "";
            const date = new Date(c.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" });
            return `<div class="activity-item">
              <div>${esc(c.name || "Unnamed")} ${c.store ? '<span style="color:var(--dim);">· ' + (STORE_NAMES[c.store] || c.store) + '</span>' : ''}</div>
              <div style="display:flex;gap:8px;align-items:center;">
                ${sourceLabel ? `<span class="activity-source">${sourceLabel}</span>` : ''}
                ${STATUS_BADGE[c.sms_status] || ''}
                <span style="color:var(--dim);font-size:12px;">${date}</span>
              </div>
            </div>`;
          }).join("");
        } else {
          activityEl.innerHTML = '<div class="empty">No new activity this week.</div>';
        }

      } catch (e) {
        console.error("Dashboard error:", e);
        document.getElementById("kpiTotal").textContent = "?";
      }
    }

    // ─── Personal Text Helpers ─────────────────────────────────
    window.copyMsg = function(btn) {
      const msg = btn.getAttribute("data-msg");
      navigator.clipboard.writeText(msg).then(() => {
        btn.textContent = "Copied!";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "Copy Message"; btn.classList.remove("copied"); }, 2000);
      });
    };

    window.markPersonalText = async function(id) {
      const now = new Date().toISOString();
      const resp = await fetch(`${WORKER_BASE}/admin/customers/${id}`, {
        method: "PATCH",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ sms_status: "invited", invite_sent_at: now, notes_append: "Personal text sent " + now.slice(0, 10) }),
      });
      if (resp.ok) {
        const card = document.getElementById("pt-" + id);
        card.classList.add("done");
        card.querySelector(".btn-mark-sent").textContent = "Done!";
        card.querySelector(".btn-mark-sent").disabled = true;
      }
    };

    // ─── QR Print Helper ──────────────────────────────────────
    function printQrPage(title, subtitle, items) {
      // items: array of { name, phone, url, short_code } or { generic: true, url }
      const win = window.open("", "_blank");
      win.document.write('<html><head><title>' + esc(title) + '</title>'
        + '<style>body{font-family:Arial,sans-serif;margin:20px;}'
        + '.qr-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;}'
        + '.qr-item{text-align:center;page-break-inside:avoid;border:1px solid #ddd;border-radius:8px;padding:12px;}'
        + '.qr-item img{width:150px;height:150px;}'
        + '.qr-name{font-weight:700;font-size:14px;margin:8px 0 4px;}'
        + '.qr-phone{font-size:12px;color:#333;margin:2px 0;}'
        + '.qr-fallback{font-size:10px;color:#888;margin-top:4px;}'
        + '.qr-fallback a{color:#004b8d;}'
        + '@media print{.no-print{display:none!important;}}</style></head><body>'
        + '<div class="no-print" style="margin-bottom:16px;">'
        + '<button onclick="window.print()" style="padding:10px 20px;font-size:16px;cursor:pointer;">Print</button>'
        + '<span style="margin-left:12px;color:#666;">' + esc(subtitle) + '</span>'
        + '</div>'
        + '<div class="qr-grid">' + items.map(item => {
          const qrApi = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encodeURIComponent(item.url);
          if (item.generic) {
            return '<div class="qr-item">'
              + '<img src="' + qrApi + '" alt="QR">'
              + '<div class="qr-name">' + esc(item.name || "G&KK NAPA") + '</div>'
              + '<div class="qr-phone">Scan to subscribe to text updates</div>'
              + '<div class="qr-fallback">Or visit: <a href="' + item.url + '">' + item.url.replace('https://', '') + '</a></div>'
              + '</div>';
          }
          const phone = item.phone ? item.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3') : '';
          return '<div class="qr-item">'
            + '<img src="' + qrApi + '" alt="QR">'
            + '<div class="qr-name">' + esc(item.name || "Unnamed") + '</div>'
            + (phone ? '<div class="qr-phone">Texts will be sent to ' + phone + '</div>' : '')
            + '<div class="qr-fallback">Not your number? Subscribe at <a href="https://gkk-napa.com/sms/subscribe">gkk-napa.com/sms/subscribe</a></div>'
            + '</div>';
        }).join('') + '</div></body></html>');
      win.document.close();
    }

    // ─── Dashboard Actions ────────────────────────────────────
    window.dashAction = async function(action) {
      if (action === "invite-ready") {
        // Fetch customers with email + mobile + status none
        const resp = await fetch(`${WORKER_BASE}/admin/customers?status=none`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => c.email && c.line_type === "mobile");
        if (eligible.length === 0) { alert("No eligible customers."); return; }
        openInviteModal(eligible.map(c => c.id), `Sending email invites to ${eligible.length} customer(s) with email + mobile`);
      } else if (action === "print-qr-no-email") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => !c.email && c.line_type === "mobile" && c.short_code);
        if (eligible.length === 0) { alert("No eligible customers with short codes."); return; }
        printQrPage("QR Mailers — Mobile, No Email", eligible.length + " QR codes — mobile customers without email",
          eligible.map(c => ({ name: c.name, phone: c.phone, url: "https://gkk-napa.com/s/" + c.short_code })));
      } else if (action === "print-qr-ready") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers?status=none`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => c.email && c.line_type === "mobile" && c.short_code);
        if (eligible.length === 0) { alert("No eligible customers with short codes."); return; }
        printQrPage("QR Codes — Ready to Invite", eligible.length + " QR codes — customers with email + mobile",
          eligible.map(c => ({ name: c.name, phone: c.phone, url: "https://gkk-napa.com/s/" + c.short_code })));
      } else if (action === "print-qr-generic") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => !c.email && (!c.phone || c.line_type !== "mobile") && c.sms_status !== "subscribed");
        if (eligible.length === 0) { alert("No eligible customers."); return; }
        printQrPage("QR Codes — Needs Outreach", eligible.length + " generic QR codes — include with invoice or mail",
          eligible.map(c => ({ name: c.name, generic: true, url: "https://gkk-napa.com/sms/subscribe" })));
      } else if (action === "personal-text") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => !c.email && c.line_type === "mobile" && c.short_code && c.sms_status !== "subscribed");
        if (eligible.length === 0) { alert("No eligible customers."); return; }
        // Show the personal text panel
        const panel = document.getElementById("personalTextPanel");
        const list = document.getElementById("personalTextList");
        list.innerHTML = eligible.map(c => {
          const phone = c.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3');
          const url = 'https://gkk-napa.com/s/' + c.short_code;
          const name = c.name || 'Valued Customer';
          const firstName = name.split(' ')[0];
          const msg = "Hey " + firstName + ", it's Brian at G&KK NAPA! We have a new text updates program for order notifications, store hours & deals. If you're interested, tap here to subscribe: " + url;
          return '<div class="pt-card" id="pt-' + c.id + '">'
            + '<div class="pt-header">'
            + '<strong>' + esc(c.name || 'Unnamed') + '</strong>'
            + (c.store ? ' <span style="color:#888;font-size:12px;">(' + esc(c.store) + ')</span>' : '')
            + '</div>'
            + '<div class="pt-steps">'
            + '<div class="pt-step">1. <a href="sms:' + c.phone.replace('+1', '') + '" class="pt-phone">' + phone + '</a> <span style="color:#888;font-size:12px;">tap to open Messages</span></div>'
            + '<div class="pt-step">2. <button class="btn-copy-msg" onclick="copyMsg(this)" data-msg="' + esc(msg).replace(/"/g, '&quot;') + '">Copy Message</button></div>'
            + '<div class="pt-step">3. Paste into Messages &amp; send</div>'
            + '<div class="pt-step">4. <button class="btn-mark-sent" onclick="markPersonalText(\'' + c.id + '\')">Mark Sent</button></div>'
            + '</div>'
            + '</div>';
        }).join('');
        panel.style.display = "block";
        panel.scrollIntoView({ behavior: "smooth" });
      } else if (action === "re-invite") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers?status=invited`, { headers: authHeaders() });
        const customers = await resp.json();
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
        const stale = customers.filter(c => c.email && c.invite_sent_at && c.invite_sent_at < thirtyDaysAgo);
        if (stale.length === 0) { alert("No stale invites found."); return; }
        openInviteModal(stale.map(c => c.id), `Re-sending to ${stale.length} customer(s) invited 30+ days ago`);
      } else if (action === "invite-email-only") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
        const customers = await resp.json();
        const eligible = customers.filter(c => c.email && (!c.phone || c.line_type === "landline") && (c.sms_status === "none" || c.sms_status === "invited"));
        if (eligible.length === 0) { alert("No eligible customers."); return; }
        openInviteModal(eligible.map(c => c.id), `Sending to ${eligible.length} email-only customer(s) (no mobile)`, false);
      } else if (action === "export-outreach") {
        const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
        const customers = await resp.json();
        const needs = customers.filter(c => (!c.email || c.email === "") && (!c.phone || c.line_type === "landline"));
        if (needs.length === 0) { alert("No customers need outreach."); return; }
        let csv = "Name,Phone,Store,Notes\\n";
        needs.forEach(c => {
          csv += `"${(c.name||'').replace(/"/g,'""')}",${c.phone||''},"${STORE_NAMES[c.store]||c.store||''}","${(c.notes||'').replace(/"/g,'""')}"\\n`;
        });
        const blob = new Blob([csv], { type: "text/csv" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "needs-outreach.csv";
        a.click();
      }
    };

    // ─── Utility Buttons ──────────────────────────────────────
    document.getElementById("btnExportCsv").addEventListener("click", async () => {
      const resp = await fetch(`${WORKER_BASE}/admin/export`, { headers: authHeaders() });
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `gkk-napa-customers-${new Date().toISOString().slice(0,10)}.csv`;
      a.click();
    });

    document.getElementById("btnPrintQr").addEventListener("click", async () => {
      const resp = await fetch(`${WORKER_BASE}/admin/customers`, { headers: authHeaders() });
      const customers = await resp.json();
      const mobileWithCodes = customers.filter(c => c.short_code && c.line_type === 'mobile');
      if (mobileWithCodes.length === 0) { alert("No mobile customers with short codes."); return; }
      printQrPage("QR Codes — G&KK NAPA", mobileWithCodes.length + " QR codes (mobile only)",
        mobileWithCodes.map(c => ({ name: c.name, phone: c.phone, url: "https://gkk-napa.com/s/" + c.short_code })));
    });

    document.getElementById("btnGenShortCodes").addEventListener("click", async () => {
      const btn = document.getElementById("btnGenShortCodes");
      btn.disabled = true;
      btn.textContent = "Generating...";
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/generate-short-codes`, { method: "POST", headers: authHeaders() });
        const data = await resp.json();
        btn.textContent = data.generated > 0 ? `${data.generated} created!` : "All set!";
        setTimeout(() => { btn.textContent = "Generate Short Codes"; btn.disabled = false; }, 2000);
      } catch { btn.textContent = "Error"; btn.disabled = false; }
    });

    // ─── Customers ───────────────────────────────────────────
    const filterStore = document.getElementById("filterStore");
    const filterStatus = document.getElementById("filterStatus");
    const filterSearch = document.getElementById("filterSearch");
    const customerList = document.getElementById("customerList");
    const customerCount = document.getElementById("customerCount");

    const btnClearSearch = document.getElementById("btnClearSearch");

    const filterLineType = document.getElementById("filterLineType");
    const filterEmail = document.getElementById("filterEmail");
    const filterPriority = document.getElementById("filterPriority");
    [filterStore, filterStatus, filterLineType, filterEmail, filterPriority].forEach(el => el.addEventListener("change", loadCustomers));
    let searchTimeout;
    filterSearch.addEventListener("input", () => {
      btnClearSearch.style.display = filterSearch.value ? "block" : "none";
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(loadCustomers, 300);
    });
    btnClearSearch.addEventListener("click", () => {
      filterSearch.value = "";
      btnClearSearch.style.display = "none";
      loadCustomers();
    });

    async function loadCustomers() {
      const params = new URLSearchParams();
      if (filterStore.value) params.set("store", filterStore.value);
      if (filterStatus.value) params.set("status", filterStatus.value);
      if (filterSearch.value.trim()) params.set("q", filterSearch.value.trim());

      try {
        const resp = await fetch(`${WORKER_BASE}/admin/customers?${params}`, { headers: authHeaders() });
        allCustomers = await resp.json();
        let filtered = allCustomers;
        if (filterLineType.value) {
          filtered = filtered.filter(c => c.line_type === filterLineType.value);
        }
        if (filterEmail.value === "has") {
          filtered = filtered.filter(c => c.email);
        } else if (filterEmail.value === "no") {
          filtered = filtered.filter(c => !c.email);
        }
        if (filterPriority.value === "priority") {
          filtered = filtered.filter(c => c.is_priority);
        }
        renderCustomers(filtered);
      } catch {
        customerList.innerHTML = '<div class="error">Failed to load customers.</div>';
      }
    }

    var _customerPage = 0;
    var _customerPageSize = 25;
    var _filteredCustomers = [];

    function renderCustomers(customers) {
      _filteredCustomers = customers;
      _customerPage = 0;
      _renderCustomerPage();
    }

    function _renderCustomerPage() {
      var customers = _filteredCustomers;
      var total = customers.length;
      var totalPages = Math.max(1, Math.ceil(total / _customerPageSize));
      if (_customerPage >= totalPages) _customerPage = totalPages - 1;
      if (_customerPage < 0) _customerPage = 0;

      var start = _customerPage * _customerPageSize;
      var end = Math.min(start + _customerPageSize, total);
      var page = customers.slice(start, end);

      customerCount.textContent = total + ' customer' + (total !== 1 ? 's' : '');

      if (total === 0) {
        customerList.innerHTML = '<div class="empty">No customers match the filters.</div>';
        return;
      }

      var html = page.map(c => `
        <div class="customer-item" data-id="${c.id}">
          <div class="customer-info">
            <div class="customer-name">
              <span class="priority-star ${c.is_priority ? 'active' : ''}" onclick="event.stopPropagation();togglePriority(${c.id},${c.is_priority ? 0 : 1})" title="${c.is_priority ? 'Remove priority' : 'Mark as priority'}">${c.is_priority ? '★' : '☆'}</span>
              ${esc(c.name || "Unnamed")}
              ${STATUS_BADGE[c.sms_status] || ""}
              ${c.line_type ? `<span class="badge badge-${c.line_type}">${c.line_type}</span>` : ""}
            </div>
            <div class="customer-detail">${esc(c.phone)}${c.store ? " &middot; " + (STORE_NAMES[c.store] || c.store) : ""}</div>
            ${c.email ? `<div class="customer-detail">${esc(c.email)}</div>` : ""}
            ${c.notes ? `<div class="customer-detail" style="">${esc(c.notes)}</div>` : ""}
          </div>
          <div class="customer-actions">
            ${c.sms_status === "none" || c.sms_status === "invited" ? `<button class="btn-success" onclick="inviteOne(${c.id})" ${!c.email ? "disabled title='No email'" : "title='Send invite email'"}>Invite</button>` : ""}
            <button class="btn-secondary" onclick="editCustomer(${c.id})">Edit</button>
            <button class="btn-danger" onclick="deleteCustomer(${c.id}, '${esc(c.name || c.phone)}')">Del</button>
          </div>
        </div>
      `).join("");

      // Pagination controls
      if (totalPages > 1) {
        html += '<div style="display:flex;align-items:center;justify-content:center;gap:12px;margin-top:16px;padding:8px 0;">';
        html += '<button class="btn-secondary" style="padding:6px 14px;font-size:13px;" onclick="customerPagePrev()"' + (_customerPage === 0 ? ' disabled' : '') + '>&larr; Prev</button>';
        html += '<span style="font-size:13px;color:rgba(255,255,255,.5);">' + (start + 1) + '–' + end + ' of ' + total + '</span>';
        html += '<button class="btn-secondary" style="padding:6px 14px;font-size:13px;" onclick="customerPageNext()"' + (_customerPage >= totalPages - 1 ? ' disabled' : '') + '>Next &rarr;</button>';
        html += '</div>';
      }

      customerList.innerHTML = html;
    }

    window.customerPagePrev = function() {
      if (_customerPage > 0) { _customerPage--; _renderCustomerPage(); customerList.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    };
    window.customerPageNext = function() {
      var totalPages = Math.ceil(_filteredCustomers.length / _customerPageSize);
      if (_customerPage < totalPages - 1) { _customerPage++; _renderCustomerPage(); customerList.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    };

    // ─── Toggle Priority ─────────────────────────────────────
    window.togglePriority = async function(id, newValue) {
      try {
        await fetch(`${WORKER_BASE}/admin/customers/${id}`, {
          method: "PUT",
          headers: authHeaders(),
          body: JSON.stringify({ is_priority: newValue }),
        });
        loadCustomers();
      } catch (e) {
        console.error("Priority toggle failed:", e);
      }
    };

    // ─── Add/Edit Customer Modal ─────────────────────────────
    const customerModal = document.getElementById("customerModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalCustomerId = document.getElementById("modalCustomerId");
    const modalName = document.getElementById("modalName");
    const modalPhone = document.getElementById("modalPhone");
    const modalEmail = document.getElementById("modalEmail");
    const modalStore = document.getElementById("modalStore");
    const modalNotes = document.getElementById("modalNotes");
    const modalError = document.getElementById("modalError");

    document.getElementById("btnAddCustomer").addEventListener("click", () => {
      modalTitle.textContent = "Add Customer";
      modalCustomerId.value = "";
      modalName.value = "";
      modalPhone.value = "";
      modalPhone.disabled = false;
      modalEmail.value = "";
      modalStore.value = "";
      modalNotes.value = "";
      document.getElementById("modalPriority").checked = false;
      modalError.style.display = "none";
      document.getElementById("subscribeUrlRow").style.display = "none";
      customerModal.classList.add("open");
    });

    window.editCustomer = async function(id) {
      const c = allCustomers.find(x => x.id === id);
      if (!c) return;
      modalTitle.textContent = "Edit Customer";
      modalCustomerId.value = c.id;
      modalName.value = c.name || "";
      modalPhone.value = c.phone ? formatPhone(c.phone) : "";
      modalPhone.disabled = false;
      modalEmail.value = c.email || "";
      modalStore.value = c.store || "";
      modalNotes.value = c.notes || "";
      document.getElementById("modalPriority").checked = !!c.is_priority;
      modalError.style.display = "none";

      // Show subscribe URL (prefer short URL if available)
      if (c.short_code) {
        document.getElementById("modalSubscribeUrl").value = `https://gkk-napa.com/s/${c.short_code}`;
      } else {
        const token = await generateSubscribeToken(c.id);
        document.getElementById("modalSubscribeUrl").value =
          `https://gkk-napa-sms.kellyraeknight78.workers.dev/quick-subscribe?token=${token}`;
      }
      document.getElementById("subscribeUrlRow").style.display = "block";

      customerModal.classList.add("open");
    };

    document.getElementById("btnModalCancel").addEventListener("click", () => {
      customerModal.classList.remove("open");
    });

    document.getElementById("btnModalSave").addEventListener("click", async () => {
      modalError.style.display = "none";
      const id = modalCustomerId.value;
      const data = {
        name: modalName.value.trim(),
        phone: modalPhone.value.trim(),
        email: modalEmail.value.trim(),
        store: modalStore.value,
        notes: modalNotes.value.trim(),
        is_priority: document.getElementById("modalPriority").checked ? 1 : 0,
      };

      if (!data.phone && !data.email) {
        modalError.textContent = "Phone number or email is required.";
        modalError.style.display = "block";
        return;
      }

      try {
        const url = id ? `${WORKER_BASE}/admin/customers/${id}` : `${WORKER_BASE}/admin/customers`;
        const method = id ? "PUT" : "POST";
        const resp = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(data) });
        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.error || "Failed to save.");
        }
        customerModal.classList.remove("open");
        loadCustomers();
      } catch (e) {
        modalError.textContent = e.message;
        modalError.style.display = "block";
      }
    });

    // ─── Check Line Types ──────────────────────────────────
    document.getElementById("btnCheckLineTypes").addEventListener("click", async () => {
      const btn = document.getElementById("btnCheckLineTypes");
      btn.disabled = true;
      btn.textContent = "Checking...";
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/check-line-types`, { method: "POST", headers: authHeaders() });
        const data = await resp.json();
        btn.textContent = data.checked > 0 ? `${data.checked} checked!` : "All set!";
        loadCustomers();
        setTimeout(() => { btn.textContent = "Check Lines"; btn.disabled = false; }, 2000);
      } catch {
        btn.textContent = "Error";
        setTimeout(() => { btn.textContent = "Check Lines"; btn.disabled = false; }, 2000);
      }
    });

    // ─── Delete Customer (with undo) ─────────────────────────
    var _pendingDelete = null;

    window.deleteCustomer = function(id, name) {
      // Cancel any previous pending delete
      if (_pendingDelete) {
        clearTimeout(_pendingDelete.timer);
        if (_pendingDelete.toast) _pendingDelete.toast.remove();
        _pendingDelete = null;
      }

      // Hide the row immediately
      var row = document.querySelector('.customer-item[data-id="' + id + '"]');
      if (row) { row.style.display = 'none'; row.dataset.pendingDelete = '1'; }

      // Build undo toast near the deleted row
      var toast = document.createElement('div');
      toast.className = 'toast';
      toast.style.borderColor = 'rgba(255,107,107,.4)';
      toast.innerHTML = '<span style="flex:1;">Deleted <strong>' + esc(name) + '</strong></span><button style="background:var(--napa-yellow);color:#111;border:none;border-radius:6px;padding:4px 12px;font-weight:700;font-size:13px;cursor:pointer;white-space:nowrap;" id="undoDeleteBtn">Undo</button>';
      document.body.appendChild(toast);
      if (row) {
        var rr = row.getBoundingClientRect();
        toast.style.left = (rr.left + rr.width / 2 - toast.offsetWidth / 2) + 'px';
        toast.style.top = (rr.top + window.scrollY) + 'px';
      } else {
        toast.style.position = 'fixed'; toast.style.top = '20px'; toast.style.right = '20px';
      }

      var pending = {
        id: id,
        toast: toast,
        timer: setTimeout(function() { _commitDelete(id, name, toast); }, 5000),
      };
      _pendingDelete = pending;

      toast.querySelector('#undoDeleteBtn').addEventListener('click', function() {
        clearTimeout(pending.timer);
        _pendingDelete = null;
        // Restore row
        if (row) { row.style.display = ''; delete row.dataset.pendingDelete; }
        toast.classList.add('fadeout');
        setTimeout(function() { toast.remove(); }, 300);
        showToast('Restored ' + name, 'success', row);
      });
    };

    async function _commitDelete(id, name, toast) {
      _pendingDelete = null;
      // Fade out the undo toast
      if (toast) { toast.classList.add('fadeout'); setTimeout(function() { toast.remove(); }, 300); }
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/customers/${id}/delete`, { method: "POST", headers: authHeaders() });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          showToast('Delete failed: ' + (err.error || resp.statusText), 'error');
          loadCustomers(); // restore list
          return;
        }
        loadCustomers();
      } catch (e) {
        showToast('Delete failed: ' + e.message, 'error');
        loadCustomers();
      }
    }

    // ─── Invite (with preview modal) ───────────────────────
    const inviteModal = document.getElementById("inviteModal");
    const inviteSubject = document.getElementById("inviteSubject");
    const inviteIntro = document.getElementById("inviteIntro");
    const inviteBullets = document.getElementById("inviteBullets");
    const invitePreview = document.getElementById("invitePreview");
    const inviteRecipientInfo = document.getElementById("inviteRecipientInfo");
    const inviteError = document.getElementById("inviteError");
    const inviteSuccess = document.getElementById("inviteSuccess");
    let pendingInviteIds = [];

    let previewHasMobile = true; // tracks which version of email preview to show

    function buildPreviewHtml(intro, bullets) {
      const bulletHtml = bullets.split("\n").filter(b => b.trim()).map(b =>
        `<tr><td style="padding:6px 0;font-size:15px;color:#333;">&#10003;&nbsp;&nbsp;${esc(b.trim())}</td></tr>`
      ).join("");
      const phoneSection = previewHasMobile
        ? `<div style="padding:0 24px 16px;text-align:center;">
            <p style="margin:0 0 12px;font-size:14px;color:#333;">Texts will be sent to <strong>(555) 555-1234</strong><br><span style="font-size:12px;color:#888;">Not a mobile number? <span style="color:#0A0094;">Subscribe with a different number</span></span></p>
          </div>`
        : '';
      const buttonText = previewHasMobile ? 'Subscribe with One Click' : 'Subscribe Now';
      return `<div style="font-family:Arial,sans-serif;">
        <div style="background-color:#0A0094;">
          <img src="https://gkk-napa.com/assets/pay-email-logo.png" alt="NAPA Auto Parts" height="75" style="display:block;height:75px;width:auto;">
          <div style="color:#ffffff;font-size:13px;padding:0 0 10px 12px;">G&amp;KK Store Updates</div>
        </div>
        <div style="padding:32px 24px 16px;">
          <h1 style="margin:0 0 16px;font-size:22px;color:#111;font-weight:700;">Hi [Customer Name],</h1>
          <p style="margin:0 0 16px;font-size:16px;color:#333;line-height:1.6;">${esc(intro)}</p>
          <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">${bulletHtml}</table>
        </div>
        ${phoneSection}
        <div style="text-align:center;padding:0 24px 16px;">
          <span style="display:inline-block;background-color:#FFC836;color:#0A0094;font-size:16px;font-weight:700;padding:14px 32px;border-radius:8px;text-transform:uppercase;letter-spacing:0.5px;">${buttonText}</span>
        </div>
        ${!previewHasMobile ? '<div style="padding:0 24px 8px;text-align:center;"><p style="margin:0;font-size:13px;color:#888;">Button links to <span style="color:#0A0094;">gkk-napa.com/sms/subscribe</span></p></div>' : ''}
        <div style="padding:0 24px 24px;">
          <p style="margin:0;font-size:12px;color:#888;line-height:1.5;text-align:center;">By clicking subscribe, you agree to receive SMS messages from G&amp;KK NAPA Auto Parts about order updates, store hours/closures, and occasional promotions. Message frequency varies. Msg &amp; data rates may apply. Consent is not a condition of purchase. Reply STOP to opt out, HELP for help. See <span style="color:#0A0094;">Privacy Policy</span> and <span style="color:#0A0094;">Terms of Service</span>.</p>
        </div>
        <div style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; gkk-napa.com</p>
        </div>
      </div>`;
    }

    function updateInvitePreview() {
      invitePreview.innerHTML = buildPreviewHtml(inviteIntro.value, inviteBullets.value);
    }

    inviteIntro.addEventListener("input", updateInvitePreview);
    inviteBullets.addEventListener("input", updateInvitePreview);

    function openInviteModal(customerIds, recipientLabel, hasMobile) {
      pendingInviteIds = customerIds;
      previewHasMobile = hasMobile !== false; // default true
      inviteRecipientInfo.textContent = recipientLabel;
      inviteError.style.display = "none";
      inviteSuccess.style.display = "none";
      document.getElementById("btnInviteSend").disabled = false;
      document.getElementById("btnInviteSend").textContent = "Send Invitations";
      updateInvitePreview();
      inviteModal.classList.add("open");
    }

    window.inviteOne = function(id) {
      const c = allCustomers.find(x => x.id === id);
      if (!c || !c.email) return;
      openInviteModal([id], `Sending to: ${c.name || c.email} (${c.email})`);
    };

    document.getElementById("btnInviteAll").addEventListener("click", () => {
      const eligible = allCustomers.filter(c => c.email && (c.sms_status === "none" || c.sms_status === "invited"));
      if (eligible.length === 0) {
        alert("No eligible customers in current filter (need email + status none/invited).");
        return;
      }
      openInviteModal(eligible.map(c => c.id), `Sending to ${eligible.length} customer(s) with email + status none/invited`);
    });

    document.getElementById("btnInviteCancel").addEventListener("click", () => {
      inviteModal.classList.remove("open");
    });

    document.getElementById("btnInviteSend").addEventListener("click", async () => {
      inviteError.style.display = "none";
      inviteSuccess.style.display = "none";
      const btn = document.getElementById("btnInviteSend");
      btn.disabled = true;
      btn.textContent = "Sending...";

      try {
        const resp = await fetch(`${WORKER_BASE}/admin/invite`, {
          method: "POST",
          headers: authHeaders(),
          body: JSON.stringify({
            customer_ids: pendingInviteIds,
            subject: inviteSubject.value.trim(),
            intro: inviteIntro.value.trim(),
            bullets: inviteBullets.value.trim().split("\n").filter(b => b.trim()),
          }),
        });
        const data = await resp.json();
        if (resp.ok) {
          inviteSuccess.textContent = `Done! ${data.sent} sent, ${data.failed} failed out of ${data.total_eligible} eligible.`;
          inviteSuccess.style.display = "block";
          btn.textContent = "Sent!";
          loadCustomers();
          setTimeout(() => inviteModal.classList.remove("open"), 2000);
        } else {
          throw new Error(data.error || "Failed to send.");
        }
      } catch (e) {
        inviteError.textContent = e.message;
        inviteError.style.display = "block";
        btn.disabled = false;
        btn.textContent = "Send Invitations";
      }
    });

    modalPhone.addEventListener("input", () => {
      const pos = modalPhone.selectionStart;
      const before = modalPhone.value.length;
      modalPhone.value = formatPhone(modalPhone.value);
      const after = modalPhone.value.length;
      modalPhone.setSelectionRange(pos + (after - before), pos + (after - before));
    });

    document.getElementById("btnCopyUrl").addEventListener("click", () => {
      const urlInput = document.getElementById("modalSubscribeUrl");
      navigator.clipboard.writeText(urlInput.value).then(() => {
        const btn = document.getElementById("btnCopyUrl");
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = "Copy"; }, 1500);
      });
    });
