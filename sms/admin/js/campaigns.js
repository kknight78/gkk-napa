// ═══ campaigns.js — Campaign History, Composer ═══

    // (Old manual message code removed — replaced by Campaign Composer)

    // ─── Campaign History ────────────────────────────────────
    function _mediaPreview(url, maxW) {
      if (!url) return '';
      maxW = maxW || 120;
      var isVideo = /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(url);
      if (isVideo) {
        return '<video src="' + esc(url) + '" style="margin-top:6px;max-width:' + maxW + 'px;border-radius:6px;" controls preload="metadata"></video>';
      }
      return '<img src="' + esc(url) + '" style="margin-top:6px;max-width:' + maxW + 'px;border-radius:6px;" />';
    }

    const campaignList = document.getElementById("campaignList");
    var _clAllCampaigns = [];
    var _clFilter = 'all';

    async function loadCampaigns() {
      try {
        var resp = await fetch(WORKER_BASE + '/admin/campaigns', { headers: authHeaders() });
        _clAllCampaigns = await resp.json();
        clApplyFilters();
      } catch {
        campaignList.innerHTML = '<div class="cl-empty">Failed to load campaigns.</div>';
      }
    }

    window.clSetFilter = function(filter) {
      _clFilter = filter;
      document.querySelectorAll('.cl-filter-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.filter === filter);
      });
      clApplyFilters();
    };

    window.clApplyFilters = function() {
      var search = (document.getElementById('clSearch') || {}).value || '';
      var sort = (document.getElementById('clSort') || {}).value || 'newest';
      var items = _clAllCampaigns.slice();

      // Classify each campaign
      items.forEach(function(c) {
        c._isDraft = c.status === 'draft';
        c._isPromo = c.promo_type === 'promo' || c.promo_type === 'compose';
        c._hasScheduled = c._isPromo && c.events && c.events.some(function(e) { return e.status === 'scheduled'; });
        c._group = c._isDraft ? 'draft' : c._hasScheduled ? 'in-flight' : 'completed';
        c._totalSent = c._isPromo && c.events ? c.events.reduce(function(s, e) { return s + (e.sent_count || 0); }, 0) : (c.sent_count || 0);
        c._totalFailed = c._isPromo && c.events ? c.events.reduce(function(s, e) { return s + (e.failed_count || 0); }, 0) : (c.failed_count || 0);
      });

      // Filter
      if (_clFilter !== 'all') {
        items = items.filter(function(c) { return c._group === _clFilter; });
      }

      // Search
      if (search) {
        var q = search.toLowerCase();
        items = items.filter(function(c) { return (c.name || '').toLowerCase().includes(q); });
      }

      // Sort
      items.sort(function(a, b) {
        var da = new Date(a.created_at || 0), db = new Date(b.created_at || 0);
        return sort === 'oldest' ? da - db : db - da;
      });

      if (items.length === 0) {
        campaignList.innerHTML = '<div class="cl-empty">' + (_clAllCampaigns.length === 0 ? 'No campaigns yet — click <strong>+ New Campaign</strong> above to get started!' : 'No campaigns match your filters.') + '</div>';
        return;
      }

      // Group by section (in-flight first, then drafts, then completed)
      var grouped = { 'in-flight': [], draft: [], completed: [] };
      items.forEach(function(c) { grouped[c._group].push(c); });

      var html = '';
      var sectionOrder = ['in-flight', 'draft', 'completed'];
      var sectionLabels = { 'in-flight': 'In-Flight', draft: 'Drafts', completed: 'Completed' };
      var showLabels = _clFilter === 'all';

      sectionOrder.forEach(function(section) {
        var list = grouped[section];
        if (list.length === 0) return;
        if (showLabels) {
          html += '<div class="cl-section-label">' + sectionLabels[section] + ' (' + list.length + ')</div>';
        }
        list.forEach(function(c) { html += _clRenderCard(c); });
      });

      campaignList.innerHTML = html;
    };

    function _clFmtDate(d) {
      return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    }

    function _clRenderCard(c) {
      var store = c.store_filter ? (STORE_NAMES[c.store_filter] || c.store_filter) : 'All Stores';
      var events = (c._isPromo && c.events) ? c.events : [];

      // Date line: show send date range for promo, creation date for drafts
      var dateStr = '';
      if (c._isDraft) {
        dateStr = 'Created ' + _clFmtDate(c.created_at);
      } else if (events.length > 0) {
        var first = events[0].send_at, last = events[events.length - 1].send_at;
        dateStr = _clFmtDate(first);
        if (events.length > 1) dateStr += ' \u2192 ' + _clFmtDate(last);
      } else {
        dateStr = _clFmtDate(c.created_at);
      }

      // Status pill
      var statusHtml = '';
      var cardClass = 'campaign-item';
      if (c._group === 'in-flight') {
        var scheduledCount = events.filter(function(e) { return e.status === 'scheduled'; }).length;
        statusHtml = '<span class="ci-status ci-status-inflight">' + scheduledCount + ' scheduled</span>';
        cardClass += ' ci-inflight';
      } else if (c._isDraft) {
        statusHtml = '<span class="ci-status ci-status-draft">Draft</span>';
        cardClass += ' ci-draft';
      } else {
        statusHtml = '<span class="ci-status ci-status-sent">Sent</span>';
      }

      // Horizontal message sub-cards
      var messagesHtml = '';
      if (events.length > 0) {
        messagesHtml = '<div class="ci-messages">';
        events.forEach(function(e, idx) {
          var isVideo = e.media_url && /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(e.media_url);
          var statusDot = e.status === 'sent' ? 'ci-dot-sent' : e.status === 'cancelled' ? 'ci-dot-cancelled' : 'ci-dot-scheduled';
          var bodySnippet = (e.body || '').replace(/\n/g, ' ').substring(0, 100);
          if ((e.body || '').length > 100) bodySnippet += '\u2026';

          // Thumbnail
          var thumbHtml = '';
          if (e.media_url) {
            if (isVideo) {
              thumbHtml = '<div class="ci-msg-thumb ci-msg-thumb-video"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg></div>';
            } else {
              thumbHtml = '<div class="ci-msg-thumb"><img src="' + esc(e.media_url) + '" /></div>';
            }
          }

          // Per-message stats line
          var msgStats = '';
          if (e.status === 'sent') {
            var eSent = e.sent_count || 0;
            var eFailed = e.failed_count || 0;
            msgStats = '<div class="ci-msg-stats">' + eSent + ' sent' +
              (eFailed > 0 ? ' &middot; <span style="color:var(--red);">' + eFailed + ' failed</span>' : '') +
              '</div>';
          } else if (e.status === 'scheduled') {
            msgStats = '<div class="ci-msg-stats"><span class="ci-msg-sched">Scheduled</span></div>';
          } else if (e.status === 'cancelled') {
            msgStats = '<div class="ci-msg-stats" style="color:var(--red);">Cancelled</div>';
          }

          messagesHtml += '<div class="ci-msg">' +
            '<div class="ci-msg-header">' +
              '<div class="ci-msg-dot ' + statusDot + '"></div>' +
              '<span class="ci-msg-label">' + esc(e.label) + '</span>' +
              '<span class="ci-msg-date">' + _clFmtDate(e.send_at) + '</span>' +
            '</div>' +
            msgStats +
            '<div class="ci-msg-content">' +
              (bodySnippet ? '<div class="ci-msg-text">' + esc(bodySnippet) + '</div>' : '') +
              thumbHtml +
            '</div>' +
          '</div>';
        });
        messagesHtml += '</div>';
      } else if (!c._isDraft && !c._isPromo) {
        var delivered = c.delivered_count || 0;
        messagesHtml = '<div class="ci-stats">' +
          '<span><span class="ci-num">' + (c.recipient_count || 0) + '</span> recipients</span>' +
          '<span><span class="ci-num">' + c._totalSent + '</span> sent</span>' +
          '<span><span class="ci-num-green">' + delivered + '</span> delivered</span>' +
          (c._totalFailed > 0 ? '<span><span class="ci-num-red">' + c._totalFailed + '</span> failed</span>' : '') +
          '</div>';
      }

      // Draft actions
      var actionsHtml = '';
      if (c._isDraft) {
        actionsHtml = '<div class="ci-draft-actions">' +
          '<button class="btn-primary" onclick="event.stopPropagation();loadDraft(' + c.id + ')">Edit</button>' +
          '<button class="btn-danger" onclick="event.stopPropagation();deleteDraft(' + c.id + ',this)">Delete</button>' +
          '</div>';
      }

      var onclick = c._isDraft ? '' : ' onclick="viewCampaign(' + c.id + ')"';
      return '<div class="' + cardClass + '"' + onclick + '>' +
        '<div class="ci-top"><div class="ci-name">' + esc(c.name) + '</div>' + statusHtml + '</div>' +
        '<div class="ci-meta">' + dateStr + ' &middot; ' + store + '</div>' +
        messagesHtml + actionsHtml +
        '</div>';
    }

    window.cancelPromoEvent = async function(campaignId, eventId) {
      if (!confirm("Cancel this scheduled event?")) return;
      // Cancel single event not supported by API — cancel all for this campaign
      // The API cancels all scheduled events, so this is the same effect
      try {
        await fetch(`${WORKER_BASE}/admin/promo/cancel/${campaignId}`, { method: "POST", headers: authHeaders() });
        loadCampaigns();
      } catch { alert("Failed to cancel."); }
    };

    window.cancelAllPromoEvents = async function(campaignId) {
      if (!confirm("Cancel ALL remaining scheduled events for this campaign?")) return;
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/promo/cancel/${campaignId}`, { method: "POST", headers: authHeaders() });
        const data = await resp.json();
        alert(`${data.cancelled} event(s) cancelled.`);
        loadCampaigns();
      } catch { alert("Failed to cancel."); }
    };

    window.loadDraft = async function(id) {
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/campaigns/${id}`, { headers: authHeaders() });
        const data = await resp.json();
        if (data.error) { alert(data.error); return; }

        // Parse draft data
        var draftMessages = [];
        try { draftMessages = JSON.parse(data.draft_data || '[]'); } catch { }
        if (!draftMessages.length) draftMessages = [{ body: data.body || '', media_url: data.media_url, media_type: 'none', send_now: true, send_at: null }];

        // Restore composer state
        composerDraftId = id;
        composerMessages = draftMessages.map(function(m) {
          var mediaType = m.media_type || 'none';
          if (!mediaType || mediaType === 'none') {
            if (m.media_url === SMS_LOGO_URL) mediaType = 'logo';
            else if (m.media_url) mediaType = 'library';
          }
          return { body: m.body || '', mediaType: mediaType, mediaUrl: m.media_url || null, sendNow: !!m.send_now, sendAt: m.send_at || null, channels: m.channels || { sms: true, email: false, facebook: false } };
        });
        document.getElementById('composerName').value = data.name || '';

        // Restore settings from promo_meta
        var meta = {};
        try { meta = JSON.parse(data.promo_meta || '{}'); } catch { }
        document.getElementById('composerPriority').checked = !!meta.priority_only;
        if (meta.dev_mode) {
          document.getElementById('composerDevMode').checked = true;
          document.getElementById('composerDevFields').style.display = 'block';
          if (meta.dev_phone) document.getElementById('composerDevPhone').value = meta.dev_phone;
          if (meta.dev_email) document.getElementById('composerDevEmail').value = meta.dev_email;
        }

        // Show draft status
        var statusEl = document.getElementById('composerDraftStatus');
        statusEl.textContent = 'Editing draft — saved ' + new Date(data.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
        statusEl.style.display = 'block';

        // Switch to composer and render
        composerRender();
        composerShowComposer();
        composerUpdateRecipients();
        document.getElementById('composerView').scrollIntoView({ behavior: 'smooth' });
      } catch (e) { alert('Failed to load draft: ' + e.message); }
    };

    window.deleteDraft = async function(id, btnEl) {
      if (!confirm('Delete this draft?')) return;
      try {
        await fetch(`${WORKER_BASE}/admin/campaigns/${id}`, { method: 'DELETE', headers: authHeaders() });
        showToast('Draft deleted', 'success', btnEl);
        loadCampaigns();
      } catch { alert('Failed to delete draft.'); }
    };

    // ─── Campaign Detail Modal ───────────────────────────────
    const campaignModal = document.getElementById("campaignModal");
    const campaignDetailTitle = document.getElementById("campaignDetailTitle");
    const campaignDetailBody = document.getElementById("campaignDetailBody");

    window.viewCampaign = async function(id) {
      campaignDetailTitle.textContent = "Loading...";
      campaignDetailBody.innerHTML = "";
      campaignModal.classList.add("open");

      try {
        const resp = await fetch(`${WORKER_BASE}/admin/campaigns/${id}`, { headers: authHeaders() });
        const data = await resp.json();

        campaignDetailTitle.textContent = data.name;
        const isPromo = data.promo_type === "promo" || data.promo_type === "compose";
        let html = `
          <div style="font-size:13px;color:var(--dim);margin-bottom:12px;">
            ${new Date(data.created_at).toLocaleString()} &middot;
            ${data.store_filter ? (STORE_NAMES[data.store_filter] || data.store_filter) : "All Stores"}
            ${data.sequence_preset ? " &middot; Sequence: " + data.sequence_preset : ""}
          </div>
        `;

        // Show promo events if applicable
        if (isPromo) {
          try {
            const evResp = await fetch(`${WORKER_BASE}/admin/promo/events?campaign_id=${id}`, { headers: authHeaders() });
            const events = await evResp.json();

            // Aggregate stats from events
            const totalSent = events.reduce((s, e) => s + (e.sent_count || 0), 0);
            const totalFailed = events.reduce((s, e) => s + (e.failed_count || 0), 0);
            const scheduledLeft = events.filter(e => e.status === "scheduled").length;
            html += `<div class="campaign-stats" style="margin-bottom:16px;">
              <span>Sent: <strong>${totalSent}</strong></span>
              <span style="color:var(--red);">Failed: <strong>${totalFailed}</strong></span>
              ${scheduledLeft > 0 ? `<span style="color:var(--napa-yellow);">Scheduled: <strong>${scheduledLeft}</strong></span>` : ''}
              ${(data.email_count || 0) > 0 ? `<span style="color:#8cc4ff;">Emailed: <strong>${data.email_count}</strong>${data.email_failed_count > 0 ? ` (${data.email_failed_count} failed)` : ''}</span>` : ''}
            </div>`;
            if (events.length > 0) {
              html += '<h2 style="font-size:14px;">Messages</h2>';
              html += events.map(e => {
                const statusClass = e.status === "sent" ? "event-sent" : e.status === "cancelled" ? "event-cancelled" : "event-scheduled";
                const dateStr = new Date(e.send_at).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
                const isScheduled = e.status === "scheduled";
                return `<div class="event-row" style="flex-direction:column;align-items:stretch;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                      <strong>${esc(e.label)}</strong>
                      <span style="color:var(--dim);margin-left:8px;">${dateStr}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:8px;">
                      ${e.status === "sent" ? `<span style="font-size:12px;">${e.sent_count} sent, ${e.failed_count} failed</span>` : ''}
                      ${isScheduled ? `<button class="btn-secondary" style="padding:4px 10px;font-size:12px;" onclick="campaignEditEvent(${e.id})">Edit</button><button class="btn-secondary" style="padding:4px 10px;font-size:12px;color:var(--red);border-color:rgba(255,80,80,.3);" onclick="campaignCancelEvent(${e.id},this)">Cancel</button>` : ''}
                      <span class="event-status ${statusClass}" id="eventStatus_${e.id}">${e.status}</span>
                    </div>
                  </div>
                  <div style="margin-top:8px;font-size:13px;color:rgba(255,255,255,.6);white-space:pre-wrap;max-height:60px;overflow:hidden;">${esc(e.body || '')}</div>
                  ${e.media_url ? _mediaPreview(e.media_url, 120) : ''}
                  <div id="eventEdit_${e.id}" style="display:none;"></div>
                </div>`;
              }).join('');
            }
          } catch { /* events fetch failed, show basic view */ }
        } else {
          // Non-compose campaigns: show body + stats from campaign row
          html += `<div style="background:rgba(0,0,0,.2);border-radius:8px;padding:12px;margin-bottom:16px;font-size:14px;white-space:pre-wrap;">${esc(data.body)}</div>`;
          if (data.media_url) html += '<div style="margin-bottom:16px;">' + _mediaPreview(data.media_url, 200) + '</div>';
          html += `<div class="campaign-stats" style="margin-bottom:16px;">
            <span>Recipients: <strong>${data.recipient_count}</strong></span>
            <span>Sent: <strong>${data.sent_count}</strong></span>
            <span style="color:var(--green);">Delivered: <strong>${data.delivered_count}</strong></span>
            <span style="color:var(--red);">Failed: <strong>${data.failed_count}</strong></span>
          </div>`;
        }

        if (data.messages && data.messages.length > 0) {
          html += '<h2 style="font-size:14px;">Message Log</h2>';
          html += data.messages.map(m => `
            <div class="msg-row">
              <div>${esc(m.customer_name || "Unknown")} <span style="color:var(--dim);">${esc(m.customer_phone)}</span></div>
              <div class="msg-status msg-${m.status}">${m.status}${m.error_code ? ` (${m.error_code})` : ""}</div>
            </div>
          `).join("");
        }

        campaignDetailBody.innerHTML = html;
      } catch {
        campaignDetailBody.innerHTML = '<div class="error">Failed to load campaign details.</div>';
      }
    };

    document.getElementById("btnCampaignClose").addEventListener("click", () => {
      campaignModal.classList.remove("open");
    });

    // Track which event edit is waiting for a library pick
    var _eventEditPickingFor = null;

    window.campaignEditEvent = function(eventId) {
      const container = document.getElementById("eventEdit_" + eventId);
      if (!container) return;
      const row = container.closest(".event-row");
      const bodyText = row.querySelector("div[style*='white-space:pre-wrap']")?.textContent || "";
      // Get current media URL from img or video element
      const mediaEl = row.querySelector("img, video");
      const mediaUrl = mediaEl ? mediaEl.src : "";

      container.style.display = "block";
      container.innerHTML = `
        <div style="margin-top:10px;padding:12px;background:rgba(0,0,0,.25);border-radius:8px;border:1px solid rgba(255,255,255,.1);">
          <label style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:4px;display:block;">Message Text</label>
          <textarea id="eventBody_${eventId}" style="width:100%;min-height:80px;font-size:14px;">${esc(bodyText)}</textarea>
          <input type="hidden" id="eventMedia_${eventId}" value="${esc(mediaUrl)}" />
          <label style="font-size:12px;color:rgba(255,255,255,.5);margin:10px 0 6px;display:block;">Media (optional)</label>
          <div id="eventMediaPreview_${eventId}" style="margin-bottom:8px;">
            ${mediaUrl ? _mediaPreview(mediaUrl, 160) : '<span style="font-size:12px;color:rgba(255,255,255,.3);">No media attached</span>'}
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn-secondary" style="padding:5px 12px;font-size:12px;" onclick="campaignEditPickLibrary(${eventId})">Choose from Library</button>
            <button class="btn-secondary" style="padding:5px 12px;font-size:12px;" onclick="campaignEditPickStudio(${eventId})">Create in Studio</button>
            ${mediaUrl ? `<button class="btn-secondary" style="padding:5px 12px;font-size:12px;color:var(--red);border-color:rgba(255,80,80,.3);" onclick="campaignEditRemoveMedia(${eventId})">Remove Media</button>` : ''}
          </div>
          <div style="margin-top:10px;display:flex;gap:8px;">
            <button class="btn-primary" style="padding:6px 16px;font-size:13px;" onclick="campaignSaveEvent(${eventId})">Save</button>
            <button class="btn-secondary" style="padding:6px 16px;font-size:13px;" onclick="document.getElementById('eventEdit_${eventId}').style.display='none'">Cancel</button>
          </div>
          <div id="eventEditError_${eventId}" class="error" style="display:none;margin-top:8px;"></div>
        </div>
      `;
    };

    window.campaignEditPickLibrary = function(eventId) {
      _eventEditPickingFor = eventId;
      _libBgPickerMode = false;
      _libBgPickerType = null;
      _libOpenOverlay(false);
    };

    window.campaignEditPickStudio = function(eventId) {
      // Close the campaign modal, open studio
      var modal = document.getElementById('campaignModal');
      if (modal) modal.classList.remove('open');
      switchToTab('studio');
    };

    window.campaignEditRemoveMedia = function(eventId) {
      document.getElementById('eventMedia_' + eventId).value = '';
      var preview = document.getElementById('eventMediaPreview_' + eventId);
      if (preview) preview.innerHTML = '<span style="font-size:12px;color:rgba(255,255,255,.3);">No media attached</span>';
      // Remove the "Remove Media" button
      var removeBtn = preview.parentElement.querySelector('button[onclick*="campaignEditRemoveMedia"]');
      if (removeBtn) removeBtn.remove();
    };

    // Called by media library when an item is picked — hook into _libRenderGrid click handler
    window._eventEditMediaPicked = function(url) {
      if (_eventEditPickingFor === null) return false;
      var eventId = _eventEditPickingFor;
      _eventEditPickingFor = null;
      document.getElementById('eventMedia_' + eventId).value = url;
      var preview = document.getElementById('eventMediaPreview_' + eventId);
      if (preview) preview.innerHTML = _mediaPreview(url, 160);
      // Ensure remove button exists
      var btns = preview.parentElement.querySelector('div[style*="flex-wrap"]');
      if (btns && !btns.querySelector('button[onclick*="campaignEditRemoveMedia"]')) {
        btns.insertAdjacentHTML('beforeend', `<button class="btn-secondary" style="padding:5px 12px;font-size:12px;color:var(--red);border-color:rgba(255,80,80,.3);" onclick="campaignEditRemoveMedia(${eventId})">Remove Media</button>`);
      }
      return true;
    };

    window.campaignSaveEvent = async function(eventId) {
      const body = document.getElementById("eventBody_" + eventId).value;
      const media_url = document.getElementById("eventMedia_" + eventId).value.trim();
      const errorEl = document.getElementById("eventEditError_" + eventId);

      try {
        const resp = await fetch(`${WORKER_BASE}/admin/promo/events/${eventId}`, {
          method: "PATCH",
          headers: authHeaders(),
          body: JSON.stringify({ body, media_url: media_url || null }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          errorEl.textContent = err.error || "Failed to save.";
          errorEl.style.display = "block";
          return;
        }
        // Refresh the campaign detail by re-opening it
        const campaignId = campaignDetailTitle.closest(".modal")?.querySelector("[data-campaign-id]")?.dataset.campaignId;
        // Find the campaign ID from the event row's parent context — just reload the modal
        const row = document.getElementById("eventEdit_" + eventId).closest(".event-row");
        const bodyDisplay = row.querySelector("div[style*='white-space:pre-wrap']");
        if (bodyDisplay) bodyDisplay.textContent = body;
        const existingMedia = row.querySelector("img, video");
        if (existingMedia) existingMedia.remove();
        if (media_url) {
          var afterEl = row.querySelector("div[style*='white-space:pre-wrap']");
          if (afterEl) afterEl.insertAdjacentHTML("afterend", _mediaPreview(media_url, 120));
        }
        document.getElementById("eventEdit_" + eventId).style.display = "none";
      } catch {
        errorEl.textContent = "Network error.";
        errorEl.style.display = "block";
      }
    };

    window.campaignCancelEvent = async function(eventId, btn) {
      if (!confirm("Cancel this scheduled message?")) return;
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/promo/events/${eventId}`, {
          method: "PATCH",
          headers: authHeaders(),
          body: JSON.stringify({ status: "cancelled" }),
        });
        if (!resp.ok) { alert("Failed to cancel."); return; }
        // Update UI inline
        const row = btn.closest(".event-row");
        const statusEl = document.getElementById("eventStatus_" + eventId);
        if (statusEl) { statusEl.textContent = "cancelled"; statusEl.className = "event-status event-cancelled"; }
        // Remove Edit/Cancel buttons
        row.querySelectorAll("button").forEach(b => b.remove());
        // Hide any open edit form
        var editEl = document.getElementById("eventEdit_" + eventId);
        if (editEl) editEl.style.display = "none";
      } catch { alert("Network error."); }
    };

    // ─── Send Mode Toggle ───
    // ─── Campaign Composer ───
    var composerMessages = [
      { body: '', mediaType: 'logo', mediaUrl: null, sendNow: true, sendAt: null, channels: { sms: true, email: true, facebook: false } }
    ];
    var composerActiveMessageIndex = null;
    var composerDraftId = null;
    var SMS_LOGO_URL = 'https://gkk-napa.com/assets/sms-logo.png';

    window.composerShowView = function(view) {
      if (view === 'studio') {
        // Show back link in Studio when coming from composer
        var backLink = document.getElementById('studioBackLink');
        if (backLink) backLink.style.display = '';
        switchToTab('studio');
      } else {
        composerShowComposer();
      }
    };

    // Show composer view (within campaigns tab)
    window.composerShowComposer = function() {
      document.getElementById('campaignListView').style.display = 'none';
      document.getElementById('composerView').style.display = 'block';
      composerUpdateRecipients();
    };

    // New Campaign button
    window.composerNewCampaign = function() {
      // Reset composer state
      composerMessages = [{ body: '', mediaType: 'logo', mediaUrl: null, sendNow: true, sendAt: null, channels: { sms: true, email: true, facebook: false } }];
      composerActiveMessageIndex = null;
      composerDraftId = null;
      var nameEl = document.getElementById('composerName');
      if (nameEl) nameEl.value = '';
      var devMode = document.getElementById('composerDevMode');
      if (devMode) { devMode.checked = false; document.getElementById('composerDevFields').style.display = 'none'; }
      var priority = document.getElementById('composerPriority');
      if (priority) priority.checked = false;
      composerShowError('');
      composerShowSuccess('');
      var draftStatus = document.getElementById('composerDraftStatus');
      if (draftStatus) draftStatus.style.display = 'none';
      composerRender();
      composerShowComposer();
    };

    // Back to campaign list
    window.composerBackToList = function() {
      document.getElementById('composerView').style.display = 'none';
      document.getElementById('campaignListView').style.display = 'block';
      loadCampaigns();
    };

    function composerRender() {
      var html = '';
      for (var i = 0; i < composerMessages.length; i++) {
        var msg = composerMessages[i];
        var isFirst = i === 0;
        html += '<div class="composer-msg-card" data-index="' + i + '">';
        html += '<div class="composer-msg-dot' + (isFirst ? '' : ' pending') + '"></div>';
        html += '<div class="composer-msg-header"><h3>Message ' + (i + 1) + '</h3>';
        if (!isFirst) html += '<button class="composer-msg-remove" onclick="composerRemoveMessage(' + i + ')" title="Remove">&times;</button>';
        html += '</div>';

        html += '<div class="composer-msg-layout">';

        // ── Left column: controls ──
        html += '<div class="composer-controls-col">';

        // Body
        html += '<label style="font-size:12px;font-weight:600;color:rgba(255,255,255,.6);">Message Text <span style="font-weight:400;color:rgba(255,255,255,.3);">(optional if media attached)</span></label>';
        html += '<textarea class="composer-msg-body" data-index="' + i + '" maxlength="1500" placeholder="Type your message..." style="min-height:80px;" oninput="composerUpdateBody(' + i + ',this)">' + (msg.body || '') + '</textarea>';
        var _segInfo = smsSegmentInfo((msg.body || '') + '\n— G&KK NAPA. Reply STOP to opt out. gkk-napa.com');
        var _segColor = _segInfo.segments > 1 ? (_segInfo.segments > 3 ? 'var(--red)' : 'var(--orange)') : 'rgba(255,255,255,.3)';
        html += '<div style="font-size:11px;color:rgba(255,255,255,.3);margin:2px 0 8px;">' + (msg.body || '').length + '/1,500 &mdash; <span style="color:' + _segColor + ';">' + _segInfo.segments + ' SMS segment' + (_segInfo.segments !== 1 ? 's' : '') + '</span> &mdash; "— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com" appended automatically</div>';

        // Media
        html += '<label style="font-size:12px;font-weight:600;color:rgba(255,255,255,.6);">Media</label>';
        html += '<div class="composer-media-btns">';
        html += '<button class="composer-media-btn' + (msg.mediaType === 'none' ? ' active' : '') + '" onclick="composerSetMedia(' + i + ',\'none\')">None</button>';
        html += '<button class="composer-media-btn' + (msg.mediaType === 'logo' ? ' active' : '') + '" onclick="composerSetMedia(' + i + ',\'logo\')">Logo</button>';
        html += '<button class="composer-media-btn' + (msg.mediaType === 'library' ? ' active' : '') + '" onclick="composerOpenLibrary(' + i + ')">Library</button>';
        html += '<button class="composer-media-btn' + (msg.mediaType === 'studio' ? ' active' : '') + '" onclick="composerOpenStudio(' + i + ')">Create in Studio</button>';
        html += '</div>';

        // Timing
        html += '<label style="font-size:12px;font-weight:600;color:rgba(255,255,255,.6);margin-top:10px;display:block;">Timing</label>';
        html += '<div class="composer-timing-row">';
        if (isFirst) {
          html += '<label><input type="radio" name="composerTiming0" value="now" style="width:auto;accent-color:var(--napa-yellow);"' + (msg.sendNow ? ' checked' : '') + ' onchange="composerSetTiming(' + i + ',true)"> Send Now</label>';
          html += '<label><input type="radio" name="composerTiming0" value="schedule" style="width:auto;accent-color:var(--napa-yellow);"' + (!msg.sendNow ? ' checked' : '') + ' onchange="composerSetTiming(' + i + ',false)"> Schedule</label>';
          if (!msg.sendNow) {
            html += '<input type="datetime-local" step="600" value="' + (msg.sendAt || '') + '" onchange="composerSetSendAt(' + i + ',this.value)" />';
          }
        } else {
          html += '<input type="datetime-local" step="600" value="' + (msg.sendAt || '') + '" onchange="composerSetSendAt(' + i + ',this.value)" />';
          html += '<span style="font-size:11px;color:rgba(255,255,255,.3);">Sent within 5 min of scheduled time</span>';
        }
        html += '</div>';

        // Channels
        var ch = msg.channels || { sms: true, email: false, facebook: false };
        var isPriority = document.getElementById('composerPriority') && document.getElementById('composerPriority').checked;
        var hasMedia = msg.mediaType !== 'none';
        html += '<label style="font-size:12px;font-weight:600;color:rgba(255,255,255,.6);margin-top:10px;display:block;">Channels</label>';
        html += '<div class="composer-media-btns">';
        html += '<button class="composer-media-btn' + (ch.sms ? ' active' : '') + '" onclick="composerToggleChannel(' + i + ',\'sms\')" title="Send as text message">SMS</button>';
        html += '<button class="composer-media-btn' + (ch.email ? ' active' : '') + '" onclick="composerToggleChannel(' + i + ',\'email\')" title="Send as email">Email</button>';
        if (!isPriority) {
          html += '<button class="composer-media-btn' + (ch.facebook ? ' active' : '') + '"' + (hasMedia ? '' : ' disabled title="Attach media to enable Facebook"') + ' onclick="composerToggleChannel(' + i + ',\'facebook\')" ' + (hasMedia ? 'title="Post to Facebook page"' : '') + '>Facebook</button>';
        }
        html += '</div>';

        html += '</div>'; // end controls col

        // ── Right column: preview + test send ──
        var mediaUrl = null;
        var isVideo = false;
        if (msg.mediaType === 'logo') mediaUrl = SMS_LOGO_URL;
        else if ((msg.mediaType === 'library' || msg.mediaType === 'studio') && msg.mediaUrl) {
          mediaUrl = msg.mediaUrl;
          isVideo = /\.(mp4|mov|webm|3gp)(\?|$)/i.test(msg.mediaUrl);
        }
        var hasBody = msg.body && msg.body.trim();
        var hasContent = hasBody || mediaUrl;

        html += '<div class="composer-preview-col">';
        html += '<div class="composer-preview-label">Preview</div>';
        html += '<div class="composer-phone" id="composerPhone' + i + '">';
        // Always show opt-out text bubble
        var bubbleText = hasBody ? (msg.body || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\n/g,'<br>') + '<br><br><span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>' : '<span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>';
        html += '<div class="composer-phone-bubble">' + bubbleText + '</div>';
        if (isVideo && mediaUrl) {
          html += '<div class="composer-phone-media"><video src="' + mediaUrl + '" controls playsinline style="width:100%;display:block;border-radius:10px;"></video></div>';
        } else if (mediaUrl) {
          html += '<div class="composer-phone-media"><img src="' + mediaUrl + '" alt="Media" /></div>';
        }
        html += '</div>'; // end phone

        // Test send — below preview
        html += '<div class="composer-test-row">';
        html += '<input type="text" id="composerTestDest' + i + '" placeholder="Phone or email" style="width:auto;" />';
        html += '<button id="composerTestBtn' + i + '" class="btn-secondary" style="flex-shrink:0;padding:8px 14px;font-size:12px;" onclick="composerTestSend(' + i + ')"' + (hasContent ? '' : ' disabled') + '>Send Test</button>';
        html += '</div>';

        html += '</div>'; // end preview col

        html += '</div>'; // end layout
        html += '</div>'; // end card
      }
      document.getElementById('composerTimeline').innerHTML = html;
    }

    window.composerAddMessage = function() {
      // Default schedule to 2 days after last message
      var lastMsg = composerMessages[composerMessages.length - 1];
      var defaultDate = '';
      if (lastMsg.sendAt) {
        var d = new Date(lastMsg.sendAt);
        d.setDate(d.getDate() + 2);
        defaultDate = d.toISOString().slice(0, 16);
      }
      composerMessages.push({ body: '', mediaType: 'none', mediaUrl: null, sendNow: false, sendAt: defaultDate, channels: { sms: true, email: true, facebook: false } });
      composerRender();
    };

    window.composerRemoveMessage = function(index) {
      if (composerMessages.length <= 1) return;
      composerMessages.splice(index, 1);
      composerRender();
    };

    function composerUpdatePreview(index) {
      var phone = document.getElementById('composerPhone' + index);
      var testBtn = document.getElementById('composerTestBtn' + index);
      if (!phone) return;
      var msg = composerMessages[index];
      var mediaUrl = null;
      var isVideo = false;
      if (msg.mediaType === 'logo') mediaUrl = SMS_LOGO_URL;
      else if ((msg.mediaType === 'library' || msg.mediaType === 'studio') && msg.mediaUrl) {
        mediaUrl = msg.mediaUrl;
        isVideo = /\.(mp4|mov|webm|3gp)(\?|$)/i.test(msg.mediaUrl);
      }
      var hasBody = msg.body && msg.body.trim();
      var hasContent = hasBody || mediaUrl;
      var h = '';
      // Always show opt-out bubble
      var bubbleText = hasBody ? msg.body.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\n/g,'<br>') + '<br><br><span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>' : '<span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>';
      h += '<div class="composer-phone-bubble">' + bubbleText + '</div>';
      if (isVideo && mediaUrl) {
        h += '<div class="composer-phone-media"><video src="' + mediaUrl + '" controls playsinline style="width:100%;display:block;border-radius:10px;"></video></div>';
      } else if (mediaUrl) {
        h += '<div class="composer-phone-media"><img src="' + mediaUrl + '" alt="Media" /></div>';
      }
      phone.innerHTML = h;
      if (testBtn) testBtn.disabled = !hasContent;
    }

    window.composerUpdateBody = function(index, el) {
      composerMessages[index].body = el.value;
      // Fast-path: update just the text bubble without rebuilding media (avoids video reload)
      var phone = document.getElementById('composerPhone' + index);
      if (phone) {
        var bubble = phone.querySelector('.composer-phone-bubble');
        var media = phone.querySelector('.composer-phone-media');
        if (media && el.value.trim()) {
          // Media exists — just update or insert the text bubble
          var escaped = el.value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\n/g,'<br>');
          var html = escaped + '<br><br>— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com';
          if (bubble) {
            bubble.innerHTML = html;
          } else {
            var div = document.createElement('div');
            div.className = 'composer-phone-bubble';
            div.innerHTML = html;
            phone.insertBefore(div, phone.firstChild);
          }
          return;
        } else if (media && !el.value.trim()) {
          // Body cleared but media exists — show just the opt-out text
          if (bubble) {
            bubble.innerHTML = '<span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>';
          } else {
            var div = document.createElement('div');
            div.className = 'composer-phone-bubble';
            div.innerHTML = '<span style="font-size:11px;color:rgba(255,255,255,.4);">— G&amp;KK NAPA. Reply STOP to opt out. gkk-napa.com</span>';
            phone.insertBefore(div, phone.firstChild);
          }
          return;
        }
      }
      // Fallback: full rebuild (no media, or structural change needed)
      composerUpdatePreview(index);
    };

    window.composerSetMedia = function(index, type) {
      composerMessages[index].mediaType = type;
      if (type === 'logo') composerMessages[index].mediaUrl = SMS_LOGO_URL;
      else if (type === 'none') {
        composerMessages[index].mediaUrl = null;
        // Disable Facebook when no media
        if (composerMessages[index].channels) composerMessages[index].channels.facebook = false;
      }
      composerRender();
    };

    window.composerToggleChannel = function(index, channel) {
      var msg = composerMessages[index];
      if (!msg.channels) msg.channels = { sms: true, email: false, facebook: false };
      msg.channels[channel] = !msg.channels[channel];
      composerUpdateRecipients();
      composerRender();
    };

    window.composerOpenStudio = function(index) {
      composerActiveMessageIndex = index;
      composerMessages[index].mediaType = 'studio';
      composerShowView('studio');
    };


    window.composerToggleDev = function() {
      var on = document.getElementById('composerDevMode').checked;
      document.getElementById('composerDevFields').style.display = on ? '' : 'none';
      composerUpdateRecipients();
    };

    window.composerSetTiming = function(index, sendNow) {
      composerMessages[index].sendNow = sendNow;
      composerMessages[index].sendAt = null;
      composerRender();
    };

    window.composerSetSendAt = function(index, val) {
      composerMessages[index].sendAt = val;
    };

    window.composerTestSend = function(index) {
      var msg = composerMessages[index];
      var btn = document.getElementById('composerTestBtn' + index);
      var dest = (document.getElementById('composerTestDest' + index).value || '').trim();
      if (!dest) { showToast('Enter a phone number or email.', 'error', btn); return; }
      var mediaUrl = null;
      if (msg.mediaType === 'logo') mediaUrl = SMS_LOGO_URL;
      else if ((msg.mediaType === 'library' || msg.mediaType === 'studio') && msg.mediaUrl) mediaUrl = msg.mediaUrl;

      var isEmail = dest.indexOf('@') !== -1;

      if (isEmail) {
        fetch(WORKER_BASE + '/admin/send-test-email', {
          method: 'POST',
          headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
          body: JSON.stringify({ email: dest, sms_text: msg.body, image_url: mediaUrl, subject: 'G&KK NAPA - SAVINGS ALERT!' })
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.error) showToast('Test failed: ' + data.error, 'error', btn);
          else showToast('Test email sent to ' + dest, 'success', btn);
        }).catch(function(e) { showToast('Error: ' + e.message, 'error', btn); });
      } else {
        fetch(WORKER_BASE + '/admin/send-test', {
          method: 'POST',
          headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
          body: JSON.stringify({ body: msg.body, phone: dest, image_url: mediaUrl })
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.error) showToast('Test failed: ' + data.error, 'error', btn);
          else showToast('Test SMS sent!', 'success', btn);
        }).catch(function(e) { showToast('Error: ' + e.message, 'error', btn); });
      }
    };

    window.composerUpdateRecipients = function() {
      var devMode = document.getElementById('composerDevMode').checked;
      var priority = document.getElementById('composerPriority').checked;

      // Derive channel flags from per-message channels
      var anySms = composerMessages.some(function(m) { return m.channels && m.channels.sms; });
      var anyEmail = composerMessages.some(function(m) { return m.channels && m.channels.email; });

      if (devMode) {
        document.getElementById('composerSmsNum').textContent = anySms ? '1' : '0';
        document.getElementById('composerEmailNum').textContent = anyEmail ? '1' : '0';
        return;
      }

      // SMS count (subscribed)
      if (anySms) {
        var smsUrl = WORKER_BASE + '/admin/customers?count_only=1&status=subscribed';
        if (priority) smsUrl += '&priority_only=1';
        fetch(smsUrl, { headers: authHeaders() }).then(function(r) { return r.json(); }).then(function(data) {
          document.getElementById('composerSmsNum').textContent = data.count || 0;
        }).catch(function() {});
      } else {
        document.getElementById('composerSmsNum').textContent = '0';
      }

      // Email count (all customers with email)
      if (anyEmail) {
        var emailUrl = WORKER_BASE + '/admin/customers?count_only=1&has_email=1';
        if (priority) emailUrl += '&priority_only=1';
        fetch(emailUrl, { headers: authHeaders() }).then(function(r) { return r.json(); }).then(function(data) {
          document.getElementById('composerEmailNum').textContent = data.count || 0;
        }).catch(function() {});
      } else {
        document.getElementById('composerEmailNum').textContent = '0';
      }

      // If priority is checked, disable Facebook on all messages
      if (priority) {
        composerMessages.forEach(function(m) {
          if (m.channels) m.channels.facebook = false;
        });
      }
    };

    window.composerViewList = function(type) {
      var priority = document.getElementById('composerPriority').checked;
      var url = WORKER_BASE + '/admin/customers?status=' + (type === 'sms' ? 'subscribed' : 'all');
      if (type === 'email') url = WORKER_BASE + '/admin/customers?has_email=1';
      if (priority) url += '&priority_only=1';

      var overlay = document.createElement('div');
      overlay.className = 'lib-overlay';
      overlay.innerHTML =
        '<div class="lib-panel" style="max-width:500px;">' +
          '<div class="lib-header"><h3 style="margin:0;font-size:16px;">' + (type === 'sms' ? 'SMS Recipients' : 'Email Recipients') + '</h3>' +
          '<button class="lib-close" onclick="this.closest(\'.lib-overlay\').remove()">&times;</button></div>' +
          '<div id="composerListBody" style="padding:16px 24px;overflow-y:auto;flex:1;"><div style="text-align:center;color:rgba(255,255,255,.4);padding:20px;">Loading...</div></div>' +
        '</div>';
      overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
      document.body.appendChild(overlay);

      fetch(url, { headers: authHeaders() }).then(function(r) { return r.json(); }).then(function(customers) {
        var body = document.getElementById('composerListBody');
        if (!customers.length) { body.innerHTML = '<div style="text-align:center;color:rgba(255,255,255,.4);padding:20px;">No recipients found.</div>'; return; }
        var html = '<div style="font-size:12px;color:rgba(255,255,255,.35);margin-bottom:8px;">' + customers.length + ' recipient' + (customers.length !== 1 ? 's' : '') + '</div>';
        html += '<table style="width:100%;font-size:13px;border-collapse:collapse;">';
        html += '<tr style="border-bottom:1px solid rgba(255,255,255,.1);"><th style="text-align:left;padding:6px 8px;color:rgba(255,255,255,.5);font-weight:600;">Name</th><th style="text-align:left;padding:6px 8px;color:rgba(255,255,255,.5);font-weight:600;">' + (type === 'sms' ? 'Phone' : 'Email') + '</th></tr>';
        customers.forEach(function(c) {
          var detail = type === 'sms' ? (c.phone || '') : (c.email || '');
          html += '<tr style="border-bottom:1px solid rgba(255,255,255,.05);"><td style="padding:6px 8px;">' + (c.name || 'Unknown') + '</td><td style="padding:6px 8px;color:rgba(255,255,255,.6);">' + detail + '</td></tr>';
        });
        html += '</table>';
        body.innerHTML = html;
      }).catch(function() {
        document.getElementById('composerListBody').innerHTML = '<div style="color:var(--red);padding:20px;">Failed to load list.</div>';
      });
    };

    // ─── Toast notification system ──────────────────────────
    // showToast(message, type, anchor)
    //   anchor: optional DOM element or element ID string — toast appears next to it
    //           if omitted, falls back to fixed top-right corner

    window.composerSubmit = function() {
      var name = document.getElementById('composerName').value.trim();
      if (!name) { composerShowError('Campaign name is required.'); return; }

      var apiMessages = [];
      var anyChannel = false;
      var anyFacebook = false;
      for (var i = 0; i < composerMessages.length; i++) {
        var msg = composerMessages[i];
        var ch = msg.channels || { sms: true, email: false, facebook: false };
        var mediaUrl = null;
        if (msg.mediaType === 'logo') mediaUrl = SMS_LOGO_URL;
        else if ((msg.mediaType === 'library' || msg.mediaType === 'studio') && msg.mediaUrl) mediaUrl = msg.mediaUrl;

        var hasBody = msg.body && msg.body.trim();
        if (!ch.sms && !ch.email && !ch.facebook) { composerShowError('Message ' + (i + 1) + ' needs at least one channel selected.'); return; }
        if (!hasBody && !mediaUrl) { composerShowError('Message ' + (i + 1) + ' needs text or media.'); return; }
        if (i > 0 && !msg.sendAt) { composerShowError('Message ' + (i + 1) + ' needs a scheduled time.'); return; }
        if (i === 0 && !msg.sendNow && !msg.sendAt) { composerShowError('Message 1 needs a scheduled time or "Send Now".'); return; }

        if (ch.sms || ch.email) anyChannel = true;
        if (ch.facebook) anyFacebook = true;

        var sendAt = null;
        if (!msg.sendNow && msg.sendAt) sendAt = new Date(msg.sendAt).toISOString();

        apiMessages.push({ body: msg.body || '', media_url: mediaUrl, send_now: i === 0 && msg.sendNow, send_at: sendAt, channels: ch });
      }

      var devMode = document.getElementById('composerDevMode').checked;
      var devPhone = (document.getElementById('composerDevPhone').value || '').trim();
      var devEmail = (document.getElementById('composerDevEmail').value || '').trim();

      if (devMode && !devPhone && !devEmail) { composerShowError('Test Mode: enter a phone number or email.'); return; }

      // Derive campaign-level flags from per-message channels
      var showSms = apiMessages.some(function(m) { return m.channels.sms; });
      var showEmail = apiMessages.some(function(m) { return m.channels.email; });

      // Build review summary
      var smsCount = document.getElementById('composerSmsNum').textContent || '0';
      var emailCount = document.getElementById('composerEmailNum').textContent || '0';
      var sendNowCount = apiMessages.filter(function(m) { return m.send_now; }).length;
      var schedCount = apiMessages.length - sendNowCount;

      var html = '';
      if (devMode) {
        html += '<div style="background:rgba(255,200,0,.08);border:1px dashed rgba(255,200,0,.3);border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:13px;color:#f59e0b;">Test Mode — sending only to you</div>';
      }
      html += '<div class="review-row"><span class="review-label">Campaign</span><span class="review-value">' + esc(name) + '</span></div>';
      if (devMode) {
        if (devPhone) html += '<div class="review-row"><span class="review-label">Test SMS to</span><span style="color:#fff;">' + esc(devPhone) + '</span></div>';
        if (devEmail) html += '<div class="review-row"><span class="review-label">Test email to</span><span style="color:#fff;">' + esc(devEmail) + '</span></div>';
      } else {
        if (showSms) html += '<div class="review-row"><span class="review-label">SMS recipients</span><span class="review-value">' + smsCount + '</span></div>';
        if (showEmail) html += '<div class="review-row"><span class="review-label">Email recipients</span><span class="review-value">' + emailCount + '</span></div>';
      }
      if (anyFacebook) {
        html += '<div class="review-row"><span class="review-label">Facebook</span><span class="review-value" style="color:#4267B2;">Will post to page</span></div>';
      }
      html += '<div class="review-row"><span class="review-label">Messages</span><span style="color:#fff;">' + apiMessages.length + ' (' + (sendNowCount > 0 ? sendNowCount + ' now' : '') + (sendNowCount > 0 && schedCount > 0 ? ', ' : '') + (schedCount > 0 ? schedCount + ' scheduled' : '') + ')</span></div>';

      // Message summaries
      for (var j = 0; j < apiMessages.length; j++) {
        var am = apiMessages[j];
        var timing = am.send_now ? 'Send immediately' : new Date(am.send_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
        var channelTags = [];
        if (am.channels.sms) channelTags.push('SMS');
        if (am.channels.email) channelTags.push('Email');
        if (am.channels.facebook) channelTags.push('Facebook');
        html += '<div class="review-msg-card">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;"><strong style="color:var(--napa-yellow);">Message ' + (j + 1) + '</strong><span style="font-size:12px;color:rgba(255,255,255,.4);">' + timing + '</span></div>';
        html += '<div style="font-size:11px;color:rgba(255,255,255,.4);margin:4px 0;">' + channelTags.join(' &middot; ') + '</div>';
        if (am.body) html += '<div class="review-msg-body">' + esc(am.body) + '</div>';
        if (am.media_url) html += '<div style="margin-top:4px;font-size:12px;color:rgba(255,255,255,.4);">+ media attached</div>';
        html += '</div>';
      }

      if (schedCount > 0) {
        html += '<div style="margin-top:12px;font-size:12px;color:rgba(255,255,255,.4);">Scheduled messages can be viewed and edited in the <strong style="color:var(--napa-yellow);">Campaigns</strong> tab before they go out.</div>';
      }

      document.getElementById('campaignReviewBody').innerHTML = html;
      var reviewModal = document.getElementById('campaignReviewModal');
      reviewModal.classList.add('open');

      // Store payload for confirm
      reviewModal._payload = {
        name: devMode ? '[TEST] ' + name : name,
        email_subject: 'G&KK NAPA - SAVINGS ALERT!',
        priority_only: document.getElementById('composerPriority').checked,
        sms_enabled: showSms,
        email_fallback: showEmail,
        email_only: showEmail && !showSms,
        messages: apiMessages
      };
      if (composerDraftId) reviewModal._payload.draft_id = composerDraftId;
      if (devMode) {
        reviewModal._payload.dev_mode = true;
        if (devPhone) reviewModal._payload.dev_phone = devPhone;
        if (devEmail) reviewModal._payload.dev_email = devEmail;
      }
    };

    document.getElementById('btnReviewCancel').addEventListener('click', function() {
      document.getElementById('campaignReviewModal').classList.remove('open');
    });

    document.getElementById('btnReviewConfirm').addEventListener('click', function() {
      var reviewModal = document.getElementById('campaignReviewModal');
      var payload = reviewModal._payload;
      if (!payload) return;

      var btn = document.getElementById('btnReviewConfirm');
      btn.disabled = true; btn.textContent = 'Sending...';
      composerShowError(''); composerShowSuccess('');

      fetch(WORKER_BASE + '/admin/campaign-compose', {
        method: 'POST',
        headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { reviewModal.classList.remove('open'); composerShowError(data.error); return; }

        // Fire Facebook posts for messages with facebook channel enabled
        var fbPromises = [];
        payload.messages.forEach(function(m) {
          if (!m.channels || !m.channels.facebook || !m.media_url) return;
          var isVideo = /\.(mp4|mov|webm|3gp)(\?|$)/i.test(m.media_url);
          var fbPayload = { message: m.body || '' };
          if (isVideo) fbPayload.video_url = m.media_url;
          else fbPayload.image_url = m.media_url;
          // If scheduled (not send_now), pass the scheduled time to Facebook
          if (m.send_at && !m.send_now) fbPayload.scheduled_time = m.send_at;
          fbPromises.push(
            fetch(WORKER_BASE + '/admin/facebook/post', {
              method: 'POST',
              headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
              body: JSON.stringify(fbPayload)
            }).then(function(r) { return r.json(); })
          );
        });

        return Promise.all(fbPromises).then(function(fbResults) {
          reviewModal.classList.remove('open');
          var msg = 'Campaign created!';
          if (data.sent > 0) msg += ' Sent to ' + data.sent + ' subscribers.';
          if (data.email_queued > 0) msg += ' ' + data.email_queued + ' emails queued — sending shortly.';
          if (data.scheduled > 0) msg += ' ' + data.scheduled + ' message(s) scheduled.';
          // Report Facebook results
          var fbOk = fbResults.filter(function(r) { return r && r.ok; }).length;
          var fbFail = fbResults.filter(function(r) { return r && !r.ok; }).length;
          if (fbOk > 0) msg += ' Posted to Facebook.';
          if (fbFail > 0) msg += ' Facebook post failed (' + fbFail + ').';
          composerShowSuccess(msg);
          showToast(msg, 'success', 'btnReviewConfirm');
          // Reset composer
          composerMessages = [{ body: '', mediaType: 'logo', mediaUrl: null, sendNow: true, sendAt: null, channels: { sms: true, email: true, facebook: false } }];
          composerDraftId = null;
          document.getElementById('composerName').value = '';
          document.getElementById('composerDraftStatus').style.display = 'none';
          composerRender();
        });
      }).catch(function(e) {
        reviewModal.classList.remove('open');
        composerShowError('Error: ' + e.message);
      }).finally(function() {
        btn.disabled = false; btn.textContent = 'Confirm & Send';
      });
    });

    window.composerSaveDraft = function() {
      var name = document.getElementById('composerName').value.trim();
      if (!name) { composerShowError('Campaign name is required to save a draft.'); return; }

      var draftMessages = [];
      for (var i = 0; i < composerMessages.length; i++) {
        var msg = composerMessages[i];
        var mediaUrl = null;
        if (msg.mediaType === 'logo') mediaUrl = SMS_LOGO_URL;
        else if ((msg.mediaType === 'library' || msg.mediaType === 'studio') && msg.mediaUrl) mediaUrl = msg.mediaUrl;
        draftMessages.push({ body: msg.body || '', media_url: mediaUrl, media_type: msg.mediaType, send_now: i === 0 && msg.sendNow, send_at: msg.sendAt || null, channels: msg.channels || { sms: true, email: false, facebook: false } });
      }

      // Derive email flags from per-message channels
      var anySms = composerMessages.some(function(m) { return m.channels && m.channels.sms; });
      var anyEmail = composerMessages.some(function(m) { return m.channels && m.channels.email; });

      var payload = {
        name: name,
        messages: draftMessages,
        priority_only: document.getElementById('composerPriority').checked,
        email_fallback: anyEmail,
        email_only: anyEmail && !anySms,
        email_subject: 'G&KK NAPA - SAVINGS ALERT!',
        dev_mode: document.getElementById('composerDevMode').checked,
        dev_phone: (document.getElementById('composerDevPhone').value || '').trim(),
        dev_email: (document.getElementById('composerDevEmail').value || '').trim()
      };
      if (composerDraftId) payload.draft_id = composerDraftId;

      var btn = document.getElementById('composerDraftBtn');
      btn.disabled = true; btn.textContent = 'Saving...';
      composerShowError('');

      fetch(WORKER_BASE + '/admin/campaign-draft', {
        method: 'POST',
        headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { composerShowError(data.error); return; }
        composerDraftId = data.draft_id;
        var statusEl = document.getElementById('composerDraftStatus');
        statusEl.textContent = 'Draft saved — ' + new Date().toLocaleTimeString();
        statusEl.style.display = 'block';
        showToast('Draft saved', 'success', btn);
      }).catch(function(e) {
        composerShowError('Error saving draft: ' + e.message);
      }).finally(function() {
        btn.disabled = false; btn.textContent = 'Save Draft';
      });
    };

    function composerShowError(msg) {
      var el = document.getElementById('composerError');
      el.textContent = msg; el.style.display = msg ? 'block' : 'none';
    }
    function composerShowSuccess(msg) {
      var el = document.getElementById('composerSuccess');
      el.textContent = msg; el.style.display = msg ? 'block' : 'none';
    }

    // Attach studio-generated image to composer
    window.csAttachToComposer = function(url) {
      // If opened from composer, attach to that message
      var idx = composerActiveMessageIndex;
      if (idx === null) {
        // Standalone studio — attach to first message
        idx = 0;
      }
      composerMessages[idx].mediaType = 'studio';
      composerMessages[idx].mediaUrl = url;
      composerActiveMessageIndex = null;
      composerRender();
      // Switch to campaigns tab and show composer
      switchToTab('campaigns');
      composerShowComposer();
    };

    // Initialize composer on load
    composerRender();
