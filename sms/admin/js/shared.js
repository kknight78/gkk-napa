// ═══ shared.js — Constants, Auth, Tabs, Modals, Utilities ═══

    const WORKER_BASE = "https://gkk-napa-sms.kellyraeknight78.workers.dev";

    const STORE_NAMES = {
      danville: "Danville, IL",
      cayuga: "Cayuga, IN",
      rockville: "Rockville, IN",
      covington: "Covington, IN",
    };

    const STATUS_BADGE = {
      subscribed: '<span class="badge badge-subscribed">Subscribed</span>',
      invited: '<span class="badge badge-invited">Invited</span>',
      stopped: '<span class="badge badge-stopped">Stopped</span>',
      none: '<span class="badge badge-none">None</span>',
    };

    const TWILIO_ERRORS = { "30003": "Unreachable", "30004": "Blocked", "30005": "Unknown #", "30006": "Landline", "30007": "Carrier violation", "21610": "Opted out" };

    let authToken = "";
    let allCustomers = [];

    // ─── Two-level tab navigation ────────────────────────────
    window.switchToTab = function(tabName, filters) {
      // Hide all panels
      document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });

      // Determine section
      var isMessaging = ['campaigns', 'studio', 'library'].includes(tabName);

      // Top nav
      document.querySelectorAll('#topNav .tab').forEach(function(t) { t.classList.remove('active'); });
      var topBtn = document.querySelector('#topNav .tab[data-section="' + (isMessaging ? 'messaging' : 'customers') + '"]');
      if (topBtn) topBtn.classList.add('active');

      // Sub-nav visibility + highlight
      document.getElementById('subNav').style.display = isMessaging ? 'flex' : 'none';
      if (isMessaging) {
        document.querySelectorAll('#subNav .tab').forEach(function(t) { t.classList.remove('active'); });
        var subBtn = document.querySelector('#subNav .tab[data-tab="' + tabName + '"]');
        if (subBtn) subBtn.classList.add('active');
      }

      // Show target panel
      var panel = document.getElementById('tab-' + tabName);
      if (panel) panel.classList.add('active');

      // Data refresh
      if (tabName === 'customers') {
        if (filters && filters.status) document.getElementById('filterStatus').value = filters.status;
        loadDashboard();
        loadCustomers();
      }
      if (tabName === 'campaigns') { loadCampaigns(); }
      if (tabName === 'library') { loadLibraryStandalone(); }
      if (tabName === 'studio') { setTimeout(csScaleCanvas, 50); }
    };

    // ─── Auth ────────────────────────────────────────────────
    function authHeaders() {
      return { "Content-Type": "application/json", Authorization: `Bearer ${authToken}` };
    }

    const loginScreen = document.getElementById("loginScreen");
    const adminScreen = document.getElementById("adminScreen");
    const passwordEl = document.getElementById("password");
    const btnLogin = document.getElementById("btnLogin");
    const loginError = document.getElementById("loginError");

    btnLogin.addEventListener("click", async () => {
      loginError.style.display = "none";
      const pw = passwordEl.value.trim();
      if (!pw) { loginError.textContent = "Please enter a password."; loginError.style.display = "block"; return; }

      authToken = pw;
      try {
        const resp = await fetch(`${WORKER_BASE}/admin/login`, { method: "POST", headers: authHeaders() });
        if (!resp.ok) {
          authToken = "";
          loginError.textContent = "Invalid password.";
          loginError.style.display = "block";
          return;
        }
        loginScreen.style.display = "none";
        adminScreen.style.display = "block";
        switchToTab('campaigns');
      } catch {
        authToken = "";
        loginError.textContent = "Could not connect to server.";
        loginError.style.display = "block";
      }
    });

    passwordEl.addEventListener("keydown", (e) => { if (e.key === "Enter") btnLogin.click(); });

    // ─── Top nav click handlers ─────────────────────────────
    document.querySelectorAll('#topNav .tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        if (tab.dataset.section === 'messaging') {
          switchToTab('campaigns');
        } else if (tab.dataset.section === 'customers') {
          switchToTab('customers');
        }
      });
    });

    // ─── Sub-nav click handlers ──────────────────────────────
    document.querySelectorAll('#subNav .tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        switchToTab(tab.dataset.tab);
      });
    });

    // ─── Modal helpers (called after DOM + other scripts load) ───
    function initModals() {
      var allModals = [
        document.getElementById('customerModal'),
        document.getElementById('campaignModal'),
        document.getElementById('inviteModal'),
        document.getElementById('campaignReviewModal')
      ];
      // Close modals on overlay click
      allModals.forEach(function(modal) {
        if (!modal) return;
        modal.addEventListener("click", function(e) {
          if (e.target === modal) modal.classList.remove("open");
        });
      });

      // Escape key closes topmost modal/overlay
      document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;
        var overlays = [
          document.getElementById('csTextEditOverlay'),
          document.getElementById('csProductEditOverlay'),
          document.getElementById('csCropperOverlay'),
          document.getElementById('campaignReviewModal'),
          document.getElementById('inviteModal'),
          document.getElementById('customerModal'),
          document.getElementById('campaignModal'),
        ];
        var libOverlay = document.querySelector('.lib-overlay');
        if (libOverlay) { libOverlay.remove(); return; }
        for (var i = 0; i < overlays.length; i++) {
          if (overlays[i] && (overlays[i].classList.contains('open'))) {
            overlays[i].classList.remove('open');
            return;
          }
        }
      });

      // Focus trapping
      allModals.forEach(function(modal) { if (modal) trapFocus(modal); });
    }

    function trapFocus(modal) {
      var focusable = modal.querySelectorAll('button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])');
      if (focusable.length === 0) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      modal.addEventListener('keydown', function(e) {
        if (e.key !== 'Tab') return;
        if (e.shiftKey) {
          if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
          if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      });
    }

    function showToast(message, type, anchor) {
      type = type || 'success';
      var el = typeof anchor === 'string' ? document.getElementById(anchor) : anchor;
      var toast = document.createElement('div');
      toast.className = 'toast ' + type;
      toast.textContent = message;
      document.body.appendChild(toast);

      if (el) {
        var rect = el.getBoundingClientRect();
        var tW = toast.offsetWidth;
        // Position above the anchor, centered horizontally
        var left = rect.left + rect.width / 2 - tW / 2;
        var top = rect.top - toast.offsetHeight - 8 + window.scrollY;
        // Keep on screen
        if (left < 8) left = 8;
        if (left + tW > window.innerWidth - 8) left = window.innerWidth - tW - 8;
        if (top < 8 + window.scrollY) top = rect.bottom + 8 + window.scrollY;
        toast.style.left = left + 'px';
        toast.style.top = top + 'px';
      } else {
        // Fallback: fixed top-right
        toast.style.position = 'fixed';
        toast.style.top = '20px';
        toast.style.right = '20px';
      }

      setTimeout(function() {
        toast.classList.add('fadeout');
        setTimeout(function() { toast.remove(); }, 300);
      }, 4000);
    }

    // ─── SMS Segment Calculator ─────────────────────────────
    function smsSegmentInfo(text) {
      if (!text) return { chars: 0, segments: 0, limit: 160 };
      // Check if GSM-7 or UCS-2
      var gsm7 = /^[\x20-\x7E\n\r]*$/.test(text); // simplified GSM check
      var charLimit = gsm7 ? 160 : 70;
      var concatLimit = gsm7 ? 153 : 67;
      var len = text.length;
      var segments;
      if (len <= charLimit) segments = 1;
      else segments = Math.ceil(len / concatLimit);
      return { chars: len, segments: segments, limit: charLimit };
    }

    // ─── Phone formatting ──────────────────────────────────────
    function formatPhone(value) {
      let digits = value.replace(/\D/g, "");
      if (digits.length === 11 && digits.startsWith("1")) digits = digits.slice(1);
      digits = digits.slice(0, 10);
      if (digits.length <= 3) return digits;
      if (digits.length <= 6) return `(${digits.slice(0, 3)}) ${digits.slice(3)}`;
      return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
    }

    // ─── Subscribe URL (HMAC-SHA256, matches worker logic) ──
    async function generateSubscribeToken(customerId) {
      const payload = `subscribe:${customerId}`;
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(authToken),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
      const hmac = btoa(String.fromCharCode(...new Uint8Array(sig)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      return btoa(`${customerId}:${hmac}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    // ─── Utility ─────────────────────────────────────────────
    function esc(str) {
      if (!str) return "";
      const d = document.createElement("div");
      d.textContent = str;
      return d.innerHTML;
    }
