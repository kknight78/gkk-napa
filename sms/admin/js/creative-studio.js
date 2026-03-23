// ═══ creative-studio.js — Creative Studio Builder ═══

    // ═══════════════════════════════════════════════════════════
    // Creative Studio v4 — Guided MMS Image Builder
    // ═══════════════════════════════════════════════════════════

    const CS_BRAND_GRAPHICS = [
      // Blue — file defaults to id if not set
      // allowsPhoto = can use uploaded/library photo bg; allowsBolt = can use bolt graphic bg; allowsVideo = can use video bg
      { id: 'blue-top-chevron',    color: 'blue',  position: 'top',    allowsPhoto: false, allowsBolt: true,  allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'blue-bottom-chevron', color: 'blue',  position: 'bottom', allowsPhoto: false, allowsBolt: true,  allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'blue-top-half',       color: 'blue',  position: 'top',    allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 598, h: 800, x: 0, y: 0 },
      { id: 'blue-top-ramp',       color: 'blue',  position: 'top',    allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 640, h: 336, x: 0, y: 0 },
      { id: 'blue-bottom-dip',     color: 'blue',  position: 'bottom', allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 640, h: 306, x: 0, y: 494 },
      { id: 'blue-top-badge',      color: 'blue',  position: 'top',    allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 418.45, h: 131, x: 110.78, y: 0, file: 'blue-both-badge' },
      { id: 'blue-bottom-badge',   color: 'blue',  position: 'bottom', allowsPhoto: true,  allowsBolt: false, allowsVideo: true,  w: 418.45, h: 131, x: 110.78, y: 669, vw: 294, vh: 92, vx: 78, vy: 695, file: 'blue-both-badge' },
      { id: 'blue-top-corner',     color: 'blue',  position: 'top',    allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'blue-bottom-corner',  color: 'blue',  position: 'bottom', allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      // Black
      { id: 'black-top-chevron',    color: 'black', position: 'top',    allowsPhoto: false, allowsBolt: true,  allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'black-bottom-chevron', color: 'black', position: 'bottom', allowsPhoto: false, allowsBolt: true,  allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'black-top-half',       color: 'black', position: 'top',    allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 598, h: 800, x: 0, y: 0 },
      { id: 'black-top-ramp',       color: 'black', position: 'top',    allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 640, h: 336, x: 0, y: 0 },
      { id: 'black-bottom-dip',     color: 'black', position: 'bottom', allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 640, h: 306, x: 0, y: 494 },
      { id: 'black-top-badge',      color: 'black', position: 'top',    allowsPhoto: true,  allowsBolt: false, allowsVideo: false, w: 418.45, h: 131, x: 110.78, y: 0, file: 'black-both-badge' },
      { id: 'black-bottom-badge',   color: 'black', position: 'bottom', allowsPhoto: true,  allowsBolt: false, allowsVideo: true,  w: 418.45, h: 131, x: 110.78, y: 669, vw: 294, vh: 92, vx: 78, vy: 695, file: 'black-both-badge' },
      { id: 'black-top-corner',     color: 'black', position: 'top',    allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
      { id: 'black-bottom-corner',  color: 'black', position: 'bottom', allowsPhoto: false, allowsBolt: false, allowsVideo: false, w: 640, h: 800, x: 0, y: 0 },
    ];

    const CS_COLORS = {
      blue:  { primary: '#2B2F84', yellow: '#F9C842', gray: '#D1D3D4' },
      black: { primary: '#000000', gold: '#D8AC4B' },
    };

    const CS_OFFER_TYPES = {
      'price-save-yellow':    { hasPrice: true, hasStartingAt: false, badge: 'yellow-save-badge',        badgeLabel: 'SAVE' },
      'price-save-blue':      { hasPrice: true, hasStartingAt: false, badge: 'blue-save-badge',          badgeLabel: 'SAVE' },
      'starting-save-yellow': { hasPrice: true, hasStartingAt: true,  badge: 'yellow-save-up-to-badge',  badgeLabel: 'SAVE UP TO' },
      'starting-save-blue':   { hasPrice: true, hasStartingAt: true,  badge: 'blue-save-up-to-badge',    badgeLabel: 'SAVE UP TO' },
      'text-only':            { hasPrice: false, hasStartingAt: false, badge: null, badgeLabel: null },
    };

    // State
    let csState = {
      mediaMode: 'image',    // 'image' or 'video'
      color: 'blue',
      graphicId: null,
      bgType: null,          // 'graphic' | 'bolt' | 'photo' | 'video'
      bgValue: null,
      bgImageData: null,
      bgRawImage: null,  // full original for in-place positioning
      bgNatW: 0, bgNatH: 0,  // natural dimensions of uploaded bg
      bgScale: 1, bgX: 0, bgY: 0,  // pan/zoom state for upload bg
      // Video bg state
      videoSource: null,     // 'generate' | 'upload' | 'library'
      videoScript: '',       // HeyGen script text
      videoUrl: null,        // source video URL (from HeyGen, upload, or library)
      videoStatus: null,     // null | 'generating' | 'done' | 'failed'
      videoId: null,         // HeyGen video_id for polling
      videoError: null,
      _videoPollTimer: null,
      _videoElapsedTimer: null,
      _videoStartTime: null,
      offerType: null,
      offerMode: null,       // 'none' | 'text' | 'price'
      offerHasBadge: false,
      offerBadgeType: 'save', // 'save' | 'saveupto'
      offerBadgeColor: 'yellow',
      offerShortText: '',    // short text next to price when no bolt
      offerDollars: '',
      offerCents: '',
      offerUnit: '',
      offerSave: '',
      offerText: '',
      showTitle: true,
      titleText: 'SALE EVENT',
      rulesText: 'In store only, while supplies last',
      bodyCount: null,
      bodyItems: [],
    };

    // Preloaded images for canvas
    const csImageCache = {};

    // ─── Step validation: enable/disable Next buttons ───
    function csValidateGraphicStep() {
      var btn = document.getElementById('csGraphicNextBtn');
      var hint = document.getElementById('csGraphicHint');
      if (!btn) return;
      var ready = csState.graphicId && csState.bgType;
      if (csState.bgType === 'video' && !csState.videoUrl) ready = false;
      btn.disabled = !ready;
      if (ready && hint) hint.style.display = 'none';
    }

    // Wrapper click handler for Next buttons — shows hint if disabled, fires step if enabled
    window.csStepNextClick = function(stepId) {
      if (stepId === 'csStepGraphic') {
        var btn = document.getElementById('csGraphicNextBtn');
        var hint = document.getElementById('csGraphicHint');
        if (btn.disabled) {
          if (!csState.graphicId) hint.textContent = 'Select a graphic above';
          else if (!csState.bgType) hint.textContent = 'Choose a background';
          else if (csState.bgType === 'video' && !csState.videoUrl) hint.textContent = 'Generate or select a video first';
          hint.style.display = 'block';
          return;
        }
      }
      csStepNext(stepId);
    };

    // ─── Graphic Filter Checkboxes ───
    window.csApplyGraphicFilter = function() {
      // Reset selection when filters change
      csState.graphicId = null;
      csState.bgType = null;
      csState.bgValue = null;
      csState.bgRawImage = null;
      csState.videoSource = null;
      csState.videoUrl = null;
      csRebuildGraphicGrid();
      csHideStepsAfter('csStepGraphic');
      document.getElementById('csBgSection').style.display = 'none';
      document.getElementById('csPlaceholder').style.display = 'flex';
      csUpdatePreview();
    };

    // Helper: is current selection a video-only graphic?
    function csIsVideoMode() {
      var g = CS_BRAND_GRAPHICS.find(function(gr) { return gr.id === csState.graphicId; });
      return g && csState.bgType === 'video';
    }

    // ─── Color Selection ───
    window.csSelectColor = function(color) {
      csState.color = color;
      csState.graphicId = null;
      csState.bgType = null;
      csState.bgValue = null;
      document.querySelectorAll('.cs-color-btn').forEach(b => b.classList.toggle('active', b.dataset.color === color));
      csRebuildGraphicGrid();
      csHideStepsAfter('csStepGraphic');
      document.getElementById('csBgSection').style.display = 'none';
      csUpdatePreview();
    };

    // ─── Graphic Grid ───
    function csRebuildGraphicGrid() {
      const grid = document.getElementById('csGraphicGrid');
      var graphics = CS_BRAND_GRAPHICS.filter(g => g.color === csState.color);
      // Apply radio filter
      var sel = document.querySelector('input[name="csGraphicFilter"]:checked');
      var filterVal = sel ? sel.value : 'all';
      if (filterVal === 'photo') graphics = graphics.filter(g => g.allowsPhoto);
      else if (filterVal === 'video') graphics = graphics.filter(g => g.allowsVideo);
      else if (filterVal === 'bolt') graphics = graphics.filter(g => g.allowsBolt);
      grid.innerHTML = graphics.map(g => {
        const svgFile = g.file || g.id;
        const pos = g.position;
        return '<div class="cs-graphic-thumb' + (csState.graphicId === g.id ? ' active' : '') + '" data-id="' + g.id + '" data-pos="' + pos + '" onclick="csSelectGraphic(\'' + g.id + '\')">' +
          '<img src="/assets/mms/brand-graphics/' + svgFile + '.svg" alt="' + g.id + '" />' +
        '</div>';
      }).join('');
    }

    // ─── Graphic Selection ───
    window.csSelectGraphic = function(id) {
      csState.graphicId = id;
      csState.bgImageData = null;
      // Highlight
      document.querySelectorAll('.cs-graphic-thumb').forEach(t => t.classList.toggle('active', t.dataset.id === id));
      csRebuildBgOptions();
      // Show bg section and auto-select background based on filter
      document.getElementById('csBgSection').style.display = 'block';
      var filterSel = document.querySelector('input[name="csGraphicFilter"]:checked');
      var activeFilter = filterSel ? filterSel.value : 'all';
      if (activeFilter === 'bolt') {
        var boltColor = csState.color === 'blue' ? '#F9C842' : '#D8AC4B';
        csSelectBg('bolt', boltColor);
      } else if (!csState.bgType || (csState.bgType !== 'photo' && csState.bgType !== 'video')) {
        var defaultColor = csState.color === 'blue' ? '#F9C842' : '#D8AC4B';
        csSelectBg('graphic', defaultColor);
      }
      // Hide placeholder
      document.getElementById('csPlaceholder').style.display = 'none';
      csUpdatePreview();
      csValidateGraphicStep();
    };

    // ─── Background Options ───
    function csRebuildBgOptions() {
      const g = CS_BRAND_GRAPHICS.find(gr => gr.id === csState.graphicId);
      const c = csState.color;
      const container = document.getElementById('csBgOptions');
      let html = '';

      // Check which radio filter is active
      var sel = document.querySelector('input[name="csGraphicFilter"]:checked');
      var filterVal = sel ? sel.value : 'all';
      var anyFilter = filterVal !== 'all';

      // When a filter is active, only show bg types that match
      var showGraphic = !anyFilter;  // solid colors only when no filter is active
      var showBolt = g && g.allowsBolt && (!anyFilter || filterVal === 'bolt');
      var showPhoto = g && g.allowsPhoto && (!anyFilter || filterVal === 'photo');
      var showVideo = g && g.allowsVideo && (!anyFilter || filterVal === 'video');

      if (showGraphic) {
        const activeVal = csState.bgValue;
        if (c === 'blue') {
          html += '<div class="cs-bg-swatch' + (activeVal === '#F9C842' && csState.bgType === 'graphic' ? ' active' : '') + '" style="background:#F9C842;" data-bg="graphic" data-val="#F9C842" onclick="csSelectBg(\'graphic\',\'#F9C842\')" title="Yellow"></div>';
          html += '<div class="cs-bg-swatch' + (activeVal === '#D1D3D4' && csState.bgType === 'graphic' ? ' active' : '') + '" style="background:#D1D3D4;" data-bg="graphic" data-val="#D1D3D4" onclick="csSelectBg(\'graphic\',\'#D1D3D4\')" title="Silver"></div>';
        } else {
          html += '<div class="cs-bg-swatch' + (activeVal === '#D8AC4B' && csState.bgType === 'graphic' ? ' active' : '') + '" style="background:#D8AC4B;" data-bg="graphic" data-val="#D8AC4B" onclick="csSelectBg(\'graphic\',\'#D8AC4B\')" title="Gold"></div>';
        }
      }

      // ── Bolt Graphic ──
      if (showBolt) {
        const texColor = c === 'blue' ? '#F9C842' : '#D8AC4B';
        html += '<div class="cs-bg-swatch cs-texture-' + c + (csState.bgType === 'bolt' ? ' active' : '') + '" style="background-color:' + texColor + ';" data-bg="bolt" onclick="csSelectBg(\'bolt\',\'' + texColor + '\')" title="Bolt Graphic"></div>';
      }

      // ── Photo bg icon ──
      if (showPhoto) {
        html += '<div class="cs-bg-upload-btn' + (csState.bgType === 'photo' ? ' active' : '') + '" onclick="csOpenPhotoBgModal()" title="Photo Background"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg></div>';
      }

      // ── Video bg icon ──
      if (showVideo) {
        html += '<div class="cs-bg-upload-btn' + (csState.bgType === 'video' ? ' active' : '') + '" onclick="csOpenVideoBgModal()" title="Video Background"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg></div>';
      }

      container.innerHTML = html;
    }

    // File upload handler
    document.getElementById('csBgFileInput').addEventListener('change', function() {
      const file = this.files[0];
      if (!file) return;
      this.value = ''; // reset so same file can be re-selected
      const reader = new FileReader();
      reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
          // Compute cover-fill scale and center
          var scale = Math.max(640 / img.width, 800 / img.height);
          csState.bgType = 'photo';
          csState.bgValue = null;
          csState.bgRawImage = e.target.result;
          csState.bgImageData = e.target.result;
          csState.bgNatW = img.width;
          csState.bgNatH = img.height;
          csState.bgScale = scale;
          csState.bgX = (640 - img.width * scale) / 2;
          csState.bgY = (800 - img.height * scale) / 2;
          document.querySelectorAll('.cs-bg-swatch').forEach(s => s.classList.remove('active'));
          document.querySelector('.cs-bg-upload-btn').classList.add('active');
          csUpdatePreview();
        };
        img.src = e.target.result;
      };
      reader.readAsDataURL(file);
    });

    // ─── Background In-Place Pan/Zoom ───
    (function() {
      var dragging = false, startX = 0, startY = 0, origX = 0, origY = 0;
      var canvas = document.getElementById('csCanvas');

      canvas.addEventListener('mousedown', function(e) {
        if (csState.bgType !== 'photo' || !csState.bgRawImage) return;
        // Don't intercept clicks on inputs, buttons, or interactive overlays
        if (e.target.closest('input, button, .cs-prev-offer-bar, .cs-prev-title-bar, .cs-prev-body-clickable, .cs-editable')) return;
        dragging = true;
        origX = csState.bgX; origY = csState.bgY;
        startX = e.clientX; startY = e.clientY;
        canvas.style.cursor = 'grabbing';
        e.preventDefault();
      });
      window.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        csState.bgX = origX + (e.clientX - startX);
        csState.bgY = origY + (e.clientY - startY);
        csBgClamp();
        csBgApplyPreview();
      });
      window.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false;
        canvas.style.cursor = '';
      });

      canvas.addEventListener('wheel', function(e) {
        if (csState.bgType !== 'photo' || !csState.bgRawImage) return;
        e.preventDefault();
        var rect = canvas.getBoundingClientRect();
        var mx = e.clientX - rect.left, my = e.clientY - rect.top;
        var oldScale = csState.bgScale;
        var minScale = Math.max(640 / csState.bgNatW, 800 / csState.bgNatH);
        csState.bgScale *= e.deltaY < 0 ? 1.03 : 0.971;
        csState.bgScale = Math.max(minScale, csState.bgScale);
        var ratio = csState.bgScale / oldScale;
        csState.bgX = mx - (mx - csState.bgX) * ratio;
        csState.bgY = my - (my - csState.bgY) * ratio;
        csBgClamp();
        csBgApplyPreview();
      }, { passive: false });
    })();

    function csBgClamp() {
      var sw = csState.bgNatW * csState.bgScale;
      var sh = csState.bgNatH * csState.bgScale;
      csState.bgX = Math.min(0, Math.max(640 - sw, csState.bgX));
      csState.bgY = Math.min(0, Math.max(800 - sh, csState.bgY));
    }

    function csBgApplyPreview() {
      var prevBg = document.getElementById('csPrevBg');
      prevBg.style.backgroundSize = (csState.bgNatW * csState.bgScale) + 'px ' + (csState.bgNatH * csState.bgScale) + 'px';
      prevBg.style.backgroundPosition = csState.bgX + 'px ' + csState.bgY + 'px';
    }

    // ─── Background Selection ───
    window.csSelectBg = function(type, value) {
      csState.bgType = type;
      csState.bgValue = value;
      csState.bgImageData = null;
      csState.bgRawImage = null;
      // Highlight
      document.querySelectorAll('#csBgOptions .cs-bg-swatch, #csBgOptions .cs-bg-upload-btn').forEach(s => s.classList.remove('active'));
      const sel = document.querySelector('#csBgOptions [data-bg="' + type + '"]' + (type === 'graphic' ? '[data-val="' + value + '"]' : ''));
      if (sel) sel.classList.add('active');
      csUpdatePreview();
    };

    // ─── ADD PHOTO Background Modal ───
    var _csBgModal = null;

    window.csOpenPhotoBgModal = function() {
      _csCloseBgModal();
      var overlay = document.createElement('div');
      overlay.className = 'cs-bg-modal-overlay';
      var html = '<div class="cs-bg-modal">';
      html += '<h3 style="color:var(--napa-yellow);font-size:18px;margin:0 0 14px;">ADD PHOTO</h3>';
      html += '<div style="display:flex;gap:8px;margin-bottom:14px;">';
      html += '<button class="cs-bg-modal-src active" id="csBgPhotoSrcUpload" onclick="csBgPhotoSetSrc(\'upload\')">Upload Photo</button>';
      html += '<button class="cs-bg-modal-src" id="csBgPhotoSrcLibrary" onclick="csBgPhotoSetSrc(\'library\')">From Library</button>';
      html += '</div>';
      html += '<div id="csBgPhotoContent">';
      html += '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:6px;">Image</div>';
      html += '<input type="file" id="csBgPhotoFileInput" accept="image/*" style="width:100%;margin-bottom:10px;" />';
      html += '<div id="csBgPhotoPreview" style="min-height:100px;background:rgba(255,255,255,.05);border:2px dashed rgba(255,255,255,.2);border-radius:8px;display:flex;align-items:center;justify-content:center;overflow:hidden;cursor:pointer;color:rgba(255,255,255,.4);font-size:13px;transition:border-color .2s,background .2s;" onclick="document.getElementById(\'csBgPhotoFileInput\').click()">Drag or click to add image</div>';
      html += '</div>';
      html += '<div style="display:flex;gap:10px;margin-top:16px;">';
      html += '<button class="btn-secondary" style="flex:1;padding:12px;font-size:15px;font-weight:700;" onclick="_csCloseBgModal()">Cancel</button>';
      html += '<button class="btn-primary" id="csBgPhotoSaveBtn" style="flex:1;padding:12px;font-size:15px;font-weight:700;" onclick="csBgPhotoSave()" disabled>Save</button>';
      html += '</div>';
      html += '</div>';
      overlay.innerHTML = html;
      overlay.addEventListener('click', function(e) { if (e.target === overlay) _csCloseBgModal(); });
      document.body.appendChild(overlay);
      _csBgModal = overlay;

      // Wire file input
      document.getElementById('csBgPhotoFileInput').addEventListener('change', function() {
        var file = this.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function(ev) {
          _csBgModal._photoData = ev.target.result;
          document.getElementById('csBgPhotoPreview').innerHTML = '<img src="' + ev.target.result + '" style="max-width:100%;max-height:200px;object-fit:contain;" />';
          document.getElementById('csBgPhotoSaveBtn').disabled = false;
        };
        reader.readAsDataURL(file);
      });

      // Drag-and-drop on preview area
      var preview = document.getElementById('csBgPhotoPreview');
      preview.addEventListener('dragover', function(e) {
        e.preventDefault();
        preview.style.borderColor = '#f5c518';
        preview.style.background = 'rgba(245,197,24,.1)';
      });
      preview.addEventListener('dragleave', function() {
        preview.style.borderColor = 'rgba(255,255,255,.2)';
        preview.style.background = 'rgba(255,255,255,.05)';
      });
      preview.addEventListener('drop', function(e) {
        e.preventDefault();
        preview.style.borderColor = 'rgba(255,255,255,.2)';
        preview.style.background = 'rgba(255,255,255,.05)';
        var file = e.dataTransfer.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        var reader = new FileReader();
        reader.onload = function(ev) {
          _csBgModal._photoData = ev.target.result;
          preview.innerHTML = '<img src="' + ev.target.result + '" style="max-width:100%;max-height:200px;object-fit:contain;" />';
          document.getElementById('csBgPhotoSaveBtn').disabled = false;
        };
        reader.readAsDataURL(file);
      });

      // Prevent browser default drop on the whole modal
      overlay.addEventListener('dragover', function(e) { e.preventDefault(); });
      overlay.addEventListener('drop', function(e) { e.preventDefault(); });
    };

    window.csBgPhotoSetSrc = function(src) {
      document.getElementById('csBgPhotoSrcUpload').classList.toggle('active', src === 'upload');
      document.getElementById('csBgPhotoSrcLibrary').classList.toggle('active', src === 'library');
      if (src === 'library') {
        _csCloseBgModal();
        _libIndex = null;
        _libBgPickerType = 'photo';
        _libFilter = 'image';
        _libOpenOverlay(true);
      }
    };

    window.csBgPhotoSave = function() {
      if (!_csBgModal || !_csBgModal._photoData) return;
      var dataUrl = _csBgModal._photoData;
      var img = new Image();
      img.onload = function() {
        var scale = Math.max(640 / img.width, 800 / img.height);
        csState.bgType = 'photo';
        csState.bgRawImage = dataUrl;
        csState.bgNatW = img.width;
        csState.bgNatH = img.height;
        csState.bgScale = scale;
        csState.bgX = (640 - img.width * scale) / 2;
        csState.bgY = (800 - img.height * scale) / 2;
        document.querySelectorAll('.cs-bg-swatch').forEach(function(s) { s.classList.remove('active'); });
        csRebuildBgOptions();
        csUpdatePreview();
      };
      img.src = dataUrl;
      _csCloseBgModal();
    };

    // ─── ADD VIDEO Background Modal ───
    window.csOpenVideoBgModal = function() {
      _csCloseBgModal();
      var overlay = document.createElement('div');
      overlay.className = 'cs-bg-modal-overlay';
      var activeSource = csState.videoSource || 'script';
      var isGen = csState.videoStatus === 'generating';
      var disOther = isGen ? ' disabled style="opacity:.4;cursor:not-allowed;"' : '';
      var html = '<div class="cs-bg-modal">';
      html += '<h3 style="color:var(--napa-yellow);font-size:18px;margin:0 0 14px;">ADD VIDEO</h3>';
      html += '<div style="display:flex;gap:8px;margin-bottom:14px;">';
      html += '<button class="cs-bg-modal-src' + (activeSource === 'upload' ? ' active' : '') + '" onclick="csBgVideoSetSrc(\'upload\')"' + disOther + '>Upload</button>';
      html += '<button class="cs-bg-modal-src' + (activeSource === 'library' ? ' active' : '') + '" onclick="csBgVideoSetSrc(\'library\')"' + disOther + '>From Library</button>';
      html += '<button class="cs-bg-modal-src' + (activeSource === 'script' || activeSource === 'generate' ? ' active' : '') + '" onclick="csBgVideoSetSrc(\'script\')">From Script</button>';
      html += '</div>';
      html += '<div id="csBgVideoContent">';
      if (activeSource === 'script' || activeSource === 'generate') {
        html += _csBuildScriptPanel();
      } else if (activeSource === 'upload') {
        html += '<input type="file" id="csBgVideoFileInputModal" accept="video/mp4,video/quicktime,video/webm" style="width:100%;" />';
      }
      html += '</div>';
      html += '<div style="display:flex;gap:10px;margin-top:16px;">';
      var isGenerating = csState.videoStatus === 'generating';
      html += '<button class="btn-secondary" style="flex:1;padding:12px;font-size:' + (isGenerating ? '13' : '15') + 'px;font-weight:700;" onclick="_csCloseBgModal()">' + (isGenerating ? 'Close \u2014 video will keep generating' : 'Cancel') + '</button>';
      html += '<button class="btn-primary" id="csBgVideoSaveBtn" style="flex:1;padding:12px;font-size:15px;font-weight:700;" onclick="csBgVideoSave()"' + (csState.videoStatus === 'done' && csState.videoUrl ? '' : ' disabled') + '>Save</button>';
      html += '</div>';
      html += '</div>';
      overlay.innerHTML = html;
      overlay.addEventListener('click', function(e) { if (e.target === overlay) _csCloseBgModal(); });
      document.body.appendChild(overlay);
      _csBgModal = overlay;

      // Wire upload input if visible
      var uploadInput = document.getElementById('csBgVideoFileInputModal');
      if (uploadInput) _csWireVideoUploadInput(uploadInput);
    };

    function _csBuildScriptPanel() {
      var wordCount = csState.videoScript ? csState.videoScript.trim().split(/\s+/).filter(function(w){return w;}).length : 0;
      var charCount = (csState.videoScript || '').length;
      var overLimit = charCount > 200;
      var h = '';
      h += '<textarea id="csVideoScript" maxlength="250" placeholder="Type what Brian should say..." style="min-height:100px;width:100%;box-sizing:border-box;" oninput="csState.videoScript=this.value;_csUpdateScriptCounter();">' + (csState.videoScript || '') + '</textarea>';
      h += '<div id="csScriptCounter" style="font-size:11px;margin-top:2px;text-align:right;color:' + (overLimit ? 'var(--red)' : 'rgba(255,255,255,.3)') + ';">' + charCount + '/200</div>';

      if (csState.videoStatus === 'generating') {
        h += '<div style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:13px;color:var(--napa-yellow);"><span class="video-spinner"></span> Generating video... <span id="csVideoElapsed" style="color:rgba(255,255,255,.3);"></span></div>';
        h += '<div style="margin-top:6px;font-size:12px;color:rgba(255,255,255,.4);">This usually takes 1–3 minutes. You can close this window and keep working.</div>';
      } else if (csState.videoStatus === 'done' && csState.videoUrl) {
        h += '<div style="margin-top:8px;font-size:13px;color:var(--green);">Video ready!</div>';
        h += '<button class="btn-secondary" style="padding:6px 12px;font-size:12px;margin-top:4px;" onclick="csGenerateVideo()">Regenerate</button>';
      } else if (csState.videoStatus === 'failed') {
        h += '<div style="margin-top:8px;font-size:13px;color:var(--red);">Failed: ' + (csState.videoError || 'Unknown error') + '</div>';
        h += '<button class="btn-primary" style="padding:6px 12px;font-size:12px;margin-top:4px;" onclick="csGenerateVideo()">Retry</button>';
      } else {
        h += '<div style="display:flex;align-items:center;gap:8px;margin-top:8px;">';
        h += '<button class="btn-primary" style="padding:8px 16px;font-size:13px;" onclick="csGenerateVideo()"' + (csState.videoScript && csState.videoScript.trim() ? '' : ' disabled') + ' id="csVideoGenBtn">Generate Video</button>';
        h += '</div>';
      }
      return h;
    }

    window._csUpdateScriptCounter = function() {
      var el = document.getElementById('csScriptCounter');
      var btn = document.getElementById('csVideoGenBtn');
      if (el) {
        var c = (csState.videoScript || '').length;
        el.textContent = c + '/200';
        el.style.color = c > 200 ? 'var(--red)' : 'rgba(255,255,255,.3)';
      }
      if (btn) btn.disabled = !(csState.videoScript && csState.videoScript.trim());
    };

    window.csBgVideoSetSrc = function(src) {
      // Block source switching while HeyGen is generating
      if (csState.videoStatus === 'generating') {
        showToast('Video is generating — please wait or cancel first.', 'info', document.querySelector('.cs-bg-modal-src'));
        return;
      }
      if (src === 'library') {
        _csCloseBgModal();
        _libIndex = null;
        _libBgPickerType = 'video';
        _libFilter = 'video';
        _libOpenOverlay(true);
        return;
      }
      csState.videoSource = src;
      var content = document.getElementById('csBgVideoContent');
      if (!content) return;
      // Update source buttons
      document.querySelectorAll('.cs-bg-modal-src').forEach(function(b) { b.classList.remove('active'); });
      var idx = src === 'upload' ? 0 : (src === 'library' ? 1 : 2);
      var btns = _csBgModal.querySelectorAll('.cs-bg-modal-src');
      if (btns[idx]) btns[idx].classList.add('active');

      if (src === 'upload') {
        content.innerHTML = '<input type="file" id="csBgVideoFileInputModal" accept="video/mp4,video/quicktime,video/webm" style="width:100%;" />';
        _csWireVideoUploadInput(document.getElementById('csBgVideoFileInputModal'));
      } else if (src === 'script') {
        content.innerHTML = _csBuildScriptPanel();
      }
    };

    function _csWireVideoUploadInput(input) {
      input.addEventListener('change', function() {
        var file = this.files[0];
        if (!file) return;
        var anchor = document.getElementById('csBgVideoSaveBtn') || input;
        csState.videoUrl = URL.createObjectURL(file);
        csState.bgType = 'video';
        csState.videoSource = 'upload';
        csState.videoStatus = 'done';
        var saveBtn = document.getElementById('csBgVideoSaveBtn');
        if (saveBtn) saveBtn.disabled = false;
        // Upload to Cloudinary in background
        var formData = new FormData();
        formData.append('file', file);
        formData.append('upload_preset', 'gkk_napa_mms');
        formData.append('resource_type', 'video');
        fetch('https://api.cloudinary.com/v1_1/dtpqxuwby/video/upload', {
          method: 'POST', body: formData
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.secure_url) {
            csState.videoUrl = data.secure_url;
            fetch(WORKER_BASE + '/admin/media-library', {
              method: 'POST',
              headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
              body: JSON.stringify({ url: data.secure_url, label: file.name.replace(/\.[^.]+$/, ''), category: 'raw_video' })
            });
            showToast('Video uploaded!', 'success', anchor);
          }
        }).catch(function(e) { showToast('Video upload failed: ' + e.message, 'error', anchor); });
      });
    }

    window.csBgVideoSave = function() {
      if (!csState.videoUrl) return;
      csState.bgType = 'video';
      csRebuildBgOptions();
      csUpdatePreview();
      _csCloseBgModal();
    };

    function _csCloseBgModal() {
      if (_csBgModal) { _csBgModal.remove(); _csBgModal = null; }
    }

    // Open library to pick bg photo or video
    window.csOpenBgLibrary = function(type) {
      _libIndex = null;
      _libBgPickerType = type;
      _libFilter = type === 'video' ? 'video' : 'image';
      _libOpenOverlay(true);
    };

    // HeyGen video generation
    window.csGenerateVideo = function() {
      var script = (csState.videoScript || '').trim();
      var genBtn = document.getElementById('csVideoGenBtn');
      if (!script) { showToast('Enter a script first.', 'error', genBtn); return; }

      var testCheckbox = document.getElementById('csVideoTestMode');
      var isTest = testCheckbox ? testCheckbox.checked : false;

      csState.videoStatus = 'generating';
      csState.videoError = null;
      csState.videoUrl = null;
      csState._videoStartTime = Date.now();
      // Refresh modal content
      var content = document.getElementById('csBgVideoContent');
      if (content) content.innerHTML = _csBuildScriptPanel();

      fetch(WORKER_BASE + '/admin/video/create', {
        method: 'POST',
        headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
        body: JSON.stringify({ script: script, test_mode: isTest })
      }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) {
          csState.videoStatus = 'failed';
          csState.videoError = data.error;
          var c = document.getElementById('csBgVideoContent');
          if (c) c.innerHTML = _csBuildScriptPanel();
          return;
        }
        csState.videoId = data.video_id;
        csState._videoPollTimer = setInterval(function() { _csVideoPoll(); }, 6000);
        document.getElementById('csVideoGeneratingBanner').style.display = 'block';
        csState._videoElapsedTimer = setInterval(function() {
          var secs = Math.round((Date.now() - csState._videoStartTime) / 1000);
          var m = Math.floor(secs / 60);
          var s = secs % 60;
          var timeStr = (m > 0 ? m + 'm ' : '') + s + 's';
          var el = document.getElementById('csVideoElapsed');
          if (el) el.textContent = timeStr;
          var el2 = document.getElementById('csVideoElapsedPreview');
          if (el2) el2.textContent = timeStr;
        }, 1000);
        showToast('Video generating — you can work on other parts while you wait.', 'info', genBtn);
      }).catch(function(e) {
        csState.videoStatus = 'failed';
        csState.videoError = e.message;
        var c = document.getElementById('csBgVideoContent');
        if (c) c.innerHTML = _csBuildScriptPanel();
      });
    };

    function _csVideoPoll() {
      if (!csState.videoId || csState.videoStatus !== 'generating') return;
      // Auto-stop polling after 5 minutes but keep state so user can retry
      if (csState._videoStartTime && (Date.now() - csState._videoStartTime > 5 * 60 * 1000)) {
        _csVideoStopTimers();
        // Don't clear videoStatus — leave as 'generating' so Check Again works
        showToast('Polling stopped after 5 min — use "Check Again" to see if it finished.', 'info', document.getElementById('csBgSection'));
        var c = document.getElementById('csBgVideoContent');
        if (c) c.innerHTML = _csBuildScriptPanel();
        // Update banner to show check-again prompt
        var banner = document.getElementById('csVideoGeneratingBanner');
        if (banner) {
          banner.querySelector('div').innerHTML = 'Polling stopped <span id="csVideoElapsedPreview"></span>';
          banner.querySelector('button').textContent = 'Check Again';
          banner.querySelector('button').onclick = function() { csCheckVideoAgain(); };
        }
        return;
      }
      fetch(WORKER_BASE + '/admin/video/status?video_id=' + encodeURIComponent(csState.videoId), {
        headers: authHeaders()
      }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.status === 'completed' && data.video_url) {
          csState.videoStatus = 'done';
          csState.videoUrl = data.video_url;
          csState.bgType = 'video';
          _csVideoStopTimers();

          // Save raw HeyGen video to Cloudinary + media library for reuse
          (function(heygenUrl) {
            var fd = new FormData();
            fd.append('file', heygenUrl);
            fd.append('upload_preset', 'gkk_napa_mms');
            fd.append('resource_type', 'video');
            fetch('https://api.cloudinary.com/v1_1/dtpqxuwby/video/upload', {
              method: 'POST', body: fd
            }).then(function(r) { return r.json(); }).then(function(cld) {
              if (cld.secure_url) {
                csState.videoUrl = cld.secure_url;
                csUpdatePreview();
                // Save to library with script snippet as label
                var label = 'HeyGen — ' + (csState.videoScript || '').substring(0, 60).trim();
                fetch(WORKER_BASE + '/admin/media-library', {
                  method: 'POST',
                  headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
                  body: JSON.stringify({ url: cld.secure_url, label: label, category: 'raw_video' })
                }).then(function() {
                  showToast('HeyGen video saved to library!', 'success', document.getElementById('csBgSection'));
                });
              } else {
                console.warn('HeyGen Cloudinary upload returned no secure_url:', cld);
              }
            }).catch(function(e) { console.warn('HeyGen Cloudinary upload failed:', e); });
          })(data.video_url);

          // Refresh modal if open
          var c = document.getElementById('csBgVideoContent');
          if (c) c.innerHTML = _csBuildScriptPanel();
          var saveBtn = document.getElementById('csBgVideoSaveBtn');
          if (saveBtn) saveBtn.disabled = false;
          csRebuildBgOptions();
          csUpdatePreview();
          showToast("Brian's video is ready!", 'success', document.getElementById('csBgVideoContent') || document.getElementById('csBgSection'));
        } else if (data.status === 'failed') {
          csState.videoStatus = 'failed';
          csState.videoError = data.error || 'Video generation failed';
          _csVideoStopTimers();
          var c2 = document.getElementById('csBgVideoContent');
          if (c2) c2.innerHTML = _csBuildScriptPanel();
        }
      }).catch(function() { /* network error — keep polling */ });
    }

    function _csVideoStopTimers() {
      if (csState._videoPollTimer) { clearInterval(csState._videoPollTimer); csState._videoPollTimer = null; }
      if (csState._videoElapsedTimer) { clearInterval(csState._videoElapsedTimer); csState._videoElapsedTimer = null; }
      var banner = document.getElementById('csVideoGeneratingBanner');
      if (banner) banner.style.display = 'none';
    }

    window.csCheckVideoAgain = function() {
      if (!csState.videoId) { showToast('No video ID to check.', 'error'); return; }
      var banner = document.getElementById('csVideoGeneratingBanner');
      if (banner) banner.querySelector('div').innerHTML = 'Checking…';
      fetch(WORKER_BASE + '/admin/video/status?video_id=' + encodeURIComponent(csState.videoId), {
        headers: authHeaders()
      }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.status === 'completed' && data.video_url) {
          csState.videoStatus = 'done';
          csState.videoUrl = data.video_url;
          csState.bgType = 'video';
          if (banner) banner.style.display = 'none';
          // Upload to Cloudinary + save to library (same as normal completion)
          (function(heygenUrl) {
            var fd = new FormData();
            fd.append('file', heygenUrl);
            fd.append('upload_preset', 'gkk_napa_mms');
            fetch('https://api.cloudinary.com/v1_1/dtpqxuwby/video/upload', {
              method: 'POST', body: fd
            }).then(function(r) { return r.json(); }).then(function(cld) {
              if (cld.secure_url) {
                csState.videoUrl = cld.secure_url;
                csUpdatePreview();
                var label = 'HeyGen — ' + (csState.videoScript || '').substring(0, 60).trim();
                fetch(WORKER_BASE + '/admin/media-library', {
                  method: 'POST',
                  headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
                  body: JSON.stringify({ url: cld.secure_url, label: label, category: 'raw_video' })
                }).then(function() {
                  showToast('HeyGen video saved to library!', 'success', document.getElementById('csBgSection'));
                });
              }
            }).catch(function(e) { console.warn('Cloudinary upload failed:', e); });
          })(data.video_url);
          csRebuildBgOptions();
          csUpdatePreview();
          var c = document.getElementById('csBgVideoContent');
          if (c) c.innerHTML = _csBuildScriptPanel();
          showToast("Brian's video is ready!", 'success', document.getElementById('csBgSection'));
        } else if (data.status === 'failed') {
          csState.videoStatus = 'failed';
          csState.videoError = data.error || 'Video generation failed';
          if (banner) banner.style.display = 'none';
          showToast('Video failed: ' + (data.error || 'unknown'), 'error', document.getElementById('csBgSection'));
          var c2 = document.getElementById('csBgVideoContent');
          if (c2) c2.innerHTML = _csBuildScriptPanel();
        } else {
          if (banner) {
            banner.querySelector('div').innerHTML = 'Still processing… <span id="csVideoElapsedPreview"></span>';
          }
          showToast('Still processing — try again in a minute.', 'info', document.getElementById('csBgSection'));
        }
      }).catch(function(e) {
        showToast('Check failed: ' + e.message, 'error');
      });
    };

    window.csCancelVideo = function() {
      _csVideoStopTimers();
      csState.videoStatus = null;
      csState.videoId = null;
      csState.videoError = null;
      // Keep videoUrl if one was already loaded (e.g. from library)
      var c = document.getElementById('csBgVideoContent');
      if (c) c.innerHTML = _csBuildScriptPanel();
      showToast('Video generation cancelled.', 'info', document.getElementById('csBgSection'));
    };

    // Save composited video to library
    window.csSaveVideoToLibrary = function(url, btnEl) {
      var anchor = btnEl || document.getElementById('csRendered');
      fetch(WORKER_BASE + '/admin/media-library', {
        method: 'POST',
        headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
        body: JSON.stringify({ url: url, label: (csState.titleText || 'Video MMS').substring(0, 80), category: 'finished_video' })
      }).then(function() {
        showToast('Saved to library!', 'success', anchor);
      }).catch(function() {
        showToast('Failed to save to library.', 'error', anchor);
      });
    };

    // ─── Offer Selection ───

    // Render the offer step content area (controls only — preview is in the canvas)
    function csRenderOfferContent() {
      var el = document.getElementById('csOfferContent');
      if (!el) return;
      var mode = csState.offerMode;

      if (mode === 'price') {
        // Price / Starting At toggle
        var startAt = csState.offerBadgeType === 'saveupto';
        el.innerHTML = '<div style="display:flex;gap:6px;">' +
          '<button class="cs-offer-type-btn' + (!startAt ? ' active' : '') + '" onclick="csSelectPriceType(\'save\')" style="padding:4px 10px;font-size:11px;">Price</button>' +
          '<button class="cs-offer-type-btn' + (startAt ? ' active' : '') + '" onclick="csSelectPriceType(\'saveupto\')" style="padding:4px 10px;font-size:11px;">Starting At</button>' +
          '</div>';
      } else {
        el.innerHTML = '';
      }
    }

    function csUpdateOfferFromVisual() {
      csState.offerHasBadge = document.getElementById('csOfferBadgeToggle').checked;
      var mode = csState.offerMode;

      // Derive offerType
      if (mode === 'none' || !mode) {
        csState.offerType = 'none';
      } else if (mode === 'text' && !csState.offerHasBadge) {
        csState.offerType = 'text-only';
      } else if (mode === 'text' && csState.offerHasBadge) {
        // Text + badge: need a price-type offerType so badge renders
        csState.offerType = (csState.offerBadgeType === 'saveupto' ? 'starting-save' : 'price-save') + '-' + csState.offerBadgeColor;
      } else if (mode === 'price') {
        csState.offerType = (csState.offerBadgeType === 'saveupto' ? 'starting-save' : 'price-save') + '-' + csState.offerBadgeColor;
      }

      // Show/hide bolt sub-options (SAVE/SAVE UP TO + color) only when bolt is checked and mode is not none
      var showBoltOpts = csState.offerHasBadge && mode && mode !== 'none';
      document.getElementById('csBadgeTypeRow').style.display = showBoltOpts ? 'flex' : 'none';
      document.getElementById('csBadgeColorPicker').style.display = showBoltOpts ? 'flex' : 'none';

      // Update badge type button states
      document.getElementById('csBadgeTypeSave').classList.toggle('active', csState.offerBadgeType !== 'saveupto');
      document.getElementById('csBadgeTypeSaveUpTo').classList.toggle('active', csState.offerBadgeType === 'saveupto');

      csRenderOfferContent();
      csBuildOfferBar();
      csUpdatePreview();
    }

    window.csSelectOfferVisual = function(mode) {
      // If switching away from 'none' while bodyCount is 9, reset body
      if (mode !== 'none' && csState.bodyCount === 9) {
        csState.bodyCount = null;
        csState.bodyItems = [];
        document.querySelectorAll('#csStepBody .cs-offer-type-btn').forEach(b => b.classList.remove('active'));
        document.getElementById('csTemplateRow').style.display = 'none';
        document.getElementById('csBodyHint').style.display = 'none';
      }
      csState.offerMode = mode;
      // Update radio buttons
      document.querySelectorAll('input[name="csOfferMode"]').forEach(function(r) { r.checked = r.value === mode; });
      // Update 9-item button visibility
      var btn9 = document.getElementById('csBodyCount9Btn');
      if (btn9) btn9.style.display = mode === 'none' ? '' : 'none';
      // Dim bolt row when No Offer
      document.getElementById('csOfferBoltRow').style.opacity = mode === 'none' ? '0.3' : '1';
      document.getElementById('csOfferBoltRow').style.pointerEvents = mode === 'none' ? 'none' : 'auto';
      // Show edit hint when text or price selected
      var hint = document.getElementById('csOfferEditHint');
      if (hint) hint.style.display = (mode === 'text' || mode === 'price') ? 'block' : 'none';
      // Uncheck bolt when switching to No Offer
      if (mode === 'none') {
        document.getElementById('csOfferBadgeToggle').checked = false;
        csState.offerHasBadge = false;
      }

      csUpdateOfferFromVisual();
    };

    window.csSelectBadgeColor = function(color) {
      csState.offerBadgeColor = color;
      document.querySelectorAll('.cs-badge-color-opt').forEach(b => {
        b.style.borderColor = b.dataset.badge === color ? 'var(--napa-yellow)' : 'transparent';
      });
      csUpdateOfferFromVisual();
    };

    window.csSelectBadgeType = function(type) {
      csState.offerBadgeType = type;
      csUpdateOfferFromVisual();
    };

    window.csSelectPriceType = function(type) {
      csState.offerBadgeType = type === 'saveupto' ? 'saveupto' : 'save';
      csUpdateOfferFromVisual();
    };

    // ─── Title & Fine Print ───
    window.csToggleTitleBar = function() {
      csState.showTitle = document.getElementById('csTitleToggle').checked;
      csUpdatePreview();
    };


    // ─── Body Selection ───
    window.csSelectBodyCount = function(count) {
      csState.bodyCount = count;
      csState.bodyItems = [];
      // Highlight count buttons only
      document.querySelectorAll('#csStepBody .cs-offer-type-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      // Reset sub-rows
      document.getElementById('csTemplateRow').style.display = 'none';
      document.getElementById('csBodyHint').style.display = 'none';
      if (count === 0) {
        document.getElementById('csStepBody').classList.add('completed');
        csHideStepsAfter('csStepBody');
        document.getElementById('csActions').style.display = 'flex';
      } else {
        // Create items with source: null (set per-cell when image added)
        csState.bodyItems = Array.from({ length: count }, () => ({ name: '', image: null, originalImage: null, partNum: '', layout: 'text-image', price: '', fullPrice: '', priceUnit: '/each', cutPriceHidden: false, unitHidden: false, source: null }));
        // Show template selector directly (no source step)
        if (count === 1 || count === 4 || count === 6 || count === 9) {
          document.getElementById('csTemplateRow').style.display = 'block';
          // Auto-select "text-image" as default
          document.querySelectorAll('#csTemplateRow .cs-offer-type-btn').forEach(b => b.classList.remove('active'));
          document.getElementById('csTemplateBtnTextImage').classList.add('active');
          document.getElementById('csStepBody').classList.add('completed');
          document.getElementById('csBodyHint').style.display = 'block';
          document.getElementById('csSampleDataBtn').style.display = 'inline-block';
          document.getElementById('csActions').style.display = 'flex';
        } else {
          document.getElementById('csTemplateRow').style.display = 'none';
          csState.bodyItems.forEach(item => { item.layout = 'text-image'; });
          document.getElementById('csStepBody').classList.add('completed');
          document.getElementById('csBodyHint').style.display = 'block';
          document.getElementById('csActions').style.display = 'flex';
        }
      }
      csUpdatePreview();
    };

    // ─── Template Selection ───
    window.csSelectTemplate = function(template, btn) {
      csState.bodyItems.forEach(function(item) { item.layout = template; item.priceHidden = false; item.cutPriceHidden = false; item.unitHidden = false; });
      // Highlight
      document.querySelectorAll('#csTemplateRow .cs-offer-type-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      // Complete the step
      document.getElementById('csStepBody').classList.add('completed');
      document.getElementById('csBodyHint').style.display = 'block';
      document.getElementById('csSampleDataBtn').style.display = 'inline-block';
      document.getElementById('csActions').style.display = 'flex';
      csUpdatePreview();
    };

    // ─── Sample Part Data ───
    const CS_SAMPLE_PARTS = [
      { partNum: 'NOL 75521', name: 'NAPA Motor Oil 5W30 Full Synthetic 5 qt', fullPrice: '$33.76' },
      { partNum: 'BAT 9848', name: 'NAPA Legend Premium AGM Battery BCI No. 48 760 CCA', fullPrice: '$463.76' },
      { partNum: 'NBK 7991MPFK1', name: 'NAPA Premium Brake Rotor and Pad Kit', fullPrice: '$296.99' },
      { partNum: 'FIL 7060', name: 'NAPA Gold Oil Filter', fullPrice: '$13.49' },
      { partNum: 'ECH EC492', name: 'Fuel Injector Connector', fullPrice: '$60.71' },
      { partNum: 'BK 7353556', name: 'Carlyle 12V 20/10/2A Battery Charger/ Maintainer w/ Engine Start Assist', fullPrice: '$217.92' },
      { partNum: 'NCP 2608235', name: 'Control Arm w/ Ball Joint - Lower Front Suspension', fullPrice: '$606.86' },
      { partNum: 'VAL 889785', name: 'Valvoline FlexFill Full Synthetic 75W-90 Gear Oil 1 QT', fullPrice: '$19.99' },
      { partNum: 'NCB RX68806', name: 'Rain-X Bug Remover Windshield Washer Fluid 1 Gal', fullPrice: '$4.99' },
      { partNum: 'BAT N99DH6YEL', name: 'Optima Yellow Top AGM Battery BCI No. 48 800 CCA', fullPrice: '$848.33' },
      { partNum: 'CRC 05482', name: 'CRC Heavy Duty Pro-Strength Degreaser 15 Wt Oz', fullPrice: '$16.48' },
      { partNum: 'APX 80550P', name: 'GEARWRENCH 56 Pc 3/8" Drive 6 Pt SAE/Metric Mechanics Tool Set', fullPrice: '$171.51' },
      { partNum: 'GRT 48880279', name: 'NAPA Brake Rotor', fullPrice: '$134.23' },
      { partNum: 'NGK 93175', name: 'NGK Spark Plug', fullPrice: '$23.99' },
      { partNum: 'NAC ABC1330GH', name: 'Air Compressor 13HP Gas Honda 30Gal Horizontal', fullPrice: '$4,893.75' },
    ];

    window.csLoadSampleData = function() {
      var count = csState.bodyCount;
      if (!count || count === 0) return;
      // Shuffle and pick N
      var shuffled = CS_SAMPLE_PARTS.slice().sort(function() { return Math.random() - 0.5; });
      var picks = shuffled.slice(0, count);
      for (var i = 0; i < count; i++) {
        var sample = picks[i];
        var item = csState.bodyItems[i];
        item.source = 'napa';
        item.partNum = sample.partNum;
        item.name = sample.name;
        item.fullPrice = sample.fullPrice;
        item.price = sample.fullPrice;
        item.priceUnit = '/each';
        // Fetch image from NAPA — stagger requests to avoid NAPA rate limiting
        (function(idx, pn) {
          var delay = count > 6 ? idx * 500 : idx * 300;
          setTimeout(function() { csFetchSampleImage(idx, pn); }, delay);
        })(i, sample.partNum);
      }
      csUpdatePreview(true);
    };

    function csFetchSampleImage(index, partNum) {
      fetch(WORKER_BASE + '/admin/napa-part-search', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ partNumber: partNum })
      })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.image) {
            var proxyUrl = WORKER_BASE + '/admin/proxy-image?url=' + encodeURIComponent(data.image);
            csState.bodyItems[index].originalImage = proxyUrl;
            csState.bodyItems[index]._canvasImage = null;
            csRemoveBg(proxyUrl).then(function(cleanUrl) {
              csState.bodyItems[index].image = cleanUrl;
              csUpdatePreview(true);
            });
          }
        })
        .catch(function(err) { console.warn('Sample image fetch failed for', partNum, err); });
    }

    // ─── Product Edit Overlay ───
    let csEditIndex = -1;
    let csEditTempImage = null;

    window.csDismissPrice = function() {
      if (csState.bodyItems[0]) {
        csState.bodyItems[0].priceHidden = true;
        csUpdatePreview(true);
      }
    };

    window.csShowPrice = function() {
      if (csState.bodyItems[0]) {
        csState.bodyItems[0].priceHidden = false;
        if (!csState.bodyItems[0].price) csState.bodyItems[0].price = '$XX.99';
        csUpdatePreview(true);
      }
    };

    window.csShowPrice4 = function(idx) {
      if (csState.bodyItems[idx]) {
        csState.bodyItems[idx].priceHidden = false;
        csState.bodyItems[idx].cutPriceHidden = false;
        csState.bodyItems[idx].unitHidden = false;
        if (!csState.bodyItems[idx].fullPrice) csState.bodyItems[idx].fullPrice = '$XX.99';
        if (!csState.bodyItems[idx].price) csState.bodyItems[idx].price = '$X.99';
        if (!csState.bodyItems[idx].priceUnit) csState.bodyItems[idx].priceUnit = '/each';
        csUpdatePreview(true);
      }
    };

    window.csDismissPrice4 = function(idx) {
      if (csState.bodyItems[idx]) {
        csState.bodyItems[idx].priceHidden = true;
        csState.bodyItems[idx].cutPriceHidden = true;
        csState.bodyItems[idx].unitHidden = true;
        csUpdatePreview(true);
      }
    };

    // ── 4-Item Text Edit Popup ──
    var csTextEditIndex = -1;

    window.csOpenTextEdit = function(index) {
      csTextEditIndex = index;
      var item = csState.bodyItems[index] || {};
      // Migrate legacy: if priceHidden=true and no new flags, set both hidden
      if (item.priceHidden && item.cutPriceHidden === undefined) {
        item.cutPriceHidden = true;
        item.unitHidden = true;
      }
      // Strip $ prefix from stored values for display
      var rawFull = (item.fullPrice || '$XX.99').replace(/^\$/, '');
      var rawCut = (item.price || '$X.99').replace(/^\$/, '');
      var rawUnit = (item.priceUnit || '/each').replace(/^\//, '');
      document.getElementById('csTeFullPrice').value = rawFull;
      document.getElementById('csTeCutPrice').value = rawCut;
      document.getElementById('csTeUnit').value = rawUnit;
      document.getElementById('csTeName').value = item.name || 'Product Name';
      // Hide name field for 6-item layouts
      document.querySelector('.cs-text-edit-desc').style.display = (csState.bodyCount === 6 || csState.bodyCount === 9) ? 'none' : '';
      // Set visibility of cut/unit wraps
      var cutHidden = !!item.cutPriceHidden;
      var unitHidden = !!item.unitHidden;
      document.getElementById('csTeCutWrap').style.display = cutHidden ? 'none' : '';
      document.getElementById('csTeUnitWrap').style.display = unitHidden ? 'none' : '';
      document.getElementById('csTeCutRow').style.display = (cutHidden && unitHidden) ? 'none' : '';
      document.getElementById('csTeResetBtn').style.display = (cutHidden || unitHidden) ? '' : 'none';
      document.getElementById('csTextEditOverlay').classList.add('open');
    };

    window.csTeDismissCutPrice = function() {
      document.getElementById('csTeCutWrap').style.display = 'none';
      var unitHidden = document.getElementById('csTeUnitWrap').style.display === 'none';
      if (unitHidden) document.getElementById('csTeCutRow').style.display = 'none';
      document.getElementById('csTeResetBtn').style.display = '';
    };

    window.csTeDismissUnit = function() {
      document.getElementById('csTeUnitWrap').style.display = 'none';
      var cutHidden = document.getElementById('csTeCutWrap').style.display === 'none';
      if (cutHidden) document.getElementById('csTeCutRow').style.display = 'none';
      document.getElementById('csTeResetBtn').style.display = '';
    };

    window.csTeReset = function() {
      document.getElementById('csTeCutWrap').style.display = '';
      document.getElementById('csTeUnitWrap').style.display = '';
      document.getElementById('csTeCutRow').style.display = '';
      document.getElementById('csTeResetBtn').style.display = 'none';
      // Restore defaults if empty
      if (!document.getElementById('csTeCutPrice').value) document.getElementById('csTeCutPrice').value = 'X.99';
      if (!document.getElementById('csTeUnit').value) document.getElementById('csTeUnit').value = 'each';
    };

    window.csTextEditSave = function() {
      var item = csState.bodyItems[csTextEditIndex];
      if (!item) return;
      // Read raw values and prepend prefixes
      var rawFull = document.getElementById('csTeFullPrice').value.trim();
      var rawCut = document.getElementById('csTeCutPrice').value.trim();
      var rawUnit = document.getElementById('csTeUnit').value.trim();
      item.fullPrice = rawFull ? '$' + rawFull : '';
      item.price = rawCut ? '$' + rawCut : '';
      item.priceUnit = rawUnit ? '/' + rawUnit : '';
      // Save per-field visibility
      item.cutPriceHidden = document.getElementById('csTeCutWrap').style.display === 'none';
      item.unitHidden = document.getElementById('csTeUnitWrap').style.display === 'none';
      item.priceHidden = false;
      item.name = document.getElementById('csTeName').value;
      document.getElementById('csTextEditOverlay').classList.remove('open');
      csUpdatePreview(true);
    };

    window.csTextEditCancel = function() {
      document.getElementById('csTextEditOverlay').classList.remove('open');
    };

    window.csProductEditSetSource = function(source) {
      var uploadBtn = document.getElementById('csProductEditSrcUpload');
      var libraryBtn = document.getElementById('csProductEditSrcLibrary');
      var napaBtn = document.getElementById('csProductEditSrcNapa');
      uploadBtn.classList.toggle('active', source === 'upload');
      libraryBtn.classList.toggle('active', source === 'library');
      napaBtn.classList.toggle('active', source === 'napa');
      document.getElementById('csProductEditUploadRow').style.display = source === 'upload' ? 'block' : 'none';
      document.getElementById('csProductEditPartRow').style.display = source === 'napa' ? 'block' : 'none';
      if (source === 'library') {
        document.getElementById('csProductEditOverlay').classList.remove('open');
        _libIndex = null;
        _libBgPickerType = 'photo';
        _libFilter = 'image';
        _libProductPickerMode = true;
        _libOpenOverlay(true);
      }
    };

    window.csEditBodyItem = function(index) {
      csEditIndex = index;
      const item = csState.bodyItems[index];
      const overlay = document.getElementById('csProductEditOverlay');

      // Title
      document.getElementById('csProductEditTitle').textContent = item.image ? 'Edit Image' : 'Add Image';

      // Pre-select source tab if item already has one, otherwise show picker with neither active
      if (item.source) {
        csProductEditSetSource(item.source);
      } else {
        document.getElementById('csProductEditSrcUpload').classList.remove('active');
        document.getElementById('csProductEditSrcLibrary').classList.remove('active');
        document.getElementById('csProductEditSrcNapa').classList.remove('active');
        document.getElementById('csProductEditUploadRow').style.display = 'none';
        document.getElementById('csProductEditPartRow').style.display = 'none';
      }

      // Populate fields
      document.getElementById('csProductEditPartNum').value = item.partNum || '';

      // Image preview
      csEditTempImage = item.image || null;
      csProductEditUpdateImgPreview();

      // File input reset
      document.getElementById('csProductEditFile').value = '';

      overlay.classList.add('open');
    };

    function csProductEditUpdateImgPreview() {
      const wrap = document.getElementById('csProductEditImgWrap');
      const placeholder = document.getElementById('csProductEditPlaceholder');
      if (csEditTempImage) {
        wrap.innerHTML = '<img class="cs-product-edit-img-preview" src="' + csEditTempImage + '" onclick="document.getElementById(\'csProductEditFile\').click()" title="Click to change image" />';
      } else {
        wrap.innerHTML = '<div class="cs-product-edit-img-placeholder" onclick="document.getElementById(\'csProductEditFile\').click()">Drag or click to add image</div>';
        csInitDropZone();
      }
    }

    // File upload in overlay → open cropper
    document.getElementById('csProductEditFile').addEventListener('change', function() {
      const file = this.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function(e) {
        // Open cropper with the image
        csCropperOpen(e.target.result, csEditIndex);
      };
      reader.readAsDataURL(file);
    });

    // Drag-and-drop on image placeholder / preview
    function csInitDropZone() {
      const wrap = document.getElementById('csProductEditImgWrap');
      if (!wrap) return;
      wrap.addEventListener('dragover', function(e) {
        e.preventDefault();
        const ph = wrap.querySelector('.cs-product-edit-img-placeholder');
        if (ph) ph.classList.add('drag-over');
      });
      wrap.addEventListener('dragleave', function(e) {
        const ph = wrap.querySelector('.cs-product-edit-img-placeholder');
        if (ph) ph.classList.remove('drag-over');
      });
      wrap.addEventListener('drop', function(e) {
        e.preventDefault();
        const ph = wrap.querySelector('.cs-product-edit-img-placeholder');
        if (ph) ph.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        const reader = new FileReader();
        reader.onload = function(ev) {
          csCropperOpen(ev.target.result, csEditIndex);
        };
        reader.readAsDataURL(file);
      });
    }
    csInitDropZone();

    // Part # lookup in overlay
    document.getElementById('csProductEditPartNum').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        csProductEditLookupPart();
      }
    });
    document.getElementById('csProductEditPartNum').addEventListener('blur', function() {
      csProductEditLookupPart();
    });

    function csProductEditLookupPart() {
      const partNum = document.getElementById('csProductEditPartNum').value.trim();
      if (!partNum || (csState.bodyItems[csEditIndex] && csState.bodyItems[csEditIndex].partNum === partNum)) return;
      csLookupPart(csEditIndex, partNum);
    }

    window.csProductEditSave = function() {
      const item = csState.bodyItems[csEditIndex];
      // Determine source from which button is active
      var isNapa = document.getElementById('csProductEditSrcNapa').classList.contains('active');
      var isUpload = document.getElementById('csProductEditSrcUpload').classList.contains('active');
      var isLibrary = document.getElementById('csProductEditSrcLibrary').classList.contains('active');
      if (isNapa) item.source = 'napa';
      else if (isLibrary) item.source = 'upload';
      else if (isUpload) item.source = 'upload';

      // Save image (may have been updated via cropper or part lookup)
      if (csEditTempImage) {
        item.image = csEditTempImage;
        item._canvasImage = null; // clear so generate re-processes bg removal
      }

      if (isNapa) {
        item.partNum = document.getElementById('csProductEditPartNum').value;
      }

      document.getElementById('csProductEditOverlay').classList.remove('open');
      csUpdatePreview();
    };

    window.csProductEditCancel = function() {
      document.getElementById('csProductEditOverlay').classList.remove('open');
    };

    window.csUploadBodyImage = function(index, input) {
      const file = input.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function(e) {
        csCropperOpen(e.target.result, index);
      };
      reader.readAsDataURL(file);
    };

    // ─── Image Cropper ───
    const csCropper = { imgEl: null, scale: 1, minScale: 1, x: 0, y: 0, dragging: false, startX: 0, startY: 0, frameW: 0, frameH: 0, natW: 0, natH: 0, index: -1, lastDist: 0, rotation: 0 };

    function csCropperOpen(dataUrl, index) {
      var cropW, cropH;
      const item = csState.bodyItems[index];
      const layout = item.layout || 'text-image';
      if (csState.bodyCount === 9) {
        cropW = layout === 'image-only' ? 180 : 176;
        cropH = layout === 'image-only' ? 180 : 120;
      } else if (csState.bodyCount === 6) {
        cropW = layout === 'image-only' ? 180 : 176;
        cropH = layout === 'image-only' ? 163 : 120;
      } else if (csState.bodyCount === 4) {
        cropW = layout === 'image-only' ? 283 : 147;
        cropH = layout === 'image-only' ? 163 : 176;
      } else {
        cropW = layout === 'image-only' ? 590 : 317;
        cropH = 352;
      }
      // Scale up the display so the cropper is comfortable to work with
      var minDim = Math.min(cropW, cropH);
      var ds = minDim < 300 ? Math.min(400 / minDim, 3.5) : 1;
      csCropper.cropW = cropW;
      csCropper.cropH = cropH;
      csCropper.displayScale = ds;
      csCropper.frameW = Math.round(cropW * ds);
      csCropper.frameH = Math.round(cropH * ds);
      csCropper.index = index;

      const overlay = document.getElementById('csCropperOverlay');
      const frame = document.getElementById('csCropperFrame');
      const img = document.getElementById('csCropperImg');
      const slider = document.getElementById('csCropperZoomSlider');

      frame.style.width = csCropper.frameW + 'px';
      frame.style.height = csCropper.frameH + 'px';

      img.onload = function() {
        csCropper.natW = img.naturalWidth;
        csCropper.natH = img.naturalHeight;
        csCropper.rotation = 0;
        csCropperRecalcScale();
        slider.min = Math.round(csCropper.minScale * 100);
        slider.max = Math.round(csCropper.minScale * 250);
        slider.value = Math.round(csCropper.scale * 100);
        csCropperApply();
      };
      img.crossOrigin = 'anonymous';
      img.src = dataUrl;
      overlay.classList.add('open');
    }

    // Get effective dimensions based on rotation (90/270 swaps W/H)
    function csCropperEffective() {
      const r = csCropper.rotation % 360;
      const swapped = (r === 90 || r === 270);
      return { w: swapped ? csCropper.natH : csCropper.natW, h: swapped ? csCropper.natW : csCropper.natH };
    }

    function csCropperRecalcScale() {
      const eff = csCropperEffective();
      const scaleX = csCropper.frameW / eff.w;
      const scaleY = csCropper.frameH / eff.h;
      csCropper.minScale = Math.max(scaleX, scaleY);
      csCropper.scale = csCropper.minScale;
      csCropper.x = (csCropper.frameW - eff.w * csCropper.scale) / 2;
      csCropper.y = (csCropper.frameH - eff.h * csCropper.scale) / 2;
    }

    function csCropperApply() {
      const img = document.getElementById('csCropperImg');
      const eff = csCropperEffective();
      const scaledW = eff.w * csCropper.scale;
      const scaledH = eff.h * csCropper.scale;
      csCropper.x = Math.min(0, Math.max(csCropper.frameW - scaledW, csCropper.x));
      csCropper.y = Math.min(0, Math.max(csCropper.frameH - scaledH, csCropper.y));
      // Build transform: translate to position, then rotate around the center of the scaled image
      const cx = csCropper.natW * csCropper.scale / 2;
      const cy = csCropper.natH * csCropper.scale / 2;
      img.style.transform = 'translate(' + csCropper.x + 'px,' + csCropper.y + 'px) translate(' + cx + 'px,' + cy + 'px) rotate(' + csCropper.rotation + 'deg) translate(-' + cx + 'px,-' + cy + 'px) scale(' + csCropper.scale + ')';
    }

    window.csCropperRotate = function() {
      csCropper.rotation = (csCropper.rotation + 90) % 360;
      csCropperRecalcScale();
      const slider = document.getElementById('csCropperZoomSlider');
      slider.min = Math.round(csCropper.minScale * 100);
      slider.max = Math.round(csCropper.minScale * 250);
      slider.value = Math.round(csCropper.scale * 100);
      csCropperApply();
    };

    // Mouse drag
    document.addEventListener('DOMContentLoaded', function() {
      const frame = document.getElementById('csCropperFrame');
      frame.addEventListener('mousedown', function(e) { csCropper.dragging = true; csCropper.startX = e.clientX - csCropper.x; csCropper.startY = e.clientY - csCropper.y; e.preventDefault(); });
      window.addEventListener('mousemove', function(e) { if (!csCropper.dragging) return; csCropper.x = e.clientX - csCropper.startX; csCropper.y = e.clientY - csCropper.startY; csCropperApply(); });
      window.addEventListener('mouseup', function() { csCropper.dragging = false; });

      // Scroll zoom
      frame.addEventListener('wheel', function(e) {
        e.preventDefault();
        const rect = frame.getBoundingClientRect();
        const mx = e.clientX - rect.left, my = e.clientY - rect.top;
        const oldScale = csCropper.scale;
        csCropper.scale *= e.deltaY < 0 ? 1.03 : 0.971;
        csCropper.scale = Math.max(csCropper.minScale, csCropper.scale);
        const ratio = csCropper.scale / oldScale;
        csCropper.x = mx - (mx - csCropper.x) * ratio;
        csCropper.y = my - (my - csCropper.y) * ratio;
        document.getElementById('csCropperZoomSlider').value = Math.round(csCropper.scale * 100);
        csCropperApply();
      }, { passive: false });

      // Touch pan + pinch zoom
      frame.addEventListener('touchstart', function(e) {
        if (e.touches.length === 1) { csCropper.dragging = true; csCropper.startX = e.touches[0].clientX - csCropper.x; csCropper.startY = e.touches[0].clientY - csCropper.y; }
        if (e.touches.length === 2) { csCropper.lastDist = Math.hypot(e.touches[1].clientX - e.touches[0].clientX, e.touches[1].clientY - e.touches[0].clientY); }
        e.preventDefault();
      }, { passive: false });
      frame.addEventListener('touchmove', function(e) {
        if (e.touches.length === 1 && csCropper.dragging) { csCropper.x = e.touches[0].clientX - csCropper.startX; csCropper.y = e.touches[0].clientY - csCropper.startY; csCropperApply(); }
        if (e.touches.length === 2) {
          const dist = Math.hypot(e.touches[1].clientX - e.touches[0].clientX, e.touches[1].clientY - e.touches[0].clientY);
          if (csCropper.lastDist) {
            const rect = frame.getBoundingClientRect();
            const cx = (e.touches[0].clientX + e.touches[1].clientX) / 2 - rect.left;
            const cy = (e.touches[0].clientY + e.touches[1].clientY) / 2 - rect.top;
            const oldScale = csCropper.scale;
            csCropper.scale *= dist / csCropper.lastDist;
            csCropper.scale = Math.max(csCropper.minScale, csCropper.scale);
            const ratio = csCropper.scale / oldScale;
            csCropper.x = cx - (cx - csCropper.x) * ratio;
            csCropper.y = cy - (cy - csCropper.y) * ratio;
            document.getElementById('csCropperZoomSlider').value = Math.round(csCropper.scale * 100);
            csCropperApply();
          }
          csCropper.lastDist = dist;
        }
        e.preventDefault();
      }, { passive: false });
      frame.addEventListener('touchend', function() { csCropper.dragging = false; csCropper.lastDist = 0; });

      // Zoom slider
      document.getElementById('csCropperZoomSlider').addEventListener('input', function() {
        const rect = document.getElementById('csCropperFrame').getBoundingClientRect();
        const cx = csCropper.frameW / 2, cy = csCropper.frameH / 2;
        const oldScale = csCropper.scale;
        csCropper.scale = Math.max(csCropper.minScale, parseInt(this.value) / 100);
        const ratio = csCropper.scale / oldScale;
        csCropper.x = cx - (cx - csCropper.x) * ratio;
        csCropper.y = cy - (cy - csCropper.y) * ratio;
        csCropperApply();
      });
    });

    window.csCropperSave = function() {
      const outW = csCropper.cropW;
      const outH = csCropper.cropH;
      const canvas = document.createElement('canvas');
      canvas.width = outW;
      canvas.height = outH;
      const ctx = canvas.getContext('2d');
      const img = document.getElementById('csCropperImg');
      const eff = csCropperEffective();
      // Source rect: map display frame viewport back to rotated image coordinates
      const sx = -csCropper.x / csCropper.scale;
      const sy = -csCropper.y / csCropper.scale;
      const sw = csCropper.frameW / csCropper.scale;
      const sh = csCropper.frameH / csCropper.scale;
      if (csCropper.rotation === 0) {
        ctx.drawImage(img, sx, sy, sw, sh, 0, 0, outW, outH);
      } else {
        // Draw rotated: create a temp canvas with the rotated full image, then crop from it
        const tmpCanvas = document.createElement('canvas');
        tmpCanvas.width = eff.w;
        tmpCanvas.height = eff.h;
        const tmpCtx = tmpCanvas.getContext('2d');
        tmpCtx.translate(eff.w / 2, eff.h / 2);
        tmpCtx.rotate(csCropper.rotation * Math.PI / 180);
        tmpCtx.drawImage(img, -csCropper.natW / 2, -csCropper.natH / 2);
        ctx.drawImage(tmpCanvas, sx, sy, sw, sh, 0, 0, outW, outH);
      }
      const croppedData = canvas.toDataURL('image/jpeg', 0.92);
      document.getElementById('csCropperOverlay').classList.remove('open');

      if (document.getElementById('csProductEditOverlay').classList.contains('open')) {
        csEditTempImage = croppedData;
        csProductEditUpdateImgPreview();
      } else {
        csState.bodyItems[csCropper.index].image = croppedData;
        csState.bodyItems[csCropper.index].source = 'upload';
        csState.bodyItems[csCropper.index]._canvasImage = null;
        csUpdatePreview();
      }
    };

    window.csCropperCancel = function() {
      document.getElementById('csCropperOverlay').classList.remove('open');
    };

    window.csLookupPart = function(index, input) {
      const partNum = typeof input === 'string' ? input : (input.value || '').trim();
      if (!partNum) return;
      // Prevent double-fetch if value hasn't changed
      if (csState.bodyItems[index].partNum === partNum) return;
      csState.bodyItems[index].partNum = partNum;

      fetch(`${WORKER_BASE}/admin/napa-part-search`, {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ partNumber: partNum })
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) {
            // API returned an error — clear partNum so user can retry
            csState.bodyItems[index].partNum = '';
            console.warn('Part lookup error:', data.error);
            return;
          }
          if (data.title) {
            let title = data.title.split(/\s*[\|]\s*/)[0].replace(/\s*-\s*NAPA.*$/i, '').trim();
            // Strip trailing part numbers (e.g. "CHT CCBC12V20AEA", "APX 82804", "FNY 60003", "AUV 19712")
            title = title.replace(/\s+[A-Z]{2,5}\s*[A-Z0-9]{3,}$/i, '').trim();
            csState.bodyItems[index].name = title;
          }
          if (data.price) {
            var formattedPrice = '$' + parseFloat(data.price).toFixed(2);
            csState.bodyItems[index].fullPrice = formattedPrice;
            csState.bodyItems[index].price = formattedPrice;
          }
          if (data.image) {
            const proxyUrl = `${WORKER_BASE}/admin/proxy-image?url=` + encodeURIComponent(data.image);
            // Save original for Cloudinary bg removal at generate time
            csState.bodyItems[index].originalImage = proxyUrl;
            csState.bodyItems[index]._canvasImage = null;
            // Remove white bg for preview (fast client-side)
            csRemoveBg(proxyUrl).then(function(cleanUrl) {
              csState.bodyItems[index].image = cleanUrl;
              csUpdatePreview(true);
              if (document.getElementById('csProductEditOverlay').classList.contains('open') && csEditIndex === index) {
                csEditTempImage = cleanUrl;
                csProductEditUpdateImgPreview();
              }
            });
          }
          csUpdatePreview(true);
        })
        .catch(err => {
          // Network error — clear partNum so user can retry
          csState.bodyItems[index].partNum = '';
          console.warn('Part lookup failed', err);
        });
    };

    // ─── Step Next Button ───
    window.csStepNext = function(stepId) {
      if (stepId === 'csStepGraphic') {
        if (!csState.graphicId || !csState.bgType) return;
        // For video bg, require a video to be ready
        if (csState.bgType === 'video' && !csState.videoUrl) {
          showToast('Generate or select a video first.', 'error', document.querySelector('#csStepGraphic .cs-step-next'));
          return;
        }
        document.getElementById('csStepGraphic').classList.add('completed');
        document.getElementById('csStartOverRow').style.display = 'block';
        csShowStep('csStepTitle');
        csUpdatePreview();
      } else if (stepId === 'csStepTitle') {
        document.getElementById('csStepTitle').classList.add('completed');
        csShowStep('csStepOffer');
        // Initialize offer content if not yet set
        if (!csState.offerMode) {
          csState.offerMode = 'none';
          csState.offerType = 'none';
          csRenderOfferContent();
          document.getElementById('csOfferBoltRow').style.opacity = '0.3';
          document.getElementById('csOfferBoltRow').style.pointerEvents = 'none';
        }
      } else if (stepId === 'csStepOffer') {
        document.getElementById('csStepOffer').classList.add('completed');
        if (csState.bgType === 'video') {
          // Skip Products step for video — go straight to actions
          csState.bodyCount = 0;
          csState.bodyItems = [];
          document.getElementById('csActions').style.display = 'flex';
        } else {
          csShowStep('csStepBody');
          // Show 9-item option only when no offer bar
          var btn9 = document.getElementById('csBodyCount9Btn');
          if (btn9) btn9.style.display = csState.offerMode === 'none' ? '' : 'none';
          // Show "None" products option only when background is an uploaded photo
          var btn0 = document.getElementById('csBodyCount0Btn');
          if (btn0) btn0.style.display = csState.bgType === 'photo' ? '' : 'none';
          document.getElementById('csActions').style.display = 'flex';
        }
      }
    };

    // ─── Step Visibility ───
    function csShowStep(id) {
      const el = document.getElementById(id);
      el.classList.remove('hidden');
      // Accordion: collapse all other steps, expand this one
      document.querySelectorAll('.cs-step:not(.hidden)').forEach(s => {
        if (s.id !== id) s.classList.add('collapsed');
      });
      el.classList.remove('collapsed');
      // Scroll into view
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    window.csToggleStep = function(id) {
      const el = document.getElementById(id);
      if (el.classList.contains('collapsed')) {
        // Expand this, collapse others
        document.querySelectorAll('.cs-step:not(.hidden)').forEach(s => s.classList.add('collapsed'));
        el.classList.remove('collapsed');
      } else {
        el.classList.add('collapsed');
      }
    };
    function csHideStepsAfter(id) {
      const steps = ['csStepGraphic', 'csStepTitle', 'csStepOffer', 'csStepBody'];
      let found = false;
      steps.forEach(s => {
        if (found) {
          document.getElementById(s).classList.add('hidden');
        }
        if (s === id) found = true;
      });
      document.getElementById('csActions').style.display = 'none';
      document.getElementById('csRendered').style.display = 'none';
    }

    // ─── Build Offer Bar (called once per offer type selection) ───
    function csBuildOfferBar() {
      const prevOfferBar = document.getElementById('csPrevOfferBar');
      if (!csState.offerType || csState.offerType === 'none') return;
      var mode = csState.offerMode;
      // Scale factor for video mode (450/640 ≈ 0.703)
      var vm = csState.bgType === 'video';
      var s = function(v) { return Math.round(vm ? v * 0.703 : v); };
      const i = 'border:0;outline:0;background:transparent;padding:0;margin:0;border-radius:0;font-family:inherit;font-weight:inherit;color:inherit;';

      // Helper: build badge HTML
      function buildBadgeHtml() {
        var cfg = CS_OFFER_TYPES[csState.offerType];
        if (!cfg || !cfg.badge) return '';
        const badgeTextColor = cfg.badge.startsWith('yellow') ? '#1D3489' : '#fff';
        const isUpTo = cfg.hasStartingAt;
        const numTop = isUpTo ? '70%' : '61%';
        const numSize = s(isUpTo ? 65 : 78);
        const pctSize = s(isUpTo ? 32 : 34);
        const pctTop = s(isUpTo ? 14 : 18) + 'px';
        var badgeW = s(171), badgeH = s(151);
        return '<div style="position:relative;width:' + badgeW + 'px;height:' + badgeH + 'px;">' +
          '<img src="/assets/mms/offer-badges/' + cfg.badge + '.svg" style="width:100%;height:100%;" />' +
          '<div style="position:absolute;top:' + numTop + ';left:0;right:0;transform:translateY(-50%);color:' + badgeTextColor + ';font-weight:900;line-height:1;text-align:center;">' +
            '<span style="position:relative;font-size:' + numSize + 'px;letter-spacing:-.5px;">' +
              '<input id="csInlineSave" autocomplete="off" onfocus="this.select()" type="text" value="' + (csState.offerSave || '') + '" placeholder="0" maxlength="2" inputmode="numeric" style="' + i + 'font-size:inherit;width:2ch;height:1em;text-align:center;color:inherit;letter-spacing:inherit;" />' +
              '<span style="position:absolute;left:100%;top:' + pctTop + ';font-size:' + pctSize + 'px;">%</span>' +
            '</span>' +
          '</div>' +
        '</div>';
      }

      prevOfferBar.innerHTML = '<div id="csPrevOfferLeft"></div><div id="csPrevOfferRight"></div>';
      const leftEl = document.getElementById('csPrevOfferLeft');
      const rightEl = document.getElementById('csPrevOfferRight');

      if (mode === 'text') {
        // Text offer
        const txt = csState.offerText || 'Click here to edit offer.';
        const isGrayBg = csState.bgValue === '#D1D3D4';
        const textColor = isGrayBg ? '#F9C842' : '#fff';
        var fontSize = s(48);
        var lineH = Math.round(fontSize * 1.15);
        var maxH = lineH * 2 + 4; // 2 lines max
        if (csState.offerHasBadge) {
          // Text + badge: text on left (clipped to 2 lines), badge on right
          leftEl.style.cssText = 'flex:1;display:flex;align-items:center;overflow:hidden;';
          leftEl.innerHTML = '<div style="width:100%;color:' + textColor + ';font-weight:900;font-size:' + fontSize + 'px;line-height:' + lineH + 'px;max-height:' + maxH + 'px;overflow:hidden;" class="cs-editable" contenteditable="true" id="csPrevOfferTextEdit">' + txt + '</div>';
          rightEl.innerHTML = buildBadgeHtml();
          var saveEl = document.getElementById('csInlineSave');
          if (saveEl) saveEl.addEventListener('input', function() { csState.offerSave = this.value; });
        } else {
          // Text only, full width
          leftEl.style.cssText = 'flex:1;display:flex;align-items:center;';
          leftEl.innerHTML = '<div style="width:100%;text-align:center;color:' + textColor + ';font-weight:900;font-size:' + fontSize + 'px;line-height:' + lineH + 'px;" class="cs-editable" contenteditable="true" id="csPrevOfferTextEdit">' + txt + '</div>';
          rightEl.innerHTML = '';
        }
        var textEditEl = document.getElementById('csPrevOfferTextEdit');
        if (textEditEl) {
          var offerLastGood = txt;
          textEditEl.addEventListener('input', function() {
            if (this.scrollHeight > 146) { this.textContent = offerLastGood; } else { offerLastGood = this.textContent; }
          });
          textEditEl.addEventListener('blur', function() { csState.offerText = this.textContent; });
        }
      } else if (mode === 'price') {
        // Price offer
        var cfg = CS_OFFER_TYPES[csState.offerType];
        var big = !cfg.hasStartingAt;
        var startAt = cfg.hasStartingAt ? '<div style="color:#fff;font-weight:900;font-size:' + s(30) + 'px;text-transform:uppercase;line-height:1;">STARTING AT</div>' : '';
        leftEl.innerHTML = startAt +
          '<div style="display:flex;align-items:flex-start;line-height:1;font-weight:900;color:#fff;">' +
            '<span style="font-size:' + s(big ? 59 : 49) + 'px;">$</span>' +
            '<input id="csInlineDollars" autocomplete="off" onfocus="this.select()" type="text" value="' + (csState.offerDollars || '') + '" placeholder="0" maxlength="3" inputmode="numeric" style="' + i + 'font-size:' + s(big ? 101 : 84) + 'px;line-height:.9;width:' + Math.max(1, (csState.offerDollars || '').length) + 'ch;height:.9em;" />' +
            '<span style="display:inline-flex;flex-direction:column;line-height:1;">' +
              '<input id="csInlineCents" autocomplete="off" onfocus="this.select()" type="text" value="' + (csState.offerCents || '') + '" placeholder="99" maxlength="2" inputmode="numeric" style="' + i + 'font-size:' + s(big ? 60 : 50) + 'px;width:2ch;height:1em;" />' +
              '<input id="csInlineUnit" autocomplete="off" onfocus="this.select()" type="text" value="' + (csState.offerUnit || '') + '" placeholder="/each" maxlength="10" style="' + i + 'font-weight:300;font-size:' + s(big ? 28 : 23) + 'px;line-height:1;width:8ch;height:1.25em;" />' +
            '</span>' +
          '</div>';

        if (csState.offerHasBadge) {
          rightEl.innerHTML = buildBadgeHtml();
          var saveEl2 = document.getElementById('csInlineSave');
          if (saveEl2) saveEl2.addEventListener('input', function() { csState.offerSave = this.value; });
        } else {
          // Short text to the right of price — 2 line max
          var shortTxt = csState.offerShortText || 'Click to add quick offer.';
          var fontSize = s(40);
          var lineH = Math.round(fontSize * 1.15);
          var maxH = lineH * 2 + 4; // 2 lines + small buffer
          rightEl.style.cssText = 'flex:1;display:flex;align-items:center;justify-content:center;overflow:hidden;margin-left:' + s(22) + 'px;';
          rightEl.innerHTML = '<div style="color:#fff;font-weight:900;font-size:' + fontSize + 'px;line-height:' + lineH + 'px;text-align:center;max-height:' + maxH + 'px;overflow:hidden;" class="cs-editable" contenteditable="true" id="csPrevOfferShortTextEdit">' + shortTxt + '</div>';
          var shortEditEl = document.getElementById('csPrevOfferShortTextEdit');
          if (shortEditEl) {
            var shortLastGood = shortTxt;
            shortEditEl.addEventListener('input', function() {
              if (this.scrollHeight > maxH) {
                this.textContent = shortLastGood;
              } else {
                shortLastGood = this.textContent;
              }
            });
            shortEditEl.addEventListener('blur', function() {
              csState.offerShortText = this.textContent;
            });
          }
        }

        // Bind inline price input listeners
        var dollarsEl = document.getElementById('csInlineDollars');
        if (dollarsEl) {
          dollarsEl.addEventListener('input', function() {
            csState.offerDollars = this.value;
            this.style.width = Math.max(1, this.value.length) + 'ch';
          });
        }
        var centsEl = document.getElementById('csInlineCents');
        if (centsEl) centsEl.addEventListener('input', function() { csState.offerCents = this.value; });
        var unitEl = document.getElementById('csInlineUnit');
        if (unitEl) unitEl.addEventListener('input', function() { csState.offerUnit = this.value; });
      }
    }

    // ─── Preview Update ───
    function csUpdatePreview(skipCapture) {
      // Capture inline-editable body text before rebuilding (skip when state was just set programmatically)
      if (!skipCapture) {
        if (csState.bodyCount > 1) {
          for (var ci = 0; ci < csState.bodyItems.length; ci++) {
            var mfpEl = document.getElementById('csPrevBodyFullPrice' + ci);
            var mpEl = document.getElementById('csPrevBodyPrice' + ci);
            var mnEl = document.getElementById('csPrevBodyName' + ci);
            if (mfpEl && csState.bodyItems[ci]) csState.bodyItems[ci].fullPrice = mfpEl.textContent;
            if (mpEl && csState.bodyItems[ci]) csState.bodyItems[ci].price = mpEl.textContent;
            if (mnEl && csState.bodyItems[ci]) csState.bodyItems[ci].name = mnEl.textContent;
          }
        } else {
          var priceEl = document.getElementById('csPrevBodyPrice');
          var nameEl = document.getElementById('csPrevBodyName');
          if (priceEl && csState.bodyItems[0]) csState.bodyItems[0].price = priceEl.textContent;
          if (nameEl && csState.bodyItems[0]) csState.bodyItems[0].name = nameEl.textContent;
        }
      }

      const g = CS_BRAND_GRAPHICS.find(gr => gr.id === csState.graphicId);
      const prevBg = document.getElementById('csPrevBg');
      const prevGraphic = document.getElementById('csPrevGraphic');
      const prevTitleBar = document.getElementById('csPrevTitleBar');
      const prevOfferBar = document.getElementById('csPrevOfferBar');
      const canvas = document.getElementById('csCanvas');

      // ── Toggle video-mode aspect ratio ──
      var isVideoMode = csState.bgType === 'video';
      canvas.classList.toggle('video-mode', isVideoMode);
      var wrap = canvas.closest('.cs-canvas-wrap');
      if (wrap) wrap.classList.toggle('video-mode', isVideoMode);
      var canvasW = isVideoMode ? 450 : 640;
      var canvasH = 800;

      // ── Background (always update, even without graphic) ──
      prevBg.className = 'cs-prev-bg';
      prevBg.style.backgroundImage = '';
      // Remove any existing video element in bg
      var existingVid = prevBg.querySelector('video');
      if (existingVid) existingVid.remove();

      if (csState.bgType === 'video' && csState.videoUrl) {
        prevBg.style.backgroundColor = '#000';
        // Insert video element for preview
        var vid = prevBg.querySelector('video');
        if (!vid) {
          vid = document.createElement('video');
          vid.style.cssText = 'width:100%;height:100%;object-fit:cover;position:absolute;top:0;left:0;z-index:10;';
          vid.muted = true;
          vid.loop = true;
          vid.playsInline = true;
          vid.autoplay = true;
          vid.controls = true;
          prevBg.appendChild(vid);
        }
        if (vid.src !== csState.videoUrl) vid.src = csState.videoUrl;
      } else if (csState.bgType === 'graphic') {
        prevBg.style.backgroundColor = csState.bgValue;
      } else if (csState.bgType === 'bolt') {
        const patternFile = csState.color === 'blue' ? 'yellow-pattern-bg-full' : 'gold-pattern-bg-full';
        prevBg.style.backgroundImage = 'url(/assets/mms/' + patternFile + '.svg)';
        prevBg.style.backgroundSize = '100% 100%';
        prevBg.style.backgroundColor = csState.bgValue;
      } else if (csState.bgType === 'photo' && csState.bgRawImage) {
        prevBg.style.backgroundImage = 'url(' + csState.bgRawImage + ')';
        prevBg.style.backgroundSize = (csState.bgNatW * csState.bgScale) + 'px ' + (csState.bgNatH * csState.bgScale) + 'px';
        prevBg.style.backgroundPosition = csState.bgX + 'px ' + csState.bgY + 'px';
        prevBg.style.backgroundRepeat = 'no-repeat';
        prevBg.style.backgroundColor = '#333';
      } else {
        prevBg.style.backgroundColor = '#ddd';
      }
      // Show/hide mute button for video preview
      csUpdateMuteBtn();
      // Toggle drag hint + cursor (only for photo bg)
      var isBgUpload = csState.bgType === 'photo' && csState.bgRawImage;
      canvas.classList.toggle('bg-draggable', !!isBgUpload);
      var hint = document.getElementById('csBgHint');
      if (hint) hint.style.display = isBgUpload ? 'block' : 'none';

      if (!g) {
        prevGraphic.style.display = 'none';
        prevTitleBar.style.display = 'none';
        prevOfferBar.style.display = 'none';
        document.getElementById('csPrevBody').style.display = 'none';
        return;
      }

      // ── Brand Graphic SVG ──
      const svgFile = g.file || g.id;
      prevGraphic.src = '/assets/mms/brand-graphics/' + svgFile + '.svg';
      prevGraphic.style.display = 'block';
      // Position the graphic (use video coords when in video mode)
      var gx = isVideoMode && g.vx != null ? g.vx : g.x;
      var gy = isVideoMode && g.vy != null ? g.vy : g.y;
      var gw = isVideoMode && g.vw != null ? g.vw : g.w;
      var gh = isVideoMode && g.vh != null ? g.vh : g.h;
      const pctX = (gx / canvasW * 100).toFixed(2);
      const pctY = (gy / canvasH * 100).toFixed(2);
      const pctW = (gw / canvasW * 100).toFixed(2);
      const pctH = (gh / canvasH * 100).toFixed(2);
      prevGraphic.style.left = pctX + '%';
      prevGraphic.style.top = pctY + '%';
      prevGraphic.style.width = pctW + '%';
      prevGraphic.style.height = pctH + '%';

      // ── Title/Rules Bar ──
      if (g.position === 'top') {
        prevTitleBar.style.top = 'auto';
        prevTitleBar.style.bottom = '0';
      } else {
        prevTitleBar.style.top = '0';
        prevTitleBar.style.bottom = 'auto';
      }
      // Only show title bar once user has reached the Title step
      var titleStepReached = !document.getElementById('csStepTitle').classList.contains('hidden');
      prevTitleBar.style.display = (csState.showTitle && titleStepReached) ? 'block' : 'none';

      // ── Offer Bar ──
      if (csState.offerType && csState.offerType !== 'none') {
        const cfg = CS_OFFER_TYPES[csState.offerType];
        prevOfferBar.style.display = 'flex';

        // Position: directly adjacent to the brand graphic/badge
        if (g.position === 'top') {
          prevOfferBar.style.top = isVideoMode ? '11.5%' : '16.375%';
          prevOfferBar.style.bottom = 'auto';
        } else {
          prevOfferBar.style.top = 'auto';
          // Offer bar sits right on top of badge (image: 16.375%, video: 13.1% = badge at vy 695/800)
          prevOfferBar.style.bottom = isVideoMode ? '13.1%' : '16.375%';
        }
        // Keep offer bar same pixel height (151px) in both modes
        prevOfferBar.style.height = isVideoMode ? '13.3%' : '18.875%';
        prevOfferBar.style.padding = '0 3.9%';

        // Rebuild offer bar (handles text, text+badge, price, price+badge, price+shorttext)
        csBuildOfferBar();
      } else {
        prevOfferBar.style.display = 'none';
      }

      // ── Subtitle Zone (video mode only) ──
      var subZone = document.getElementById('csPrevSubtitleZone');
      if (isVideoMode) {
        // Matches Creatomate template: subtitles centered around 55-65% from top
        subZone.style.top = '53%';
        subZone.style.bottom = 'auto';
        subZone.style.height = '14%';
        subZone.style.display = 'flex';
      } else {
        subZone.style.display = 'none';
      }

      // ── Body (hidden in video mode — no products) ──
      const prevBody = document.getElementById('csPrevBody');
      if (isVideoMode) {
        prevBody.style.display = 'none';
      } else if (csState.bodyCount > 0 && csState.bodyItems.length > 0) {
        var noOffer = !csState.offerType || csState.offerType === 'none';
        var bodyTop, bodyHeight;
        if (noOffer) {
          bodyTop = g.position === 'top' ? 131 : 95;
          bodyHeight = 574;
        } else {
          bodyTop = g.position === 'top' ? 318 : 131;
          bodyHeight = 352;
        }
        prevBody.style.top = (bodyTop / 800 * 100).toFixed(2) + '%';
        prevBody.style.height = bodyHeight + 'px';
        prevBody.style.display = 'flex';
        prevBody.style.background = '';  // reset inline bg from previous render

        // Placeholder helpers
        const placeholderImg = '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.4);font-size:13px;gap:6px;"><span style="font-size:32px;">&#128247;</span>Click to add image</div>';
        const placeholderImgSmall = '<div style="width:100%;height:70%;background:rgba(255,255,255,.1);border-radius:4px;display:flex;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.4);font-size:11px;gap:4px;"><span style="font-size:20px;">&#128247;</span>Click</div>';

        // 1-item layouts
        if (csState.bodyCount === 1) {
          const item = csState.bodyItems[0];
          const layout = item.layout || 'text-image';
          const isNapa = item.source === 'napa';
          prevBody.style.padding = '0';
          prevBody.style.gap = '0';
          prevBody.style.flexWrap = 'nowrap';
          prevBody.style.alignItems = 'center';
          prevBody.style.justifyContent = 'center';


          if (layout === 'text-image') {
            const showPrice = !item.priceHidden;
            const priceHtml = showPrice
              ? '<div style="position:relative;flex-shrink:0;">' +
                  '<div class="cs-editable cs-body-price" contenteditable="true" id="csPrevBodyPrice" style="color:#D0021B;font-weight:700;font-size:40px;line-height:1.1;text-decoration:line-through;padding-right:28px;">' + (item.price || '$XX.99') + '</div>' +
                  '<span onclick="csDismissPrice()" style="position:absolute;top:-4px;right:0;cursor:pointer;color:rgba(255,255,255,.6);font-size:20px;font-weight:700;line-height:1;padding:4px;background:rgba(0,0,0,.4);border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;" title="Remove cut price">&times;</span>' +
                '</div>'
              : '<div onclick="csShowPrice()" style="cursor:pointer;color:rgba(255,255,255,.45);font-size:14px;padding:4px 0;flex-shrink:0;"><span style="font-size:16px;">+</span> Add cut price</div>';
            if (isNapa) {
              // NAPA: 25px padding each side, two 295px halves
              prevBody.style.background = '';
              prevBody.innerHTML =
                '<div style="display:flex;width:100%;height:352px;padding:0 25px;box-sizing:border-box;background:rgba(0,0,0,.3);">' +
                  '<div style="width:295px;min-width:295px;display:flex;flex-direction:column;padding:16px 10px 16px 0;box-sizing:border-box;overflow:hidden;">' +
                    priceHtml +
                    '<div class="cs-editable cs-body-name" contenteditable="true" id="csPrevBodyName" style="color:#fff;font-weight:600;font-size:40px;line-height:1.2;flex:1;overflow:hidden;word-break:break-word;">' + (item.name || 'Product Name') + '</div>' +
                  '</div>' +
                  '<div class="cs-prev-body-clickable" style="width:295px;min-width:295px;height:352px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;" onclick="csEditBodyItem(0)">' +
                    (item.image ? '<img src="' + item.image + '" style="max-width:295px;max-height:352px;object-fit:contain;" /><div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>' : placeholderImg) +
                  '</div>' +
                '</div>';
            } else {
              // Upload: edge-to-edge, 323px text + 317px image
              prevBody.innerHTML =
                '<div style="display:flex;width:100%;height:352px;">' +
                  '<div style="width:323px;display:flex;flex-direction:column;padding:16px 20px;box-sizing:border-box;background:rgba(0,0,0,.3);overflow:hidden;">' +
                    priceHtml +
                    '<div class="cs-editable cs-body-name" contenteditable="true" id="csPrevBodyName" style="color:#fff;font-weight:600;font-size:40px;line-height:1.2;flex:1;overflow:hidden;word-break:break-word;">' + (item.name || 'Product Name') + '</div>' +
                  '</div>' +
                  '<div class="cs-prev-body-clickable" style="width:317px;min-width:317px;height:352px;background:rgba(0,0,0,.3);overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;" onclick="csEditBodyItem(0)">' +
                    (item.image ? '<img src="' + item.image + '" style="width:100%;height:100%;object-fit:contain;" /><div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>' : placeholderImg) +
                  '</div>' +
                '</div>';
            }
            // Bind blur to save editable text back to state
            var priceEl = document.getElementById('csPrevBodyPrice');
            var nameEl = document.getElementById('csPrevBodyName');
            if (priceEl) {
              priceEl.addEventListener('blur', function() { csState.bodyItems[0].price = this.textContent; });
              priceEl.addEventListener('focus', function() {
                var sel = window.getSelection();
                var range = document.createRange();
                range.selectNodeContents(this);
                sel.removeAllRanges();
                sel.addRange(range);
              });
            }
            if (nameEl) {
              nameEl.addEventListener('blur', function() { csState.bodyItems[0].name = this.textContent; });
              nameEl.addEventListener('focus', function() {
                var sel = window.getSelection();
                var range = document.createRange();
                range.selectNodeContents(this);
                sel.removeAllRanges();
                sel.addRange(range);
              });
            }
          } else {
            // Image only: 590x352 centered (25px padding each side) — clickable
            prevBody.style.justifyContent = 'center';
            prevBody.style.padding = '0';
            prevBody.style.background = '';
            prevBody.innerHTML =
              '<div class="cs-prev-body-clickable" style="width:100%;height:352px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.3);padding:0 25px;box-sizing:border-box;" onclick="csEditBodyItem(0)">' +
                (item.image ? '<img src="' + item.image + '" style="max-width:100%;max-height:100%;object-fit:contain;" /><div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>' : placeholderImg) +
              '</div>';
          }
        } else if (csState.bodyCount === 4) {
          // ─── 4-Item Layouts ───
          var layout4 = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
          prevBody.style.padding = '0';
          prevBody.style.gap = '0';
          prevBody.style.flexWrap = 'nowrap';
          prevBody.style.alignItems = 'center';
          prevBody.style.justifyContent = 'center';

          if (layout4 === 'image-only') {
            // 4-Item Photo Only — 2×2 grid, linear gradient bg
            prevBody.style.background = '';
            var gridHtml = '<div style="display:flex;flex-wrap:wrap;width:100%;height:352px;padding:0 25px;box-sizing:border-box;justify-content:space-between;align-content:space-between;background:linear-gradient(90deg, #fff 0%, rgba(255,255,255,0.3) 80%);">';
            // NAPA: align images toward center; Upload: center in cell
            var cellAligns = [
              { jc: 'flex-end',  ai: 'flex-end'  },  // 0: top-left → push right+down
              { jc: 'flex-start', ai: 'flex-end'  },  // 1: top-right → push left+down
              { jc: 'flex-end',  ai: 'flex-start' },  // 2: bottom-left → push right+up
              { jc: 'flex-start', ai: 'flex-start' }   // 3: bottom-right → push left+up
            ];
            for (var gi = 0; gi < 4; gi++) {
              var gItem = csState.bodyItems[gi] || {};
              var cellNapa = gItem.source === 'napa';
              var cellJc = cellNapa ? cellAligns[gi].jc : 'center';
              var cellAi = cellNapa ? cellAligns[gi].ai : 'center';
              var imgStyle4 = 'max-width:283px;max-height:163px;object-fit:contain;';
              gridHtml += '<div class="cs-prev-body-clickable" style="width:283px;height:163px;overflow:hidden;cursor:pointer;display:flex;align-items:' + cellAi + ';justify-content:' + cellJc + ';position:relative;" onclick="csEditBodyItem(' + gi + ')">';
              if (gItem.image) {
                gridHtml += '<img src="' + gItem.image + '" style="' + imgStyle4 + '" />';
                gridHtml += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                gridHtml += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.4);font-size:11px;gap:4px;background:rgba(0,0,0,.15);border-radius:4px;"><span style="font-size:20px;">&#128247;</span>Click</div>';
              }
              gridHtml += '</div>';
            }
            gridHtml += '</div>';
            prevBody.innerHTML = gridHtml;

          } else {
            // 4-Item Text-Image — 2×2 grid: left=image(147×176), right=price bar(148×56)+desc(148×120)
            prevBody.style.background = '';
            var tiHtml = '<div style="display:flex;flex-wrap:wrap;width:100%;height:352px;padding:0 25px;box-sizing:border-box;background:rgba(0,0,0,0.3);">';
            for (var ti = 0; ti < 4; ti++) {
              var tItem = csState.bodyItems[ti] || {};
              // Price bar content (display only — editing via popup)
              var priceBar4 = '';
              priceBar4 += '<div style="color:#fff;font-weight:900;font-size:24px;line-height:1;">' + (tItem.fullPrice || '$XX.99') + '</div>';
              var showCut4 = !tItem.cutPriceHidden;
              var showUnit4 = !tItem.unitHidden;
              if (showCut4 || showUnit4) {
                priceBar4 += '<div style="display:flex;align-items:baseline;gap:3px;">';
                if (showCut4) priceBar4 += '<span style="color:#FFC836;font-weight:300;font-size:11px;line-height:1;text-decoration:line-through;">' + (tItem.price || '$X.99') + '</span>';
                if (showUnit4) priceBar4 += '<span style="color:#fff;font-size:11px;font-weight:300;">' + (tItem.priceUnit || '/each') + '</span>';
                priceBar4 += '</div>';
              }

              var tCellNapa = tItem.source === 'napa';
              tiHtml += '<div style="width:295px;height:176px;display:flex;overflow:hidden;">';
              // Left: image 147×176
              var tCellBg = tCellNapa ? 'background:linear-gradient(180deg, #fff 60%, #999 100%);' : '';
              var tPlaceholderColor = tCellNapa ? 'color:rgba(0,0,0,.3);' : 'color:rgba(255,255,255,.4);background:rgba(0,0,0,.15);border-radius:4px;';
              tiHtml += '<div class="cs-prev-body-clickable" style="width:147px;height:176px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;' + tCellBg + '" onclick="csEditBodyItem(' + ti + ')">';
              if (tItem.image) {
                tiHtml += '<img src="' + tItem.image + '" style="max-width:147px;max-height:176px;object-fit:contain;" />';
                tiHtml += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                tiHtml += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;' + tPlaceholderColor + 'font-size:10px;gap:3px;"><span style="font-size:18px;">&#128247;</span>Click</div>';
              }
              tiHtml += '</div>';
              // Right panel: price bar (148×56) + description (148×120) — click to open text edit popup
              tiHtml += '<div style="width:148px;height:176px;display:flex;flex-direction:column;overflow:hidden;cursor:pointer;" onclick="csOpenTextEdit(' + ti + ')">';
              // Price bar — solid black, centered
              tiHtml += '<div style="width:148px;height:56px;background:#000;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;">';
              tiHtml += priceBar4;
              tiHtml += '</div>';
              // Description — white bg, centered vertically
              tiHtml += '<div style="width:148px;height:120px;background:#fff;display:flex;align-items:center;justify-content:center;padding:4px 13px;box-sizing:border-box;">';
              tiHtml += '<div style="color:#222;font-weight:300;font-size:16px;line-height:1.25;text-align:left;overflow:hidden;word-break:break-word;max-height:112px;">' + (tItem.name || 'Product Name') + '</div>';
              tiHtml += '</div>';
              tiHtml += '</div>';
              tiHtml += '</div>';
            }
            tiHtml += '</div>';
            prevBody.innerHTML = tiHtml;

            // No blur handlers needed — editing via popup
          }
        } else if (csState.bodyCount === 6) {
          // ─── 6-Item Layouts ───
          var layout6 = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
          prevBody.style.padding = '0';
          prevBody.style.gap = '0';
          prevBody.style.flexWrap = 'nowrap';
          prevBody.style.alignItems = 'center';
          prevBody.style.justifyContent = 'center';

          if (layout6 === 'image-only') {
            // 6-Item Photo Only — 3×2 grid, linear gradient bg
            prevBody.style.background = '';
            var grid6Html = '<div style="display:flex;flex-wrap:wrap;width:100%;height:352px;padding:0 25px;box-sizing:border-box;justify-content:space-between;align-content:space-between;background:linear-gradient(90deg, #fff 0%, rgba(255,255,255,0.3) 80%);">';
            for (var g6 = 0; g6 < 6; g6++) {
              var g6Item = csState.bodyItems[g6] || {};
              var imgStyle6 = 'max-width:180px;max-height:163px;object-fit:contain;';
              grid6Html += '<div class="cs-prev-body-clickable" style="width:180px;height:163px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;position:relative;" onclick="csEditBodyItem(' + g6 + ')">';
              if (g6Item.image) {
                grid6Html += '<img src="' + g6Item.image + '" style="' + imgStyle6 + '" />';
                grid6Html += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                grid6Html += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.4);font-size:11px;gap:4px;background:rgba(0,0,0,.15);border-radius:4px;"><span style="font-size:20px;">&#128247;</span>Click</div>';
              }
              grid6Html += '</div>';
            }
            grid6Html += '</div>';
            prevBody.innerHTML = grid6Html;

          } else {
            // 6-Item Text-Image — 3×2 grid: image (176×120) + price bar (176×56)
            prevBody.style.background = '';
            var ti6Html = '<div style="display:flex;flex-wrap:wrap;width:100%;height:352px;padding:0 8px;box-sizing:border-box;column-gap:48px;row-gap:0;background:rgba(0,0,0,0.3);">';
            for (var t6 = 0; t6 < 6; t6++) {
              var t6Item = csState.bodyItems[t6] || {};
              // Price bar content
              var priceBar6 = '';
              priceBar6 += '<div style="color:#fff;font-weight:900;font-size:20px;line-height:1;">' + (t6Item.fullPrice || '$XX.99') + '</div>';
              var showCut6 = !t6Item.cutPriceHidden;
              var showUnit6 = !t6Item.unitHidden;
              if (showCut6 || showUnit6) {
                priceBar6 += '<div style="display:flex;align-items:baseline;gap:3px;">';
                if (showCut6) priceBar6 += '<span style="color:#FFC836;font-weight:300;font-size:10px;line-height:1;text-decoration:line-through;">' + (t6Item.price || '$X.99') + '</span>';
                if (showUnit6) priceBar6 += '<span style="color:#fff;font-size:10px;font-weight:300;">' + (t6Item.priceUnit || '/each') + '</span>';
                priceBar6 += '</div>';
              }

              var t6CellNapa = t6Item.source === 'napa';
              ti6Html += '<div style="width:176px;height:176px;display:flex;flex-direction:column;overflow:hidden;">';
              // Top: image 176×120
              var t6CellBg = t6CellNapa ? 'background:linear-gradient(180deg, #fff 60%, #999 100%);' : '';
              var t6PlaceholderColor = t6CellNapa ? 'color:rgba(0,0,0,.3);' : 'color:rgba(255,255,255,.4);background:rgba(0,0,0,.15);border-radius:4px;';
              ti6Html += '<div class="cs-prev-body-clickable" style="width:176px;height:120px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;' + t6CellBg + '" onclick="csEditBodyItem(' + t6 + ')">';
              if (t6Item.image) {
                ti6Html += '<img src="' + t6Item.image + '" style="max-width:176px;max-height:120px;object-fit:contain;" />';
                ti6Html += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                ti6Html += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;' + t6PlaceholderColor + 'font-size:10px;gap:3px;"><span style="font-size:18px;">&#128247;</span>Click</div>';
              }
              ti6Html += '</div>';
              // Bottom: price bar (176×56, solid black) — click to open text edit
              ti6Html += '<div style="width:176px;height:56px;background:#000;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;cursor:pointer;" onclick="csOpenTextEdit(' + t6 + ')">';
              ti6Html += priceBar6;
              ti6Html += '</div>';
              ti6Html += '</div>';
            }
            ti6Html += '</div>';
            prevBody.innerHTML = ti6Html;
          }
        } else if (csState.bodyCount === 9) {
          // ─── 9-Item Preview ───
          var layout9 = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
          prevBody.style.padding = '0';
          prevBody.style.gap = '0';
          prevBody.style.flexWrap = 'nowrap';
          prevBody.style.alignItems = 'center';
          prevBody.style.justifyContent = 'center';

          if (layout9 === 'image-only') {
            prevBody.style.background = '';
            var grid9Html = '<div style="display:flex;flex-wrap:wrap;width:100%;height:' + bodyHeight + 'px;padding:0 25px;box-sizing:border-box;justify-content:space-between;align-content:space-between;background:linear-gradient(90deg, #fff 0%, rgba(255,255,255,0.3) 80%);">';
            for (var g9 = 0; g9 < 9; g9++) {
              var g9Item = csState.bodyItems[g9] || {};
              grid9Html += '<div class="cs-prev-body-clickable" style="width:180px;height:180px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;position:relative;" onclick="csEditBodyItem(' + g9 + ')">';
              if (g9Item.image) {
                grid9Html += '<img src="' + g9Item.image + '" style="max-width:180px;max-height:180px;object-fit:contain;" />';
                grid9Html += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                grid9Html += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.4);font-size:11px;gap:4px;background:rgba(0,0,0,.15);border-radius:4px;"><span style="font-size:20px;">&#128247;</span>Click</div>';
              }
              grid9Html += '</div>';
            }
            grid9Html += '</div>';
            prevBody.innerHTML = grid9Html;
          } else {
            // Text-Image: 3×3 grid, 176×176 cells (image 176×120 + price bar 176×56)
            prevBody.style.background = '';
            var ti9Html = '<div style="display:flex;flex-wrap:wrap;width:100%;height:' + bodyHeight + 'px;padding:23px 8px;box-sizing:border-box;column-gap:48px;row-gap:0;background:rgba(0,0,0,0.3);">';
            for (var t9 = 0; t9 < 9; t9++) {
              var t9Item = csState.bodyItems[t9] || {};
              var priceBar9 = '';
              priceBar9 += '<div style="color:#fff;font-weight:900;font-size:20px;line-height:1;">' + (t9Item.fullPrice || '$XX.99') + '</div>';
              var showCut9 = !t9Item.cutPriceHidden;
              var showUnit9 = !t9Item.unitHidden;
              if (showCut9 || showUnit9) {
                priceBar9 += '<div style="display:flex;align-items:baseline;gap:3px;">';
                if (showCut9) priceBar9 += '<span style="color:#FFC836;font-weight:300;font-size:10px;line-height:1;text-decoration:line-through;">' + (t9Item.price || '$X.99') + '</span>';
                if (showUnit9) priceBar9 += '<span style="color:#fff;font-size:10px;font-weight:300;">' + (t9Item.priceUnit || '/each') + '</span>';
                priceBar9 += '</div>';
              }
              var t9CellNapa = t9Item.source === 'napa';
              ti9Html += '<div style="width:176px;height:176px;display:flex;flex-direction:column;overflow:hidden;">';
              var t9CellBg = t9CellNapa ? 'background:linear-gradient(180deg, #fff 60%, #999 100%);' : '';
              var t9PlaceholderColor = t9CellNapa ? 'color:rgba(0,0,0,.3);' : 'color:rgba(255,255,255,.4);background:rgba(0,0,0,.15);border-radius:4px;';
              ti9Html += '<div class="cs-prev-body-clickable" style="width:176px;height:120px;overflow:hidden;cursor:pointer;display:flex;align-items:center;justify-content:center;' + t9CellBg + '" onclick="csEditBodyItem(' + t9 + ')">';
              if (t9Item.image) {
                ti9Html += '<img src="' + t9Item.image + '" style="max-width:176px;max-height:120px;object-fit:contain;" />';
                ti9Html += '<div class="cs-img-hover-overlay"><span>&#128247;</span>Click to change</div>';
              } else {
                ti9Html += '<div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;' + t9PlaceholderColor + 'font-size:10px;gap:3px;"><span style="font-size:18px;">&#128247;</span>Click</div>';
              }
              ti9Html += '</div>';
              ti9Html += '<div style="width:176px;height:56px;background:#000;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;cursor:pointer;" onclick="csOpenTextEdit(' + t9 + ')">';
              ti9Html += priceBar9;
              ti9Html += '</div>';
              ti9Html += '</div>';
            }
            ti9Html += '</div>';
            prevBody.innerHTML = ti9Html;
          }
        } else {
          // Other multi-item counts — generic grid
          prevBody.style.padding = '8px';
          prevBody.style.gap = '8px';
          prevBody.style.flexWrap = 'wrap';
          prevBody.style.alignItems = 'center';
          prevBody.style.justifyContent = 'center';
          prevBody.innerHTML = csState.bodyItems.map(function(item, i) {
            return '<div class="cs-prev-body-clickable" style="width:30%;text-align:center;cursor:pointer;" onclick="csEditBodyItem(' + i + ')">' +
              (item.image ? '<img src="' + item.image + '" style="width:100%;height:70%;object-fit:contain;background:#fff;border-radius:4px;" />' : placeholderImgSmall) +
              '<div style="color:#fff;font-size:11px;text-align:center;margin-top:4px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (item.name || '') + '</div>' +
            '</div>';
          }).join('');
        }
      } else {
        prevBody.style.display = 'none';
        prevBody.innerHTML = '';
      }

      csValidateGraphicStep();
    }


    // ─── Editable Text Handlers ───
    // Rules: auto-shrink font to fit one line
    function csAutoShrinkRules() {
      const el = document.getElementById('csPrevRulesText');
      if (!el) return;
      let size = 24;
      el.style.fontSize = size + 'px';
      while (el.scrollWidth > el.clientWidth && size > 16) {
        size -= 1;
        el.style.fontSize = size + 'px';
      }
    }
    document.getElementById('csPrevRulesText').addEventListener('input', csAutoShrinkRules);
    document.getElementById('csPrevTitleText').addEventListener('input', function() {
      csState.titleText = this.value;
    });
    document.getElementById('csPrevRulesText').addEventListener('input', function() {
      csState.rulesText = this.value;
    });

    // ─── Plain-text paste for all contenteditable elements ───
    document.addEventListener('paste', function(e) {
      var target = e.target;
      if (!target.isContentEditable) return;
      e.preventDefault();
      var text = (e.clipboardData || window.clipboardData).getData('text/plain');
      document.execCommand('insertText', false, text);
    });

    // ─── Canvas Rendering ───
    function csLoadImage(src) {
      if (csImageCache[src]) return Promise.resolve(csImageCache[src]);
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => { csImageCache[src] = img; resolve(img); };
        img.onerror = reject;
        img.src = src;
      });
    }

    // Remove near-white background from product images → returns a data URL with transparency
    const csNoBgCache = {};
    function csRemoveBg(imgSrc) {
      if (csNoBgCache[imgSrc]) return Promise.resolve(csNoBgCache[imgSrc]);
      return csLoadImage(imgSrc).then(function(img) {
        const c = document.createElement('canvas');
        c.width = img.naturalWidth || img.width;
        c.height = img.naturalHeight || img.height;
        const cx = c.getContext('2d');
        cx.drawImage(img, 0, 0);
        const d = cx.getImageData(0, 0, c.width, c.height);
        const px = d.data;
        for (let i = 0; i < px.length; i += 4) {
          // If pixel is near-white/light-gray, make transparent
          if (px[i] > 200 && px[i+1] > 200 && px[i+2] > 200) {
            px[i+3] = 0;
          }
        }
        cx.putImageData(d, 0, 0);
        const url = c.toDataURL('image/png');
        csNoBgCache[imgSrc] = url;
        return url;
      });
    }

    // Call worker endpoint to remove background via Replicate AI.
    // Returns a proxy URL for the transparent PNG. Caches per original URL.
    const csReplicateBgCache = {};
    async function csReplicateBgRemove(proxyUrl) {
      if (csReplicateBgCache[proxyUrl]) return csReplicateBgCache[proxyUrl];
      // Extract the original NAPA URL from the proxy URL query param
      const napaUrl = new URL(proxyUrl).searchParams.get('url');
      if (!napaUrl) return null;
      try {
        const resp = await fetch(WORKER_BASE + '/admin/remove-bg', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ imageUrl: napaUrl }),
        });
        if (!resp.ok) return null;
        const data = await resp.json();
        if (!data.url) return null;
        // Proxy the Replicate output through our CORS proxy for canvas access
        const cleanUrl = WORKER_BASE + '/admin/proxy-image?url=' + encodeURIComponent(data.url);
        // Pre-load to ensure it's ready for canvas drawing
        await csLoadImage(cleanUrl);
        csReplicateBgCache[proxyUrl] = cleanUrl;
        return cleanUrl;
      } catch (e) {
        console.warn('Replicate bg removal failed', e);
        return null;
      }
    }

    function csWrapText(ctx, text, font, maxWidth) {
      ctx.font = font;
      const words = text.split(' ');
      const lines = [];
      let line = '';
      for (const word of words) {
        const test = line ? line + ' ' + word : word;
        if (ctx.measureText(test).width > maxWidth && line) {
          lines.push(line);
          line = word;
        } else {
          line = test;
        }
      }
      if (line) lines.push(line);
      return lines;
    }

    window.csGenerate = async function() {
      const btn = document.querySelector('.cs-actions-row .btn-primary');

      // ── Validation ──
      var errors = [];
      // Title bar
      if (csState.showTitle) {
        var title = (document.getElementById('csPrevTitleText').value || csState.titleText || '').trim();
        if (!title || title === 'CLICK HERE TO ADD EVENT NAME!!') errors.push('Add an event name in the title bar');
        var rules = (document.getElementById('csPrevRulesText').value || csState.rulesText || '').trim();
        if (rules === 'Add fine print like: in-store only, sale dates, while supplies last, etc.') errors.push('Update or clear the fine print text');
      }
      // Offer bar
      if (csState.offerMode === 'text') {
        var offerTxt = csState.offerText || '';
        if (!offerTxt || offerTxt === 'Click here to edit offer.') errors.push('Add your offer text');
      }
      if (csState.offerMode === 'price') {
        if (!csState.offerDollars) errors.push('Enter a price amount');
      }
      if (csState.offerMode && csState.offerMode !== 'none' && csState.offerHasBadge && !csState.offerSave) {
        errors.push('Enter the save percentage on the bolt');
      }
      // Products
      if (csState.bodyCount > 0 && csState.bodyItems.length > 0) {
        var missingImg = csState.bodyItems.filter(function(it) { return !it.image; });
        if (missingImg.length > 0) errors.push('Add images to all ' + csState.bodyCount + ' product slots');
      }
      if (errors.length > 0) {
        showToast(errors[0], 'error', btn);
        return;
      }

      btn.textContent = 'Generating...';
      btn.disabled = true;

      // Capture any inline-edited text (name, price) from the preview before rendering
      csUpdatePreview(false);

      // ── Video bg: Creatomate composite ──
      if (csState.bgType === 'video') {
        try {
          if (!csState.videoUrl) throw new Error('No video selected or generated');
          const g = CS_BRAND_GRAPHICS.find(gr => gr.id === csState.graphicId);
          if (!g) throw new Error('No graphic selected');

          // Read title/rules from DOM
          var titleVal = document.getElementById('csPrevTitleText').value || csState.titleText;
          var rulesVal = document.getElementById('csPrevRulesText').value || csState.rulesText;

          // Build offer bar text
          var offerText = null;
          if (csState.offerMode === 'text' && csState.offerText) {
            offerText = csState.offerText;
          } else if (csState.offerMode === 'price') {
            var parts = [];
            if (csState.offerBadgeType === 'saveupto') parts.push('Starting At');
            parts.push('$' + csState.offerDollars + (csState.offerCents ? '.' + csState.offerCents : ''));
            if (csState.offerUnit) parts.push(csState.offerUnit);
            if (csState.offerHasBadge && csState.offerSave) parts.push('SAVE ' + csState.offerSave + '%');
            if (!csState.offerHasBadge && csState.offerShortText) parts.push(csState.offerShortText);
            offerText = parts.join(' ');
          }

          // Call worker composite endpoint (uses Creatomate template)
          var compositeResp = await fetch(WORKER_BASE + '/admin/video/composite', {
            method: 'POST',
            headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
            body: JSON.stringify({
              video_url: csState.videoUrl,
              badge_color: g.color,
              title_text: titleVal,
              rules_text: rulesVal,
              offer_text: offerText || null,
            }),
          });
          var compositeData = await compositeResp.json();
          if (compositeData.error) throw new Error(compositeData.error);

          // Poll for completion
          var renderId = compositeData.render_id;
          var finalUrl = null;
          for (var pollCount = 0; pollCount < 60; pollCount++) {
            await new Promise(function(r) { setTimeout(r, 3000); });
            var statusResp = await fetch(WORKER_BASE + '/admin/video/composite-status?render_id=' + encodeURIComponent(renderId), {
              headers: authHeaders(),
            });
            var statusData = await statusResp.json();
            if (statusData.status === 'succeeded' && statusData.url) {
              finalUrl = statusData.url;
              break;
            } else if (statusData.status === 'failed') {
              throw new Error(statusData.error || 'Composite rendering failed');
            }
            // Update button text with progress
            btn.textContent = 'Rendering video... ' + (pollCount * 3) + 's';
          }
          if (!finalUrl) throw new Error('Composite timed out');

          // Upload to Cloudinary so MMS compression transforms work at send time
          btn.textContent = 'Uploading to Cloudinary...';
          try {
            var uploadResp = await fetch('https://api.cloudinary.com/v1_1/dtpqxuwby/video/upload', {
              method: 'POST',
              body: (function() { var fd = new FormData(); fd.append('file', finalUrl); fd.append('upload_preset', 'gkk_napa_mms'); fd.append('resource_type', 'video'); return fd; })(),
            });
            var uploadData = await uploadResp.json();
            if (uploadData.secure_url) {
              finalUrl = uploadData.secure_url;
            } else {
              console.warn('Cloudinary video upload returned no secure_url:', uploadData);
            }
          } catch (uploadErr) {
            console.warn('Cloudinary video upload failed, using Creatomate URL directly:', uploadErr);
          }

          // Show result
          var rendered = document.getElementById('csRendered');
          rendered.style.display = 'block';
          rendered.querySelector('#csRenderInfo').textContent = '';
          var renderedImg = document.getElementById('csRenderedImg');
          renderedImg.style.display = 'none';

          // Show video instead of image
          var existingVid = rendered.querySelector('video.cs-rendered-video');
          if (existingVid) existingVid.remove();
          var vidEl = document.createElement('video');
          vidEl.className = 'cs-rendered-video';
          vidEl.src = finalUrl;
          vidEl.controls = true;
          vidEl.playsInline = true;
          vidEl.style.cssText = 'width:100%;max-width:360px;border-radius:8px;margin-bottom:8px;';
          renderedImg.parentNode.insertBefore(vidEl, renderedImg);

          // Show action buttons
          var actionsDiv = rendered.querySelector('.cs-rendered-actions') || document.createElement('div');
          actionsDiv.className = 'cs-rendered-actions';
          var btnsHtml = '<button class="btn-primary" onclick="csSaveVideoToLibrary(\'' + finalUrl + '\',this);this.disabled=true;this.textContent=\'Saved!\';">Save</button> ';
          if (composerActiveMessageIndex !== null) {
            btnsHtml += '<button class="btn-primary" onclick="csSaveVideoToLibrary(\'' + finalUrl + '\',this);csAttachToComposer(\'' + finalUrl + '\');this.disabled=true;this.textContent=\'Done!\';">Use in Campaign</button> ';
          }
          btnsHtml += '<button class="btn-secondary" onclick="this.parentNode.previousElementSibling.remove();this.parentNode.parentNode.style.display=\'none\';">Discard</button>';
          actionsDiv.innerHTML = btnsHtml;
          if (!rendered.querySelector('.cs-rendered-actions')) rendered.appendChild(actionsDiv);

          rendered.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        } catch (err) {
          showToast('Video generation failed: ' + err.message, 'error', btn);
        }
        btn.textContent = 'Generate';
        btn.disabled = false;
        return;
      }

      // ── Image mode: Canvas rendering (existing code) ──
      try {
        const g = CS_BRAND_GRAPHICS.find(gr => gr.id === csState.graphicId);
        if (!g) throw new Error('No graphic selected');

        const canvas = document.createElement('canvas');
        const SCALE = 2;
        canvas.width = 640 * SCALE;
        canvas.height = 800 * SCALE;
        const ctx = canvas.getContext('2d');
        ctx.scale(SCALE, SCALE);

        // 1. Background
        if (csState.bgType === 'photo' && csState.bgRawImage) {
          const bgImg = await csLoadImage(csState.bgRawImage);
          var sw = bgImg.width * csState.bgScale;
          var sh = bgImg.height * csState.bgScale;
          ctx.drawImage(bgImg, csState.bgX, csState.bgY, sw, sh);
        } else if (csState.bgType === 'bolt') {
          // Use the actual pattern SVG
          const patternFile = csState.color === 'blue' ? 'yellow-pattern-bg-full' : 'gold-pattern-bg-full';
          try {
            const patImg = await csLoadImage('/assets/mms/' + patternFile + '.svg');
            ctx.drawImage(patImg, 0, 0, 640, 800);
          } catch (e) {
            ctx.fillStyle = csState.bgValue;
            ctx.fillRect(0, 0, 640, 800);
          }
        } else {
          ctx.fillStyle = csState.bgValue || '#ddd';
          ctx.fillRect(0, 0, 640, 800);
        }

        // 2. Brand graphic SVG (drawn early so offer/body render on top)
        try {
          const gFile = g.file || g.id;
          const gImg = await csLoadImage('/assets/mms/brand-graphics/' + gFile + '.svg');
          ctx.drawImage(gImg, g.x, g.y, g.w, g.h);
        } catch (e) { console.warn('Graphic load failed', e); }

        // 3. Offer bar
        if (csState.offerType && csState.offerType !== 'none') {
          const cfg = CS_OFFER_TYPES[csState.offerType];
          const offerY = g.position === 'top' ? 131 : (800 - 131 - 151);
          ctx.fillStyle = 'rgba(0,0,0,0.45)';
          ctx.fillRect(0, offerY, 640, 151);

          await document.fonts.ready;

          // Helper: draw badge on canvas
          async function drawCanvasBadge() {
            if (!cfg.badge) return;
            try {
              const badgeImg = await csLoadImage('/assets/mms/offer-badges/' + cfg.badge + '.svg');
              const bw = 171, bh = 151;
              const bx = 640 - bw - 25;
              ctx.drawImage(badgeImg, bx, offerY, bw, bh);
              const badgeTextColor = cfg.badge.startsWith('yellow') ? '#1D3489' : '#ffffff';
              const isUpTo = cfg.hasStartingAt;
              const numYRatio = isUpTo ? 0.88 : 0.82;
              const numPx = isUpTo ? 65 : 78;
              const pctSize = isUpTo ? 32 : 34;
              const pctTopPx = isUpTo ? 9 : 12;
              ctx.save();
              ctx.fillStyle = badgeTextColor;
              const saveNum = csState.offerSave || '0';
              const badgeCx = bx + bw / 2;
              const badgeCy = offerY + bh * numYRatio;
              ctx.font = '900 ' + numPx + 'px "NAPA Sans Cn", system-ui';
              const numW = ctx.measureText(saveNum).width;
              ctx.textAlign = 'center';
              ctx.fillText(saveNum, badgeCx, badgeCy);
              ctx.font = '900 ' + pctSize + 'px "NAPA Sans Cn", system-ui';
              ctx.textAlign = 'left';
              const pctY = badgeCy - numPx + pctTopPx + pctSize;
              ctx.fillText('%', badgeCx + numW / 2, pctY);
              ctx.restore();
            } catch (e) { console.warn('Badge load failed', e); }
          }

          // Helper: draw price on canvas
          function drawCanvasPrice() {
            const dollars = csState.offerDollars || '0';
            const cents = csState.offerCents || '99';
            const unit = csState.offerUnit || '';
            const big = !cfg.hasStartingAt;
            const szDollarSign = big ? 59 : 49;
            const szDollars = big ? 101 : 84;
            const szCents = big ? 60 : 50;
            const szUnit = big ? 28 : 23;
            ctx.save();
            ctx.translate(25, 0);
            let priceTop = offerY + (big ? 20 : 49);
            if (cfg.hasStartingAt) {
              ctx.fillStyle = '#fff';
              ctx.font = '900 30px "NAPA Sans Cn", system-ui';
              ctx.fillText('STARTING AT', 0, priceTop);
              priceTop += 6;
            }
            ctx.fillStyle = '#fff';
            ctx.font = '900 ' + szDollarSign + 'px "NAPA Sans Cn", system-ui';
            const dollarSignW = ctx.measureText('$').width;
            ctx.fillText('$', 0, priceTop + szDollarSign * 0.85);
            ctx.font = '900 ' + szDollars + 'px "NAPA Sans Cn", system-ui';
            ctx.fillText(dollars, dollarSignW, priceTop + szDollars * 0.85);
            const dollarsW = dollarSignW + ctx.measureText(dollars).width;
            ctx.font = '900 ' + szCents + 'px "NAPA Sans Cn", system-ui';
            ctx.fillText(cents, dollarsW, priceTop + szCents * 0.85);
            ctx.font = '300 ' + szUnit + 'px "NAPA Sans Cn", system-ui';
            ctx.fillText(unit, dollarsW, priceTop + szCents * 0.85 + szUnit);
            ctx.restore();
          }

          if (csState.offerMode === 'price') {
            // Price on left
            drawCanvasPrice();
            if (csState.offerHasBadge) {
              // Badge on right
              await drawCanvasBadge();
            } else if (csState.offerShortText) {
              // Short text on right
              const shortFont = '900 40px "NAPA Sans Cn", system-ui';
              const shortLines = csWrapText(ctx, csState.offerShortText, shortFont, 280);
              ctx.fillStyle = '#fff';
              ctx.font = shortFont;
              ctx.textAlign = 'center';
              const shortLineH = 46;
              const shortTop = offerY + (151 - shortLines.length * shortLineH) / 2 + 34;
              for (let li = 0; li < shortLines.length; li++) {
                ctx.fillText(shortLines[li], 490, shortTop + li * shortLineH);
              }
              ctx.textAlign = 'start';
            }
          } else if (csState.offerMode === 'text') {
            const isGray = csState.bgValue === '#D1D3D4';
            const offerColor = isGray ? '#F9C842' : '#fff';
            const txt = csState.offerText || 'Click here to edit offer.';
            if (csState.offerHasBadge) {
              // Text on left, badge on right
              const textFont = '900 48px "NAPA Sans Cn", system-ui';
              const textLines = csWrapText(ctx, txt, textFont, 400);
              ctx.fillStyle = offerColor;
              ctx.font = textFont;
              const lineH = 55;
              const textTop = offerY + (151 - textLines.length * lineH) / 2 + 40;
              ctx.save();
              ctx.translate(25, 0);
              for (let li = 0; li < textLines.length; li++) {
                ctx.fillText(textLines[li], 0, textTop + li * lineH);
              }
              ctx.restore();
              await drawCanvasBadge();
            } else {
              // Text-only centered
              const offerFont = '900 48px "NAPA Sans Cn", system-ui';
              const offerLines = csWrapText(ctx, txt, offerFont, 580);
              ctx.fillStyle = offerColor;
              ctx.font = offerFont;
              ctx.textAlign = 'center';
              const offerLineH = 68;
              const offerTextTop = offerY + (151 - offerLines.length * offerLineH) / 2 + 50;
              for (let li = 0; li < offerLines.length; li++) {
                ctx.fillText(offerLines[li], 320, offerTextTop + li * offerLineH);
              }
              ctx.textAlign = 'start';
            }
          }
        }

        // 3. Body items — use Replicate AI bg removal for NAPA images
        // Process in batches of 3 to avoid worker timeout, with client-side fallback
        const napaItems = csState.bodyItems.filter(it => it.source === 'napa' && it.originalImage && !it._canvasImage);
        if (napaItems.length > 0) {
          btn.textContent = 'Removing backgrounds...';
          const BATCH_SIZE = 3;
          for (let bi = 0; bi < napaItems.length; bi += BATCH_SIZE) {
            const batch = napaItems.slice(bi, bi + BATCH_SIZE);
            await Promise.all(batch.map(async (item) => {
              try {
                const cleanUrl = await csReplicateBgRemove(item.originalImage);
                if (cleanUrl) {
                  item._canvasImage = cleanUrl;
                  return;
                }
              } catch (e) { console.warn('Replicate bg removal failed for', item.originalImage, e); }
              // Fallback: client-side pixel-level bg removal
              try {
                item._canvasImage = await csRemoveBg(item.image);
              } catch (e2) { console.warn('Client-side bg removal also failed', e2); }
            }));
          }
          btn.textContent = 'Generating...';
        }
        if (csState.bodyCount > 0) {
          const noOfferC = !csState.offerType || csState.offerType === 'none';
          const bodyY = noOfferC ? (g.position === 'top' ? 131 : 95) : (g.position === 'top' ? 318 : 131);
          const bodyH = noOfferC ? 574 : 352;

          if (csState.bodyCount === 1) {
            const item = csState.bodyItems[0];
            const layout = item.layout || 'text-image';
            const isNapa = item.source === 'napa';

            if (layout === 'text-image') {
              // NAPA: 25px pad, 295+295. Upload: 323 text + 317 image edge-to-edge.
              const sidePad = isNapa ? 25 : 0;
              const imgW = isNapa ? 295 : 317;
              const textW = isNapa ? 295 : 323;
              const imgX = sidePad + textW;

              // Full-width black 30% bg
              ctx.fillStyle = 'rgba(0,0,0,0.3)';
              ctx.fillRect(0, bodyY, 640, bodyH);

              if (item.image) {
                try {
                  const bodyImg = await csLoadImage(item._canvasImage || item.image);
                  if (isNapa) {
                    const scale = Math.min(imgW / bodyImg.width, bodyH / bodyImg.height);
                    const dw = bodyImg.width * scale;
                    const dh = bodyImg.height * scale;
                    const dx = imgX + (imgW - dw) / 2;
                    const dy = bodyY + (bodyH - dh) / 2;
                    ctx.drawImage(bodyImg, dx, dy, dw, dh);
                  } else {
                    ctx.drawImage(bodyImg, imgX, bodyY, imgW, bodyH);
                  }
                } catch (e) { console.warn('Body image load failed', e); }
              }

              // Text on left: price at top, name at bottom. Name at top if no price.
              await document.fonts.ready;
              const textX = sidePad + 10;
              const nameWeight = isNapa ? '600' : '500';
              const lineH = 48;
              const pad = 16;
              const textMaxW = textW - 20;

              const showPrice = item.price && !item.priceHidden;
              const priceLines = showPrice ? csWrapText(ctx, item.price, '700 40px "NAPA Sans Cn", system-ui', textMaxW) : [];
              let nameLines = item.name ? csWrapText(ctx, item.name, nameWeight + ' 40px "NAPA Sans Cn", system-ui', textMaxW) : [];
              const maxNameLines = Math.max(1, (showPrice ? 5 : 7) - priceLines.length);
              if (nameLines.length > maxNameLines) { nameLines = nameLines.slice(0, maxNameLines); nameLines[maxNameLines - 1] += '...'; }

              if (showPrice) {
                // Price at top
                let priceY = bodyY + pad + lineH;
                ctx.fillStyle = '#D0021B';
                ctx.font = '700 40px "NAPA Sans Cn", system-ui';
                for (const line of priceLines) {
                  ctx.fillText(line, textX, priceY);
                  const tw = ctx.measureText(line).width;
                  ctx.fillRect(textX, priceY - 14, tw, 3);
                  priceY += lineH;
                }
              }
              if (item.name) {
                // Name immediately after price (or at top if no price)
                let nameY = bodyY + pad + lineH + (priceLines.length * lineH);
                ctx.fillStyle = '#fff';
                ctx.font = nameWeight + ' 40px "NAPA Sans Cn", system-ui';
                for (const line of nameLines) {
                  ctx.fillText(line, textX, nameY);
                  nameY += lineH;
                }
              }
            } else {
              // Image only: 640 wide, 25px padding each side = 590x352 image
              ctx.fillStyle = 'rgba(0,0,0,0.3)';
              ctx.fillRect(0, bodyY, 640, bodyH);
              if (item.image) {
                try {
                  const bodyImg = await csLoadImage(item._canvasImage || item.image);
                  if (isNapa) {
                    const scale = Math.min(590 / bodyImg.width, bodyH / bodyImg.height);
                    const dw = bodyImg.width * scale;
                    const dh = bodyImg.height * scale;
                    const dx = 25 + (590 - dw) / 2;
                    const dy = bodyY + (bodyH - dh) / 2;
                    ctx.drawImage(bodyImg, dx, dy, dw, dh);
                  } else {
                    ctx.drawImage(bodyImg, 25, bodyY, 590, bodyH);
                  }
                } catch (e) { console.warn('Body image load failed', e); }
              }
            }
          } else if (csState.bodyCount === 4) {
            // ─── 4-Item Canvas Render ───
            const layout4c = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
            const items4 = csState.bodyItems;
            // Positions: 2×2, 25px side padding, flush
            const cellW4 = layout4c === 'image-only' ? 283 : 295;
            const cellH4 = layout4c === 'image-only' ? 163 : 176;
            const gap4X = 640 - 50 - cellW4 * 2; // space between the 2 cols
            const gap4Y = bodyH - cellH4 * 2; // space between the 2 rows

            if (layout4c === 'image-only') {
              // Horizontal gradient: 30% white at left → solid white at 80%
              const grad = ctx.createLinearGradient(0, 0, 640, 0);
              grad.addColorStop(0, '#ffffff');
              grad.addColorStop(0.8, 'rgba(255,255,255,0.3)');
              ctx.fillStyle = grad;
              ctx.fillRect(0, bodyY, 640, bodyH);

              for (let qi = 0; qi < 4; qi++) {
                const col4 = qi % 2;
                const row4 = Math.floor(qi / 2);
                const cx4 = 25 + col4 * (cellW4 + gap4X);
                const cy4 = bodyY + row4 * (cellH4 + gap4Y);
                if (items4[qi] && items4[qi].image) {
                  try {
                    const img4 = await csLoadImage(items4[qi]._canvasImage || items4[qi].image);
                    const cellNapa = items4[qi].source === 'napa';
                    if (cellNapa) {
                      const s4 = Math.min(cellW4 / img4.width, cellH4 / img4.height);
                      const dw4 = img4.width * s4;
                      const dh4 = img4.height * s4;
                      const dx4 = col4 === 0 ? cx4 + (cellW4 - dw4) : cx4;
                      const dy4 = row4 === 0 ? cy4 + (cellH4 - dh4) : cy4;
                      ctx.drawImage(img4, dx4, dy4, dw4, dh4);
                    } else {
                      // Upload: cropped to exact cell size, draw contain
                      const s4 = Math.min(cellW4 / img4.width, cellH4 / img4.height);
                      const dw4 = img4.width * s4;
                      const dh4 = img4.height * s4;
                      ctx.drawImage(img4, cx4 + (cellW4 - dw4) / 2, cy4 + (cellH4 - dh4) / 2, dw4, dh4);
                    }
                  } catch (e) {}
                }
              }
            } else {
              // Text-Image: body bg = black at 30%
              ctx.fillStyle = 'rgba(0,0,0,0.3)';
              ctx.fillRect(0, bodyY, 640, bodyH);
              await document.fonts.ready;

              const imgW4 = 147;
              const panelW4 = 148;
              const priceBarH = 56;
              const descH = 120;

              for (let qi = 0; qi < 4; qi++) {
                const col4 = qi % 2;
                const row4 = Math.floor(qi / 2);
                const cx4 = 25 + col4 * (cellW4 + gap4X);
                const cy4 = bodyY + row4 * (cellH4 + gap4Y);
                const it4 = items4[qi] || {};

                // ── Left: Image panel (147×176) ──
                const cellNapa4 = it4.source === 'napa';
                if (cellNapa4) {
                  const iGrad = ctx.createLinearGradient(0, cy4, 0, cy4 + cellH4);
                  iGrad.addColorStop(0.6, '#ffffff');
                  iGrad.addColorStop(1, '#999999');
                  ctx.fillStyle = iGrad;
                  ctx.fillRect(cx4, cy4, imgW4, cellH4);
                }
                if (it4.image) {
                  try {
                    const img4 = await csLoadImage(it4._canvasImage || it4.image);
                    const s4 = Math.min(imgW4 / img4.width, cellH4 / img4.height);
                    const dw4 = img4.width * s4;
                    const dh4 = img4.height * s4;
                    ctx.drawImage(img4, cx4 + (imgW4 - dw4) / 2, cy4 + (cellH4 - dh4) / 2, dw4, dh4);
                  } catch (e) {}
                }

                // ── Right panel origin ──
                const rx4 = cx4 + imgW4;

                // ── Price bar (148×56, solid black) ──
                ctx.fillStyle = '#000000';
                ctx.fillRect(rx4, cy4, panelW4, priceBarH);

                // Always draw fullPrice
                if (it4.fullPrice) {
                  const showCut4c = !it4.cutPriceHidden && !!it4.price;
                  const showUnit4c = !it4.unitHidden && !!it4.priceUnit;
                  const hasCutRow4 = showCut4c || showUnit4c;
                  const totalPriceH = 24 + (hasCutRow4 ? 14 : 0);
                  const priceCenterY = cy4 + priceBarH / 2;
                  let priceY = priceCenterY - totalPriceH / 2;

                  ctx.fillStyle = '#ffffff';
                  ctx.font = '900 24px "NAPA Sans Cn", system-ui';
                  ctx.textAlign = 'center';
                  ctx.fillText(it4.fullPrice, rx4 + panelW4 / 2, priceY + 20);
                  priceY += 24;

                  if (hasCutRow4) {
                    ctx.font = '300 11px "NAPA Sans Cn", system-ui';
                    // Measure visible parts
                    const cutText = showCut4c ? it4.price : '';
                    const unitText = showUnit4c ? it4.priceUnit : '';
                    const cutW = cutText ? ctx.measureText(cutText).width : 0;
                    const eachW = unitText ? ctx.measureText(unitText).width : 0;
                    const gapW = (cutText && unitText) ? 3 : 0;
                    const totalW = cutW + gapW + eachW;
                    const startX = rx4 + (panelW4 - totalW) / 2;
                    let drawX = startX;

                    if (showCut4c) {
                      ctx.fillStyle = '#FFC836';
                      ctx.textAlign = 'left';
                      ctx.fillText(cutText, drawX, priceY + 10);
                      ctx.fillRect(drawX, priceY + 6, cutW, 1);
                      drawX += cutW + gapW;
                    }
                    if (showUnit4c) {
                      ctx.fillStyle = '#ffffff';
                      ctx.textAlign = 'left';
                      ctx.fillText(unitText, drawX, priceY + 10);
                    }
                  }
                  ctx.textAlign = 'left';
                }

                // ── Description area (148×120, solid white) ──
                const descY = cy4 + priceBarH;
                ctx.fillStyle = '#ffffff';
                ctx.fillRect(rx4, descY, panelW4, descH);

                if (it4.name) {
                  ctx.fillStyle = '#222222';
                  const nameFont = '300 16px "NAPA Sans Cn", system-ui';
                  ctx.font = nameFont;
                  const maxNameW = panelW4 - 26;
                  const nLines4 = csWrapText(ctx, it4.name, nameFont, maxNameW);
                  const lineH = 20;
                  const maxLines = Math.min(nLines4.length, 5);
                  const totalTextH = maxLines * lineH;
                  const nameStartY = descY + (descH - totalTextH) / 2 + 14;
                  for (let nl = 0; nl < maxLines; nl++) {
                    ctx.fillText(nLines4[nl], rx4 + 13, nameStartY + nl * lineH);
                  }
                }
              }
            }
          } else if (csState.bodyCount === 6) {
            // ─── 6-Item Canvas Render ───
            const layout6c = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
            const items6 = csState.bodyItems;

            if (layout6c === 'image-only') {
              // Photo Only: 3×2 grid, 180×163 cells, 25px side padding
              const cellW6 = 180;
              const cellH6 = 163;
              const gap6X = (590 - cellW6 * 3) / 2; // 25
              const gap6Y = bodyH - cellH6 * 2; // 26

              const grad6 = ctx.createLinearGradient(0, 0, 640, 0);
              grad6.addColorStop(0, '#ffffff');
              grad6.addColorStop(0.8, 'rgba(255,255,255,0.3)');
              ctx.fillStyle = grad6;
              ctx.fillRect(0, bodyY, 640, bodyH);

              for (let q6 = 0; q6 < 6; q6++) {
                const col6 = q6 % 3;
                const row6 = Math.floor(q6 / 3);
                const cx6 = 25 + col6 * (cellW6 + gap6X);
                const cy6 = bodyY + row6 * (cellH6 + gap6Y);
                if (items6[q6] && items6[q6].image) {
                  try {
                    const img6 = await csLoadImage(items6[q6]._canvasImage || items6[q6].image);
                    const s6 = Math.min(cellW6 / img6.width, cellH6 / img6.height);
                    const dw6 = img6.width * s6;
                    const dh6 = img6.height * s6;
                    ctx.drawImage(img6, cx6 + (cellW6 - dw6) / 2, cy6 + (cellH6 - dh6) / 2, dw6, dh6);
                  } catch (e) {}
                }
              }
            } else {
              // Text-Image: 3×2 grid, 176×176 cells, image 176×120 + price bar 176×56
              ctx.fillStyle = 'rgba(0,0,0,0.3)';
              ctx.fillRect(0, bodyY, 640, bodyH);
              await document.fonts.ready;

              const cellW6t = 176;
              const cellH6t = 176;
              const imgH6 = 120;
              const priceH6 = 56;
              const colGap6 = 48;

              for (let q6 = 0; q6 < 6; q6++) {
                const col6 = q6 % 3;
                const row6 = Math.floor(q6 / 3);
                const cx6 = 8 + col6 * (cellW6t + colGap6);
                const cy6 = bodyY + row6 * cellH6t;
                const it6 = items6[q6] || {};

                // ── Image area (176×120) ──
                const cellNapa6 = it6.source === 'napa';
                if (cellNapa6) {
                  const iGrad6 = ctx.createLinearGradient(0, cy6, 0, cy6 + imgH6);
                  iGrad6.addColorStop(0.6, '#ffffff');
                  iGrad6.addColorStop(1, '#999999');
                  ctx.fillStyle = iGrad6;
                  ctx.fillRect(cx6, cy6, cellW6t, imgH6);
                }
                if (it6.image) {
                  try {
                    const img6 = await csLoadImage(it6._canvasImage || it6.image);
                    const s6 = Math.min(cellW6t / img6.width, imgH6 / img6.height);
                    const dw6 = img6.width * s6;
                    const dh6 = img6.height * s6;
                    ctx.drawImage(img6, cx6 + (cellW6t - dw6) / 2, cy6 + (imgH6 - dh6) / 2, dw6, dh6);
                  } catch (e) {}
                }

                // ── Price bar (176×56, solid black) ──
                const py6 = cy6 + imgH6;
                ctx.fillStyle = '#000000';
                ctx.fillRect(cx6, py6, cellW6t, priceH6);

                // Always draw fullPrice
                if (it6.fullPrice) {
                  const showCut6c = !it6.cutPriceHidden && !!it6.price;
                  const showUnit6c = !it6.unitHidden && !!it6.priceUnit;
                  const hasCutRow6 = showCut6c || showUnit6c;
                  const totalPriceH6 = 20 + (hasCutRow6 ? 12 : 0);
                  const priceCenterY6 = py6 + priceH6 / 2;
                  let priceY6 = priceCenterY6 - totalPriceH6 / 2;

                  ctx.fillStyle = '#ffffff';
                  ctx.font = '900 20px "NAPA Sans Cn", system-ui';
                  ctx.textAlign = 'center';
                  ctx.fillText(it6.fullPrice, cx6 + cellW6t / 2, priceY6 + 16);
                  priceY6 += 20;

                  if (hasCutRow6) {
                    ctx.font = '300 10px "NAPA Sans Cn", system-ui';
                    const cutText6 = showCut6c ? it6.price : '';
                    const unitText6 = showUnit6c ? it6.priceUnit : '';
                    const cutW6 = cutText6 ? ctx.measureText(cutText6).width : 0;
                    const eachW6 = unitText6 ? ctx.measureText(unitText6).width : 0;
                    const gapW6 = (cutText6 && unitText6) ? 3 : 0;
                    const totalW6 = cutW6 + gapW6 + eachW6;
                    const startX6 = cx6 + (cellW6t - totalW6) / 2;
                    let drawX6 = startX6;

                    if (showCut6c) {
                      ctx.fillStyle = '#FFC836';
                      ctx.textAlign = 'left';
                      ctx.fillText(cutText6, drawX6, priceY6 + 9);
                      ctx.fillRect(drawX6, priceY6 + 5, cutW6, 1);
                      drawX6 += cutW6 + gapW6;
                    }
                    if (showUnit6c) {
                      ctx.fillStyle = '#ffffff';
                      ctx.textAlign = 'left';
                      ctx.fillText(unitText6, drawX6, priceY6 + 9);
                    }
                  }
                  ctx.textAlign = 'left';
                }
              }
            }
          } else if (csState.bodyCount === 9) {
            // ─── 9-Item Canvas Render ───
            const layout9c = csState.bodyItems[0] ? (csState.bodyItems[0].layout || 'text-image') : 'text-image';
            const items9 = csState.bodyItems;

            if (layout9c === 'image-only') {
              // Photo Only: 3×3 grid, 180×180 cells, 25px side padding
              const cellW9 = 180;
              const cellH9 = 180;
              const gap9X = (590 - cellW9 * 3) / 2; // 25
              const gap9Y = (bodyH - cellH9 * 3) / 2; // ~17

              const grad9 = ctx.createLinearGradient(0, 0, 640, 0);
              grad9.addColorStop(0, '#ffffff');
              grad9.addColorStop(0.8, 'rgba(255,255,255,0.3)');
              ctx.fillStyle = grad9;
              ctx.fillRect(0, bodyY, 640, bodyH);

              for (let q9 = 0; q9 < 9; q9++) {
                const col9 = q9 % 3;
                const row9 = Math.floor(q9 / 3);
                const cx9 = 25 + col9 * (cellW9 + gap9X);
                const cy9 = bodyY + gap9Y + row9 * (cellH9 + gap9Y);
                if (items9[q9] && items9[q9].image) {
                  try {
                    const img9 = await csLoadImage(items9[q9]._canvasImage || items9[q9].image);
                    const s9 = Math.min(cellW9 / img9.width, cellH9 / img9.height);
                    const dw9 = img9.width * s9;
                    const dh9 = img9.height * s9;
                    ctx.drawImage(img9, cx9 + (cellW9 - dw9) / 2, cy9 + (cellH9 - dh9) / 2, dw9, dh9);
                  } catch (e) {}
                }
              }
            } else {
              // Text-Image: 3×3 grid, 176×176 cells, image 176×120 + price bar 176×56
              ctx.fillStyle = 'rgba(0,0,0,0.3)';
              ctx.fillRect(0, bodyY, 640, bodyH);
              await document.fonts.ready;

              const cellW9t = 176;
              const cellH9t = 176;
              const imgH9 = 120;
              const priceH9 = 56;
              const colGap9 = 48;
              const topPad9 = Math.floor((bodyH - cellH9t * 3) / 2);

              for (let q9 = 0; q9 < 9; q9++) {
                const col9 = q9 % 3;
                const row9 = Math.floor(q9 / 3);
                const cx9 = 8 + col9 * (cellW9t + colGap9);
                const cy9 = bodyY + topPad9 + row9 * cellH9t;
                const it9 = items9[q9] || {};

                // Image area (176×120)
                const cellNapa9 = it9.source === 'napa';
                if (cellNapa9) {
                  const iGrad9 = ctx.createLinearGradient(0, cy9, 0, cy9 + imgH9);
                  iGrad9.addColorStop(0.6, '#ffffff');
                  iGrad9.addColorStop(1, '#999999');
                  ctx.fillStyle = iGrad9;
                  ctx.fillRect(cx9, cy9, cellW9t, imgH9);
                }
                if (it9.image) {
                  try {
                    const img9 = await csLoadImage(it9._canvasImage || it9.image);
                    const s9 = Math.min(cellW9t / img9.width, imgH9 / img9.height);
                    const dw9 = img9.width * s9;
                    const dh9 = img9.height * s9;
                    ctx.drawImage(img9, cx9 + (cellW9t - dw9) / 2, cy9 + (imgH9 - dh9) / 2, dw9, dh9);
                  } catch (e) {}
                }

                // Price bar (176×56, solid black)
                const py9 = cy9 + imgH9;
                ctx.fillStyle = '#000000';
                ctx.fillRect(cx9, py9, cellW9t, priceH9);

                if (it9.fullPrice) {
                  const showCut9c = !it9.cutPriceHidden && !!it9.price;
                  const showUnit9c = !it9.unitHidden && !!it9.priceUnit;
                  const hasCutRow9 = showCut9c || showUnit9c;
                  const totalPriceH9 = 20 + (hasCutRow9 ? 12 : 0);
                  const priceCenterY9 = py9 + priceH9 / 2;
                  let priceY9 = priceCenterY9 - totalPriceH9 / 2;

                  ctx.fillStyle = '#ffffff';
                  ctx.font = '900 20px "NAPA Sans Cn", system-ui';
                  ctx.textAlign = 'center';
                  ctx.fillText(it9.fullPrice, cx9 + cellW9t / 2, priceY9 + 16);
                  priceY9 += 20;

                  if (hasCutRow9) {
                    ctx.font = '300 10px "NAPA Sans Cn", system-ui';
                    const cutText9 = showCut9c ? it9.price : '';
                    const unitText9 = showUnit9c ? it9.priceUnit : '';
                    const cutW9 = cutText9 ? ctx.measureText(cutText9).width : 0;
                    const eachW9 = unitText9 ? ctx.measureText(unitText9).width : 0;
                    const gapW9 = (cutText9 && unitText9) ? 3 : 0;
                    const totalW9 = cutW9 + gapW9 + eachW9;
                    const startX9 = cx9 + (cellW9t - totalW9) / 2;
                    let drawX9 = startX9;

                    if (showCut9c) {
                      ctx.fillStyle = '#FFC836';
                      ctx.textAlign = 'left';
                      ctx.fillText(cutText9, drawX9, priceY9 + 9);
                      ctx.fillRect(drawX9, priceY9 + 5, cutW9, 1);
                      drawX9 += cutW9 + gapW9;
                    }
                    if (showUnit9c) {
                      ctx.fillStyle = '#ffffff';
                      ctx.textAlign = 'left';
                      ctx.fillText(unitText9, drawX9, priceY9 + 9);
                    }
                  }
                  ctx.textAlign = 'left';
                }
              }
            }
          } else if (csState.bodyCount > 1) {
            // Other multi-item: generic grid
            const items = csState.bodyItems;
            const cols = 3;
            const cellW = (640 - 20) / cols;
            const cellH = bodyH / Math.ceil(items.length / cols);
            for (let i = 0; i < items.length; i++) {
              const col = i % cols;
              const row = Math.floor(i / cols);
              const cx = 10 + col * cellW;
              const cy = bodyY + row * cellH;
              if (items[i].image) {
                try {
                  const img = await csLoadImage(items[i]._canvasImage || items[i].image);
                  const imgH = cellH * 0.7;
                  ctx.drawImage(img, cx + 4, cy + 4, cellW - 8, imgH);
                } catch (e) {}
              }
              if (items[i].name) {
                ctx.fillStyle = '#fff';
                ctx.font = '700 11px system-ui';
                ctx.textAlign = 'center';
                ctx.fillText(items[i].name, cx + cellW / 2, bodyY + (row + 1) * cellH - 4, cellW - 8);
                ctx.textAlign = 'start';
              }
            }
          }
        }

        // 5. Title/Rules bar (on top of everything)
        if (csState.showTitle) {
          const titleH = 18 + 38 + 24 + 15; // trim-adjusted: top + title + rules + bottom = 95
          const titleY = g.position === 'top' ? (800 - titleH) : 0;
          ctx.fillStyle = '#000';
          ctx.fillRect(0, titleY, 640, titleH);

          ctx.fillStyle = '#F9C842';
          ctx.font = '700 38px "NAPA Sans Cn", system-ui';
          ctx.fillText((csState.titleText || 'CLICK HERE TO ADD EVENT NAME!!').toUpperCase(), 25, titleY + 18 + 34);
          ctx.fillStyle = '#fff';
          ctx.font = '500 24px "NAPA Sans Cn", system-ui';
          ctx.fillText(csState.rulesText || 'Add fine print like: in-store only, sale dates, while supplies last, etc.', 25, titleY + 18 + 38 + 22);
        }

        // 5. Export
        // MMS carrier limits: T-Mobile 1MB, Verizon 1.2MB, AT&T 600KB (short code only)
        const MMS_MAX = 1000 * 1024;
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.92));
        let finalBlob = blob;
        if (blob.size > MMS_MAX) {
          finalBlob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.80));
        }
        if (finalBlob.size > MMS_MAX) {
          finalBlob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.65));
        }

        // Show rendered image
        const url = URL.createObjectURL(finalBlob);
        const renderedImg = document.getElementById('csRenderedImg');
        renderedImg.src = url;
        document.getElementById('csRenderInfo').textContent =
          'Size: ' + (finalBlob.size / 1024).toFixed(0) + ' KB | 1280x1600 JPEG';
        document.getElementById('csRendered').style.display = 'block';
        renderedImg.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        // Upload to Cloudinary
        try {
          const fd = new FormData();
          fd.append('file', finalBlob, 'creative.jpg');
          fd.append('upload_preset', 'gkk_napa_mms');
          const resp = await fetch('https://api.cloudinary.com/v1_1/dtpqxuwby/image/upload', {
            method: 'POST', body: fd
          });
          const data = await resp.json();
          if (data.secure_url) {
            document.getElementById('csRenderInfo').textContent +=
              ' | Uploaded: ' + data.secure_url.split('/').pop();

            // Clear any previous action buttons
            var oldActions = document.getElementById('csPostGenActions');
            if (oldActions) oldActions.remove();

            // Action buttons: Save / Discard / Save & Use in Campaign
            var actionsDiv = document.createElement('div');
            actionsDiv.id = 'csPostGenActions';
            actionsDiv.style.cssText = 'display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;';

            function csSaveToLibrary(url) {
              return fetch(WORKER_BASE + '/admin/media-library', {
                method: 'POST',
                headers: Object.assign({}, authHeaders(), { 'Content-Type': 'application/json' }),
                body: JSON.stringify({ url: url, label: (csState.titleText || 'Creative Studio').substring(0, 80), category: 'finished_image' })
              });
            }

            var saveBtn = document.createElement('button');
            saveBtn.textContent = 'Save';
            saveBtn.className = 'btn btn-primary';
            saveBtn.onclick = function() {
              saveBtn.disabled = true; saveBtn.textContent = 'Saved!';
              csSaveToLibrary(data.secure_url);
              discardBtn.remove();
            };

            actionsDiv.appendChild(saveBtn);

            if (composerActiveMessageIndex !== null) {
              var useBtn = document.createElement('button');
              useBtn.textContent = 'Use in Campaign';
              useBtn.className = 'btn btn-primary';
              useBtn.onclick = function() {
                csSaveToLibrary(data.secure_url);
                csAttachToComposer(data.secure_url);
              };
              actionsDiv.appendChild(useBtn);
            }

            var discardBtn = document.createElement('button');
            discardBtn.textContent = 'Discard';
            discardBtn.className = 'btn-secondary';
            discardBtn.style.cssText = 'padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;';
            discardBtn.onclick = function() {
              actionsDiv.innerHTML = '<span style="color:rgba(255,255,255,.4);font-size:13px;">Discarded — not saved to library.</span>';
            };
            actionsDiv.appendChild(discardBtn);

            document.getElementById('csRenderInfo').parentNode.appendChild(actionsDiv);
          }
        } catch (e) { console.warn('Cloudinary upload failed', e); }

      } catch (e) {
        console.error('Generate failed:', e);
        alert('Error: ' + e.message);
      } finally {
        btn.textContent = 'Generate Image';
        btn.disabled = false;
      }
    };

    // ─── Reset ───
    window.csReset = function() {
      // Stop any video timers
      _csVideoStopTimers();
      csState = {
        mediaMode: 'image', color: 'blue', graphicId: null, bgType: null, bgValue: null, bgImageData: null, bgRawImage: null, bgNatW: 0, bgNatH: 0, bgScale: 1, bgX: 0, bgY: 0,
        videoSource: null, videoScript: '', videoUrl: null, videoStatus: null, videoId: null, videoError: null, _videoPollTimer: null, _videoElapsedTimer: null, _videoStartTime: null,
        offerType: null, offerMode: null, offerHasBadge: false, offerBadgeType: 'save', offerBadgeColor: 'yellow', offerShortText: '',
        offerDollars: '', offerCents: '', offerUnit: '', offerSave: '', offerText: '',
        showTitle: true, titleText: 'CLICK HERE TO ADD EVENT NAME!!', rulesText: 'Add fine print like: in-store only, sale dates, while supplies last, etc.',
        bodyCount: null, bodyItems: [],
      };
      // Reset filter radio to "All"
      var allRadio = document.querySelector('input[name="csGraphicFilter"][value="all"]');
      if (allRadio) allRadio.checked = true;
      // Restore Products step visibility
      document.getElementById('csStepBody').style.display = '';
      document.querySelectorAll('.cs-color-btn').forEach(b => b.classList.toggle('active', b.dataset.color === 'blue'));
      document.querySelectorAll('.cs-step').forEach(s => s.classList.remove('completed', 'collapsed'));
      csRebuildGraphicGrid();
      csHideStepsAfter('csStepGraphic');
      document.getElementById('csBgSection').style.display = 'none';
      document.getElementById('csPlaceholder').style.display = 'flex';
      document.getElementById('csPrevGraphic').style.display = 'none';
      document.getElementById('csPrevTitleBar').style.display = 'none';
      document.getElementById('csPrevOfferBar').style.display = 'none';
      var _prevBg = document.getElementById('csPrevBg');
      _prevBg.style.backgroundColor = '';
      _prevBg.style.backgroundImage = '';
      var _vidEl = _prevBg.querySelector('video');
      if (_vidEl) _vidEl.remove();
      document.getElementById('csRendered').style.display = 'none';
      var _prevBody = document.getElementById('csPrevBody');
      _prevBody.innerHTML = '';
      _prevBody.style.display = 'none';
      document.getElementById('csActions').style.display = 'none';
      document.getElementById('csPrevOfferBar').innerHTML = '<div id="csPrevOfferLeft"></div><div id="csPrevOfferRight"></div>';
      document.getElementById('csPrevTitleText').value = 'CLICK HERE TO ADD EVENT NAME!!';
      document.getElementById('csPrevRulesText').value = 'Add fine print like: in-store only, sale dates, while supplies last, etc.';
      document.getElementById('csTemplateRow').style.display = 'none';
      document.getElementById('csBodyHint').style.display = 'none';
      document.getElementById('csSampleDataBtn').style.display = 'none';
      document.getElementById('csStartOverRow').style.display = 'none';
    };

    // ─── Init ───
    csRebuildGraphicGrid();

    // ─── Video mute toggle ───
    var _csMuteSvgOn = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>';
    var _csMuteSvgOff = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>';
    window.csToggleVideoMute = function() {
      var vid = document.querySelector('#csPrevBg video');
      if (!vid) return;
      vid.muted = !vid.muted;
      var btn = document.getElementById('csVideoMuteBtn');
      if (btn) {
        btn.innerHTML = vid.muted ? _csMuteSvgOff : _csMuteSvgOn;
        btn.title = vid.muted ? 'Unmute' : 'Mute';
      }
    };
    function csUpdateMuteBtn() {
      var btn = document.getElementById('csVideoMuteBtn');
      if (!btn) return;
      var hasVideo = csState.bgType === 'video' && csState.videoUrl;
      btn.style.display = hasVideo ? '' : 'none';
      if (hasVideo) {
        var vid = document.querySelector('#csPrevBg video');
        var muted = !vid || vid.muted;
        btn.innerHTML = muted ? _csMuteSvgOff : _csMuteSvgOn;
        btn.title = muted ? 'Unmute' : 'Mute';
      }
    }

    // ─── Preview size toggle ───
    var CS_SIZES = { s: 360, m: 480, l: 640 };
    var _csCurrentSize = 'm';

    window.csSetPreviewSize = function(size) {
      _csCurrentSize = size;
      document.querySelectorAll('.cs-size-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.size === size);
      });
      csScaleCanvas();
    };

    // ─── Responsive canvas scaling ───
    function csScaleCanvas() {
      var wrap = document.querySelector('.cs-canvas-wrap');
      var canvas = document.getElementById('csCanvas');
      if (!wrap || !canvas) return;
      var isVideoMode = canvas.classList.contains('video-mode');
      var canvasW = isVideoMode ? 450 : 640;
      var targetW = CS_SIZES[_csCurrentSize] || 640;
      var displayW = isVideoMode ? Math.min(targetW, 450) : targetW;
      wrap.style.maxWidth = displayW + 'px';
      var controls = document.getElementById('csPreviewControls');
      if (controls) controls.style.maxWidth = displayW + 'px';
      var canvasH = isVideoMode ? 800 : 800;
      if (displayW === canvasW) {
        canvas.style.transform = '';
        canvas.style.transformOrigin = '';
        wrap.style.height = '';
      } else {
        var scale = displayW / canvasW;
        canvas.style.transform = 'scale(' + scale + ')';
        canvas.style.transformOrigin = 'top left';
        wrap.style.height = Math.round(canvasH * scale) + 'px';
      }
    }
    window.addEventListener('resize', csScaleCanvas);
    csScaleCanvas();

