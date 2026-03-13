// ═══ media-library.js — Media Library State, Grid, Overlay ═══

    // Media Library state
    var _libAllItems = [];
    var _libFilter = 'all';
    var _libSearch = '';
    var _libSort = 'newest';
    var _libIndex = null;
    var _libOverlay = null;
    var _libBgPickerMode = false;  // true when picking bg for Studio
    var _libBgPickerType = null;   // 'photo' or 'video'
    var _libAllowedCategories = null; // array of allowed categories, or null for all

    function _libRenderGrid() {
      var grid = document.getElementById('libGrid');
      if (!grid) return;
      var items = _libAllItems.slice();

      // Filter by allowed categories (set by opener context; heygen_video treated as raw_video)
      if (_libAllowedCategories) {
        items = items.filter(function(i) {
          var cat = i.category === 'heygen_video' ? 'raw_video' : i.category;
          return _libAllowedCategories.indexOf(cat) !== -1;
        });
      }
      // Additional UI filter (if filter tabs are shown)
      if (_libFilter === 'image') items = items.filter(function(i) { return !/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(i.url); });
      if (_libFilter === 'video') items = items.filter(function(i) { return /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(i.url); });

      // Search
      if (_libSearch) {
        var q = _libSearch.toLowerCase();
        items = items.filter(function(i) { return (i.label || '').toLowerCase().indexOf(q) !== -1; });
      }

      // Sort
      if (_libSort === 'newest') items.sort(function(a, b) { return b.created_at.localeCompare(a.created_at); });
      else if (_libSort === 'oldest') items.sort(function(a, b) { return a.created_at.localeCompare(b.created_at); });
      else if (_libSort === 'name') items.sort(function(a, b) { return (a.label || '').localeCompare(b.label || ''); });

      // Count
      document.getElementById('libCount').textContent = items.length + ' item' + (items.length !== 1 ? 's' : '');

      if (!items.length) {
        grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px 0;color:rgba(255,255,255,.35);">' +
          (_libAllItems.length ? 'No matches found.' : 'No media yet. Create one in the Studio!') + '</div>';
        return;
      }
      var html = '';
      items.forEach(function(item, idx) {
        var isVideo = /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(item.url);
        var dateStr = item.created_at ? new Date(item.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
        html += '<div class="lib-cell" data-idx="' + idx + '" data-url="' + item.url + '" data-id="' + item.id + '">';
        html += '<div class="lib-thumb">';
        if (isVideo) {
          html += '<video src="' + item.url + '" muted preload="metadata" style="width:100%;height:100%;object-fit:cover;"></video>';
          html += '<div class="lib-badge">VIDEO</div>';
        } else {
          html += '<img src="' + item.url + '" loading="lazy" style="width:100%;height:100%;object-fit:cover;" />';
        }
        html += '<button class="lib-delete" data-id="' + item.id + '" title="Delete">&times;</button>';
        html += '</div>';
        html += '<div class="lib-meta">';
        html += '<div class="lib-name">' + (item.label || 'Untitled') + '</div>';
        html += '<div class="lib-date">' + dateStr + '</div>';
        html += '</div>';
        html += '</div>';
      });
      grid.innerHTML = html;

      // Click handlers
      grid.querySelectorAll('.lib-cell').forEach(function(cell) {
        cell.addEventListener('click', function(e) {
          if (e.target.closest('.lib-delete')) return;
          var url = cell.dataset.url;
          if (_libBgPickerMode) {
            // Studio bg picker mode
            if (_libBgPickerType === 'video') {
              csState.videoUrl = url;
              csState.videoSource = 'library';
              csState.bgType = 'video';
              csState.videoStatus = 'done';
            } else {
              // Photo bg from library
              var img = new Image();
              img.crossOrigin = 'anonymous';
              img.onload = function() {
                var scale = Math.max(640 / img.width, 800 / img.height);
                csState.bgType = 'photo';
                csState.bgRawImage = url;
                csState.bgNatW = img.width;
                csState.bgNatH = img.height;
                csState.bgScale = scale;
                csState.bgX = (640 - img.width * scale) / 2;
                csState.bgY = (800 - img.height * scale) / 2;
                csUpdatePreview();
              };
              img.src = url;
            }
            csRebuildBgOptions();
            csUpdatePreview();
          } else if (typeof _eventEditMediaPicked === 'function' && _eventEditMediaPicked(url)) {
            // Event edit picker — handled by campaigns.js
          } else {
            // Composer library picker
            composerMessages[_libIndex].mediaUrl = url;
            composerMessages[_libIndex].mediaType = 'library';
            composerRender();
          }
          if (_libOverlay) _libOverlay.remove();
        });
      });
      grid.querySelectorAll('.lib-delete').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
          e.stopPropagation();
          if (!confirm('Delete this item from the library?')) return;
          var id = btn.dataset.id;
          btn.textContent = '...';
          fetch(WORKER_BASE + '/admin/media-library/' + id, {
            method: 'DELETE', headers: authHeaders()
          }).then(function() {
            _libAllItems = _libAllItems.filter(function(i) { return String(i.id) !== String(id); });
            _libRenderGrid();
          });
        });
      });
    }

    function _libOpenOverlay(bgPickerMode) {
      _libBgPickerMode = !!bgPickerMode;
      _libSearch = '';
      _libSort = 'newest';
      _libAllItems = [];

      // Set category restrictions and default filter based on mode
      if (_libBgPickerMode) {
        _libFilter = _libBgPickerType === 'video' ? 'video' : 'image';
        if (_libBgPickerType === 'video') {
          _libAllowedCategories = ['raw_video'];
        } else {
          _libAllowedCategories = ['raw_image'];
        }
      } else {
        _libFilter = 'all';
        // Composer / event edit context — only finished ads
        _libAllowedCategories = ['finished_image', 'finished_video'];
      }

      var title = _libBgPickerMode ? ('Select ' + (_libBgPickerType === 'video' ? 'Video' : 'Photo')) : 'Select Media';

      var overlay = document.createElement('div');
      overlay.className = 'lib-overlay';
      _libOverlay = overlay;

      var filterHtml = '';
      if (!_libBgPickerMode) {
        // Show all filter tabs in composer mode
        filterHtml = '<div class="lib-filters">' +
          '<button class="lib-filter-btn active" data-filter="all">All</button>' +
          '<button class="lib-filter-btn" data-filter="image">Images</button>' +
          '<button class="lib-filter-btn" data-filter="video">Videos</button>' +
        '</div>';
      }

      overlay.innerHTML =
        '<div class="lib-panel">' +
          '<div class="lib-header">' +
            '<h3 style="margin:0;font-size:18px;font-weight:700;">' + title + '</h3>' +
            '<button class="lib-close" onclick="this.closest(\'.lib-overlay\').remove()">&times;</button>' +
          '</div>' +
          '<div class="lib-toolbar">' +
            '<input type="search" id="libSearchInput" placeholder="Search by name..." class="lib-search" />' +
            filterHtml +
            '<select id="libSortSelect" class="lib-sort">' +
              '<option value="newest">Newest First</option>' +
              '<option value="oldest">Oldest First</option>' +
              '<option value="name">Name A–Z</option>' +
            '</select>' +
          '</div>' +
          '<div class="lib-status"><span id="libCount">0 items</span></div>' +
          '<div id="libGrid" class="lib-grid"><div style="grid-column:1/-1;text-align:center;padding:40px 0;color:rgba(255,255,255,.35);">Loading...</div></div>' +
        '</div>';

      overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
      document.body.appendChild(overlay);

      // Wire up controls
      document.getElementById('libSearchInput').addEventListener('input', function() {
        _libSearch = this.value; _libRenderGrid();
      });
      document.getElementById('libSortSelect').addEventListener('change', function() {
        _libSort = this.value; _libRenderGrid();
      });
      overlay.querySelectorAll('.lib-filter-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          overlay.querySelectorAll('.lib-filter-btn').forEach(function(b) { b.classList.remove('active'); });
          btn.classList.add('active');
          _libFilter = btn.dataset.filter;
          _libRenderGrid();
        });
      });

      // Fetch items
      fetch(WORKER_BASE + '/admin/media-library', { headers: authHeaders() }).then(function(r) { return r.json(); }).then(function(items) {
        _libAllItems = items;
        _libRenderGrid();
      }).catch(function() {
        document.getElementById('libGrid').innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px 0;color:var(--red);">Failed to load library.</div>';
      });
    }

    window.composerOpenLibrary = function(index) {
      _libIndex = index;
      _libBgPickerType = null;
      composerMessages[index].mediaType = 'library';
      composerMessages[index].mediaUrl = null;
      composerRender();
      _libOpenOverlay(false);
    };

    // ─── Standalone Library (tab-library panel) ──────────────
    var _libStandaloneFilter = 'all';
    var _libStandaloneSearch = '';
    var _libStandaloneSort = 'newest';

    function _libRenderStandaloneGrid() {
      var grid = document.getElementById('libStandaloneGrid');
      if (!grid) return;
      var items = _libAllItems.slice();

      // Filter by category (heygen_video treated as raw_video)
      if (_libStandaloneFilter !== 'all') {
        items = items.filter(function(i) {
          var cat = i.category === 'heygen_video' ? 'raw_video' : i.category;
          return cat === _libStandaloneFilter;
        });
      }

      // Search
      if (_libStandaloneSearch) {
        var q = _libStandaloneSearch.toLowerCase();
        items = items.filter(function(i) { return (i.label || i.name || i.url || '').toLowerCase().includes(q); });
      }

      // Sort
      if (_libStandaloneSort === 'newest') items.sort(function(a, b) { return new Date(b.created_at || 0) - new Date(a.created_at || 0); });
      else if (_libStandaloneSort === 'oldest') items.sort(function(a, b) { return new Date(a.created_at || 0) - new Date(b.created_at || 0); });
      else if (_libStandaloneSort === 'name') items.sort(function(a, b) { return (a.label || a.name || '').localeCompare(b.label || b.name || ''); });

      // Count
      var countEl = document.getElementById('libStandaloneCount');
      if (countEl) countEl.textContent = items.length + ' item' + (items.length !== 1 ? 's' : '');

      if (items.length === 0) {
        grid.innerHTML = '<div style="text-align:center;padding:40px 0;color:var(--dim);">' +
          (_libAllItems.length ? 'No matches found.' : 'No media yet. Create one in the Studio!') + '</div>';
        return;
      }

      var html = '<div class="lib-grid">';
      items.forEach(function(item) {
        var isVideo = /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(item.url);
        var dateStr = item.created_at ? new Date(item.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
        html += '<div class="lib-cell" data-id="' + item.id + '">';
        html += '<div class="lib-thumb">';
        var catLabels = { raw_image: 'RAW', raw_video: 'RAW', finished_image: 'AD', finished_video: 'AD' };
        var catLabel = catLabels[item.category] || '';
        if (isVideo) {
          html += '<video src="' + esc(item.url) + '" muted preload="metadata" style="width:100%;height:100%;object-fit:cover;"></video>';
          html += '<div class="lib-badge">' + (catLabel ? catLabel + ' \u00B7 ' : '') + 'VIDEO</div>';
        } else {
          html += '<img src="' + esc(item.url) + '" loading="lazy" style="width:100%;height:100%;object-fit:cover;" />';
          if (catLabel) html += '<div class="lib-badge">' + catLabel + '</div>';
        }
        html += '<button class="lib-delete" data-id="' + item.id + '" title="Delete">&times;</button>';
        html += '</div>';
        html += '<div class="lib-meta">';
        html += '<div class="lib-name">' + esc(item.label || item.name || 'Untitled') + '</div>';
        html += '<div class="lib-date">' + dateStr + '</div>';
        html += '</div>';
        html += '</div>';
      });
      html += '</div>';
      grid.innerHTML = html;

      // Click handlers
      grid.querySelectorAll('.lib-cell').forEach(function(cell) {
        cell.addEventListener('click', function(e) {
          if (e.target.closest('.lib-delete')) return;
          var id = cell.dataset.id;
          var item = _libAllItems.find(function(i) { return String(i.id) === String(id); });
          if (item) _libShowDetail(item);
        });
      });
      // Delete handlers
      grid.querySelectorAll('.lib-delete').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
          e.stopPropagation();
          if (!confirm('Delete this item from the library?')) return;
          var id = btn.dataset.id;
          btn.textContent = '...';
          fetch(WORKER_BASE + '/admin/media-library/' + id, {
            method: 'DELETE', headers: authHeaders()
          }).then(function() {
            _libAllItems = _libAllItems.filter(function(i) { return String(i.id) !== String(id); });
            _libRenderStandaloneGrid();
          });
        });
      });
    }

    // ─── Detail Overlay ─────────────────────────────────────
    function _libShowDetail(item) {
      var isVideo = /\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i.test(item.url);
      var catNames = {
        raw_image: 'Raw Image', raw_video: 'Raw Video',
        finished_image: 'Image Ad', finished_video: 'Video Ad'
      };
      var catName = catNames[item.category] || item.category || 'Unknown';
      var dateStr = item.created_at ? new Date(item.created_at).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit'
      }) : '';

      var isHeyGen = isVideo && (item.label || '').indexOf('HeyGen') === 0;
      var mediaHtml;
      if (isVideo && isHeyGen) {
        // Crop 16:9 HeyGen video to 9:16 portrait in a container
        mediaHtml = '<div style="width:280px;max-width:100%;aspect-ratio:9/16;overflow:hidden;border-radius:8px;margin:0 auto;">' +
          '<video src="' + esc(item.url) + '" controls preload="metadata" style="width:100%;height:100%;object-fit:cover;"></video>' +
          '</div>';
      } else if (isVideo) {
        mediaHtml = '<video src="' + esc(item.url) + '" controls preload="metadata" style="max-width:100%;max-height:60vh;border-radius:8px;background:#000;"></video>';
      } else {
        mediaHtml = '<img src="' + esc(item.url) + '" style="max-width:100%;max-height:60vh;border-radius:8px;" />';
      }

      var overlay = document.createElement('div');
      overlay.className = 'lib-overlay';
      overlay.innerHTML =
        '<div class="lib-detail-panel">' +
          '<button class="lib-close" style="position:absolute;top:14px;right:14px;" onclick="this.closest(\'.lib-overlay\').remove()">&times;</button>' +
          '<div class="lib-detail-media">' + mediaHtml + '</div>' +
          '<div class="lib-detail-info">' +
            '<div class="lib-detail-name">' + esc(item.label || item.name || 'Untitled') + '</div>' +
            '<div class="lib-detail-meta">' +
              '<span class="lib-detail-cat">' + catName + '</span>' +
              '<span class="lib-detail-date">' + dateStr + '</span>' +
            '</div>' +
            '<div class="lib-detail-actions">' +
              '<button class="btn-secondary" style="padding:8px 16px;font-size:13px;" onclick="this.closest(\'.lib-overlay\').remove()">Close</button>' +
              '<button class="btn-secondary" style="padding:8px 16px;font-size:13px;color:var(--red);border-color:rgba(255,80,80,.3);" id="libDetailDelete">Delete</button>' +
            '</div>' +
          '</div>' +
        '</div>';

      overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
      document.body.appendChild(overlay);

      // Delete
      document.getElementById('libDetailDelete').addEventListener('click', function() {
        if (!confirm('Delete this item from the library?')) return;
        fetch(WORKER_BASE + '/admin/media-library/' + item.id, {
          method: 'DELETE', headers: authHeaders()
        }).then(function() {
          _libAllItems = _libAllItems.filter(function(i) { return String(i.id) !== String(item.id); });
          _libRenderStandaloneGrid();
          overlay.remove();
          showToast('Deleted.', 'success');
        });
      });
    }

    window.libStandaloneSetFilter = function(filter, btn) {
      _libStandaloneFilter = filter;
      document.querySelectorAll('#tab-library .lib-filter-btn').forEach(function(b) { b.classList.remove('active'); });
      if (btn) btn.classList.add('active');
      _libRenderStandaloneGrid();
    };

    window.loadLibraryStandalone = function() {
      var grid = document.getElementById('libStandaloneGrid');
      if (!grid) return;
      grid.innerHTML = '<div style="text-align:center;padding:40px 0;color:var(--dim);">Loading...</div>';

      // Wire up controls (idempotent)
      var searchEl = document.getElementById('libStandaloneSearch');
      if (searchEl && !searchEl._wired) {
        searchEl._wired = true;
        searchEl.addEventListener('input', function() { _libStandaloneSearch = this.value; _libRenderStandaloneGrid(); });
      }
      var sortEl = document.getElementById('libStandaloneSort');
      if (sortEl && !sortEl._wired) {
        sortEl._wired = true;
        sortEl.addEventListener('change', function() { _libStandaloneSort = this.value; _libRenderStandaloneGrid(); });
      }

      fetch(WORKER_BASE + '/admin/media-library', { headers: authHeaders() }).then(function(r) { return r.json(); }).then(function(items) {
        _libAllItems = items;
        _libRenderStandaloneGrid();
      }).catch(function() {
        grid.innerHTML = '<div style="text-align:center;padding:40px 0;color:var(--red);">Failed to load library.</div>';
      });
    };

    window.libStandaloneUpload = function() {
      var input = document.createElement('input');
      input.type = 'file';
      input.accept = 'image/*,video/mp4,video/quicktime,video/webm';
      input.onchange = function() {
        if (!input.files || !input.files[0]) return;
        var file = input.files[0];
        var formData = new FormData();
        formData.append('file', file);
        showToast('Uploading...', 'info');
        fetch(WORKER_BASE + '/admin/media-library', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + authToken },
          body: formData
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.error) { showToast('Upload failed: ' + data.error, 'error'); return; }
          showToast('Uploaded!', 'success');
          loadLibraryStandalone();
        }).catch(function() { showToast('Upload failed', 'error'); });
      };
      input.click();
    };
