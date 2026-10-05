/**
 * 模块名称：池代理列表（proxies.js）
 * 功能描述：代理列表的数据面：查询与渲染、筛选与高级筛选、排序与分页、行选中、批量验证与删除、
 *           单条收藏，以及行详情抽屉、右键菜单、表格键盘漫游、列宽调整与表格密度的接线。
 * 职责边界：负责：代理列表的查询、呈现与交互，以及列表侧发起的批量验证与删除；不负责：池状态、抓取插件与
 *           任务中心（提交后任务的进度与结果展示，pool.js），面板外壳与配置/日志页（app.js），浮层与表格通用组件（tables.js）。
 * 关键依赖：jQuery（全局 $ 及各 Ajax 与工具方法）；common.js（转义、模板、存储、空行、时间格式化与 token 拼接）；
 *           app.js（toast / 确认框 / 按钮加载态 / 剪贴板）；i18n.js（T / lang / onLangRender）；
 *           pool.js（poolRequest / poolErrorText / poolReady / trackTask / updatePoolStatus）；
 *           tables.js（表格加载态与重试、行抽屉、右键菜单、键盘漫游）。
 * 已知限制：
 *           1) 全部为全局变量与全局函数，与 app.js、pool.js 共用命名空间，重名会静默覆盖。
 *           2) 行选中：单击单选、Ctrl/⌘ 跳行多选、Shift 从锚点扩选、拖拽按起始行整段加选或取消，补发的 click 被抑制。
 *           3) 翻页、改筛选、改每页条数都会清空选中：选中集合按 id 记，跨页保留会删掉不可见的行。
 *           4) 列宽拖拽开始时必须锁死全部列宽并切 table-layout: fixed，只锁被拖的列会让其余列重排。
 *           5) 筛选存档只在页面加载后首次打开池页签时恢复一次，否则页签切换会重置未提交的条件。
 *           6) 详情抽屉与右键菜单的数据取自 pageProxies，仅对当前页的行有效，翻页即失效。
 *           7) 行点击与拖选必须限定选择器 tr[data-id]：骨架行与失败提示行没有 data-index，匹配它们会把 lastCheckedIndex 写成 NaN。
 */

var currentFilters = {};
var sortField = 'health_score';
var sortOrder = 'desc';
var currentPage = 1;
var pageSize = 50;
var totalCount = 0;
var pageProxies = [];
var selectedIds = {};
var lastCheckedIndex = -1;
var _filtersRestored = false;

var FILTER_DEBOUNCE_MS = 300;

var FILTER_STORAGE_KEY = 'proxycat-pool-filters-v3';

var FILTER_FIELDS = [
  ['#filter-protocol', 'protocol'],
  ['#filter-status', 'status'],
  ['#filter-favorite', 'is_favorite'],
  ['#filter-anonymity', 'anonymity_level'],
  ['#filter-source', 'source'],
  ['#filter-region', 'region'],
  ['#filter-ip', 'ip'],
  ['#filter-min-delay', 'min_delay'],
  ['#filter-max-delay', 'max_delay'],
  ['#filter-min-health', 'min_health_score'],
];


function _regionValue(value) {
  var text = (value || '').trim();
  return (text && text !== '未知') ? text : '';
}

function regionText(p) {
  var zh = _regionValue(p.region);
  var en = _regionValue(p.region_en);
  return lang === 'en' ? (en || zh) : (zh || en);
}

function regionHint(p) {
  var shown = regionText(p);
  var other = lang === 'en' ? _regionValue(p.region) : _regionValue(p.region_en);
  if (!other || other === shown) return shown;
  return shown ? shown + ' / ' + other : other;
}

var REGION_EN_FIELDS = ['country_en', 'province_en', 'city_en'];
var REGION_ZH_FIELDS = ['country', 'province', 'city'];

function regionUntranslated(p) {
  var shown = regionText(p);
  if (!shown) return false;
  var mine = lang === 'en' ? REGION_ZH_FIELDS : REGION_EN_FIELDS;
  return mine.some(function (field, index) {
    var other = lang === 'en' ? REGION_EN_FIELDS[index] : REGION_ZH_FIELDS[index];
    var value = (p[field] || '').trim();
    if (!value || value === '未知') return false;
    return value === (p[other] || '').trim();
  });
}

function sortColumnForLanguage(field) {
  if (field === 'region' && lang === 'en') return 'region_en';
  return field;
}


function loadProxies() {
  onLangRender(loadProxies);
  var params = $.extend({}, collectFilterParams(), {
    page: currentPage,
    page_size: pageSize,
    sort_by: sortColumnForLanguage(sortField),
    sort_order: sortOrder
  });

  updateSortIcons();
  beginTableLoad('#proxy-tbody', 8, 8);

  $.ajax({ url: appendToken('/api/pool/get?' + $.param(params)), timeout: 15000 })
    .done(function (list) {
      clearTableAlert('#proxy-tbody');
      pageProxies = list || [];
      renderProxyTable(pageProxies);
      loadProxyCount();
    })
    .fail(function (x) {
      showTableAlert('#proxy-tbody', 8,
        poolErrorText(x) + T().sep_mid + T().stale_data_note, 'proxies');
    });
}

registerTableRetry('proxies', loadProxies);

function loadProxyCount() {
  var countParams = $.extend({}, collectFilterParams());
  $.get(appendToken('/api/pool/count?' + $.param(countParams)))
    .done(function (d) {
      totalCount = d.count || 0;
      renderPager();
    });
}

function renderProxyTable(proxies) {
  var tbody = $('#proxy-tbody');
  tbody.empty();
  $('#proxy-count-badge').text(totalCount + ' ' + T().items_unit).toggle(totalCount > 0);

  if (!proxies.length) {
    tbody.append(emptyRow(8, T().no_proxies));
    updateSelectionUI();
    return;
  }

  proxies.forEach(function (p, index) {
    tbody.append(renderProxyRow(p, index));
  });

  updateSelectionUI();
}

function renderProxyRow(p, index) {
  var id = p.id;
  var classes = [];
  if (selectedIds[id]) classes.push('selected');
  if (p.is_valid === false) classes.push('invalid');
  var rowClass = classes.length ? ' class="' + classes.join(' ') + '"' : '';

  var tooltip = T().col_source + T().sep_colon + (p.source_plugin || '--') +
                '\n' + T().col_validated_at + T().sep_colon + (p.validated_at || '--');

  var untranslated = regionUntranslated(p);
  var regionNote = untranslated ? ' · ' + T().geo_region_untranslated : '';
  var regionMark = untranslated ? '<span class="region-untranslated">*</span>' : '';

  var exitDiffers = p.exit_ip_differs === true;
  var realIpCell = p.real_ip
    ? '<td class="cell-real-ip cell-mono cell-copy' +
        (exitDiffers ? ' cell-exit-differs' : '') + '"' +
      ' data-act="copy" data-copy="' + escapeHtml(p.real_ip) + '"' +
      ' title="' + escapeHtml(copyHint(p.real_ip)) + '">' +
      '<span class="cell-real-ip-value cell-clip">' + escapeHtml(p.real_ip) + '</span>' +
      '</td>'
    : '<td class="cell-real-ip cell-mono">--</td>';

  return '<tr data-id="' + id + '" data-index="' + index + '"' + rowClass +
      ' title="' + escapeHtml(tooltip) + '">' +
    '<td class="cell-protocol">' + protocolBadge(p.protocol) + invalidBadge(p) + '</td>' +
    '<td class="cell-addr cell-copy" data-act="copy"' +
      ' data-copy="' + escapeHtml(p.proxy_url) + '"' +
      ' title="' + escapeHtml(copyHint(p.proxy_url)) + '">' +
      '<span class="cell-clip">' + escapeHtml(p.ip) + ':' + p.port + '</span></td>' +
    realIpCell +
    '<td class="cell-region" title="' + escapeHtml(regionHint(p) + regionNote) + '">' +
      '<span class="cell-clip">' + escapeHtml(regionText(p) || '--') + '</span>' + regionMark + '</td>' +
    '<td class="cell-delay">' + delayBadge(p.delay_ms) + '</td>' +
    '<td class="cell-health">' + healthBadge(p.health_score) + '</td>' +
    '<td class="cell-anonymity">' + anonymityBadge(p.anonymity_level, p.anonymity_fallback) + '</td>' +
    '<td class="cell-actions">' +
      '<button class="icon-btn" data-act="detail" title="' + escapeHtml(T().detail_btn) + '">' +
        '<i class="fa fa-ellipsis-h"></i></button>' +
      '<button class="icon-btn' + (p.is_favorite ? ' on' : '') + '" data-act="favorite"' +
        ' title="' + escapeHtml(T().favorite_btn) + '">' +
        '<i class="fa ' + (p.is_favorite ? 'fa-star' : 'fa-star-o') + '"></i></button>' +
    '</td>' +
  '</tr>';
}

function copyHint(value) {
  return T().click_to_copy + T().sep_colon + value;
}

$(document).on('click', '#proxy-tbody [data-act]', function (e) {
  var $el = $(this);
  var $row = $el.closest('tr');
  var id = parseInt($row.attr('data-id'), 10);

  switch ($el.attr('data-act')) {
    case 'copy':
      copyProxy($el.attr('data-copy'));
      break;
    case 'favorite':
      toggleFavorite(id);
      break;
    case 'detail':
      openProxyDrawer(id);
      break;
  }
});

$(document).on('contextmenu', '#proxy-tbody tr[data-id]', function (e) {
  var id = parseInt($(this).attr('data-id'), 10);
  if (!proxyById(id)) return;
  e.preventDefault();
  openProxyRowMenu(id, e.clientX, e.clientY);
});

$(document).on('click', '#proxy-tbody tr[data-id]', function (e) {
  if (_dragMoved) { _dragMoved = false; return; }
  if ($(e.target).closest('[data-act]').length) return;
  var sel = window.getSelection && window.getSelection();
  if (sel && sel.toString().length > 0) return;

  var $row = $(this);
  toggleRow(
    parseInt($row.attr('data-id'), 10),
    parseInt($row.attr('data-index'), 10),
    e
  );
});

var _dragSelecting = false;
var _dragMoved = false;
var _dragStartIndex = -1;
var _dragStartOn = false;

$(document).on('mousedown', '#proxy-tbody tr[data-id]', function (e) {
  if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey) return;
  if ($(e.target).closest('[data-act]').length) return;

  _dragSelecting = true;
  _dragMoved = false;
  _dragStartIndex = parseInt($(this).attr('data-index'), 10);
  var startId = parseInt($(this).attr('data-id'), 10);
  _dragStartOn = !selectedIds[startId];
  e.preventDefault();
});

$(document).on('mouseenter', '#proxy-tbody tr[data-id]', function () {
  if (!_dragSelecting) return;
  _dragMoved = true;

  var index = parseInt($(this).attr('data-index'), 10);
  var lo = Math.min(_dragStartIndex, index), hi = Math.max(_dragStartIndex, index);
  for (var i = lo; i <= hi; i++) {
    var p = pageProxies[i];
    if (!p) continue;
    if (_dragStartOn) selectedIds[p.id] = true;
    else delete selectedIds[p.id];
  }
  lastCheckedIndex = index;
  syncRowSelection();
});

$(document).on('mouseup', function () {
  _dragSelecting = false;
});


function protocolBadge(protocol) {
  var text = (protocol || '').toUpperCase();
  return '<span class="badge proxy-tag ' + escapeHtml(protocol || '') + '">' + escapeHtml(text) + '</span>';
}

function invalidBadge(p) {
  if (p.is_valid) return '';
  return '<span class="badge badge-invalid" title="' +
         escapeHtml(T().proxy_invalid_badge_hint) + '">' +
         escapeHtml(T().proxy_invalid_badge) + '</span>';
}

function delayBadge(delay) {
  if (delay === null || delay === undefined) return '<span class="badge badge-delay">--</span>';
  var ms = Math.round(delay);
  var cls = ms < 500 ? 'fast' : (ms < 2000 ? 'mid' : 'slow');
  return '<span class="badge badge-delay ' + cls + '">' + ms + 'ms</span>';
}

function healthBadge(score) {
  if (!score) return '<span class="badge badge-delay">--</span>';
  var cls = score >= 70 ? 'fast' : (score >= 40 ? 'mid' : 'slow');
  return '<span class="badge badge-delay ' + cls + '">' + Math.round(score) + '</span>';
}

function anonymityBadge(level, fallback) {
  var names = {
    elite: [T().anon_elite, 'badge-elite'],
    anonymous: [T().anon_anonymous, 'badge-anonymous'],
    transparent: [T().anon_transparent, 'badge-transparent'],
    unverified: [T().anon_unverified, 'badge-unverified']
  };
  var entry = names[level];
  if (!entry) {
    entry = [level || '--', ''];
  }
  var cls = 'badge ' + entry[1] + (fallback ? ' badge-fallback' : '');
  var hint = fallback ? ' title="' + escapeHtml(T().anon_fallback_hint) + '"' : '';
  return '<span class="' + cls + '"' + hint + '>' + escapeHtml(entry[0]) + '</span>';
}


function proxyById(id) {
  for (var i = 0; i < pageProxies.length; i++) {
    if (pageProxies[i].id === id) return pageProxies[i];
  }
  return null;
}

function _text(v) {
  return (v === undefined || v === null || v === '') ? '' : String(v);
}

function _rate(v) {
  if (v === undefined || v === null || v === '') return '';
  return (Number(v) * 100).toFixed(1) + '%';
}

function openProxyDrawer(id) {
  var p = proxyById(id);
  if (!p) return;

  var regionEn = [p.country_en, p.province_en, p.city_en].filter(Boolean).join(' / ');
  var supports = [p.supports_https ? 'HTTPS' : '', p.supports_http ? 'HTTP' : '']
    .filter(Boolean).join(' · ');

  openRowDrawer({
    title: p.ip + ':' + p.port,
    subtitle: (p.protocol || '').toUpperCase() +
      (p.source_plugin ? ' · ' + p.source_plugin : ''),
    fields: drawerSections([
      [T().drawer_group_conn, [
        { label: T().col_address, value: p.proxy_url, mono: true, copy: true },
        { label: T().col_real_ip, value: _text(p.real_ip), mono: true },
        { label: T().drawer_username, value: _text(p.username), mono: true, copy: true },
        { label: T().drawer_password, value: _text(p.password), mono: true },
        { label: T().col_region, value: _text(regionText(p)) },
        { label: T().drawer_region_en, value: regionEn },
        { label: T().drawer_supports, value: supports },
        { label: T().col_source, value: _text(p.source_plugin) }
      ]],
      [T().drawer_group_quality, [
        { label: T().col_delay, value: p.delay_ms === null || p.delay_ms === undefined ? '' : Math.round(p.delay_ms) + ' ms', mono: true },
        { label: T().col_health, value: p.health_score === null || p.health_score === undefined ? '' : String(Math.round(p.health_score)), mono: true },
        { label: T().col_anonymity, html: anonymityBadge(p.anonymity_level, p.anonymity_fallback) },
        { label: T().drawer_success_rate, value: _rate(p.success_rate), mono: true },
        { label: T().drawer_avg_delay, value: p.avg_delay_ms ? Math.round(p.avg_delay_ms) + ' ms' : '', mono: true },
        { label: T().drawer_probe_rate, value: _rate(p.probe_success_rate), mono: true },
        { label: T().drawer_total_checks, value: p.total_checks ? String(p.total_checks) : '', mono: true },
        { label: T().drawer_favorite, value: p.is_favorite ? T().yes : T().no }
      ]],
      [T().drawer_group_time, [
        { label: T().col_validated_at, value: p.validated_at ? fmtTime(p.validated_at) : '' },
        { label: T().drawer_quality_at, value: p.quality_assessed_at ? fmtTime(p.quality_assessed_at) : '' }
      ]]
    ]),
    actions: [
      { label: T().validate_selected_btn, icon: 'fa-check',
        onClick: function () { validateProxyRow(id, 'liveness'); } },
      { label: T().validate_full_btn, icon: 'fa-stethoscope',
        onClick: function () { validateProxyRow(id, 'full'); } },
      { label: p.is_favorite ? T().drawer_unfavorite : T().favorite_btn,
        icon: p.is_favorite ? 'fa-star' : 'fa-star-o',
        onClick: function () { toggleFavorite(id); } },
      { label: T().delete_selected_btn, icon: 'fa-trash', danger: true,
        onClick: function () { deleteProxyRow(id); } }
    ]
  });
}

function openProxyRowMenu(id, x, y) {
  var p = proxyById(id);
  if (!p) return;

  openContextMenu(x, y, [
    { label: T().detail_btn, icon: 'fa-ellipsis-h',
      onClick: function () { openProxyDrawer(id); } },
    { label: T().copy_addr_btn, icon: 'fa-copy',
      onClick: function () { copyProxy(p.proxy_url); } },
    { label: T().ctx_copy_curl, icon: 'fa-terminal',
      onClick: function () { copyToClipboard(copyCurlCommand(p.proxy_url)); } },
    { separator: true },
    { label: p.is_favorite ? T().drawer_unfavorite : T().favorite_btn,
      icon: p.is_favorite ? 'fa-star' : 'fa-star-o',
      onClick: function () { toggleFavorite(id); } },
    { label: T().validate_selected_btn, icon: 'fa-check',
      onClick: function () { validateProxyRow(id, 'liveness'); } },
    { label: T().validate_full_btn, icon: 'fa-stethoscope',
      onClick: function () { validateProxyRow(id, 'full'); } },
    { separator: true },
    { label: T().delete_selected_btn, icon: 'fa-trash', danger: true,
      onClick: function () { deleteProxyRow(id); } }
  ]);
}

function copyCurlCommand(proxyUrl) {
  var target = $('input[name="test_url"]').val() || 'https://www.baidu.com';
  return 'curl -x ' + proxyUrl + ' -sS -o /dev/null -w "%{http_code}\\n" ' + target;
}

function validateProxyRow(id, mode) {
  if (!poolReady()) return;
  poolRequest('POST', 'proxies/batch/validate', { proxy_ids: [id], mode: mode }, function (r) {
    toast(r.message, 'success');
    if (r.task_id) trackTask(r.task_id, T().task_validate_selected);
  });
}

function deleteProxyRow(id) {
  var p = proxyById(id);
  showConfirm(T().delete_selected_btn,
    fillTemplate(T().confirm_delete_proxy, p ? (p.ip + ':' + p.port) : id),
    function (ok) {
      if (!ok) return;
      poolRequest('DELETE', 'proxies/batch/delete', { proxy_ids: [id] }, function (r) {
        toast(r.message, 'success');
        delete selectedIds[id];
        loadProxies();
        updatePoolStatus();
      });
    }, { danger: true });
}

function initProxyTableKeyboard() {
  attachTableKeyboard('#proxy-table', {
    onToggle: function (i) {
      var p = pageProxies[i];
      if (p) toggleRow(p.id, i, {});
    },
    onExtend: function (i) {
      if (lastCheckedIndex < 0) { lastCheckedIndex = i; return; }
      selectRange(Math.min(lastCheckedIndex, i), Math.max(lastCheckedIndex, i), true);
    },
    onSelectAll: function () {
      toggleSelectAll(true);
      $('#select-all').prop('checked', true);
    },
    onActivate: function (i) {
      if (pageProxies[i]) openProxyDrawer(pageProxies[i].id);
    },
    onClear: function () {
      selectedIds = {};
      lastCheckedIndex = -1;
      syncRowSelection();
      updateSelectionUI();
    }
  });
}


var COL_WIDTH_STORAGE_KEY = 'proxycat-pool-cols-v1';

var _colDrag = null;

var COL_MIN_WIDTH = 48;
var COL_MAX_WIDTH = 900;

function lockColumnWidths(table) {
  var cells = table.tHead.rows[0].cells;
  if (!table.classList.contains('cols-locked')) {
    var widths = [];
    for (var i = 0; i < cells.length; i++) {
      widths.push(cells[i].getBoundingClientRect().width);
    }
    if (!widths[0]) return cells;
    for (var j = 0; j < cells.length; j++) {
      cells[j].style.width = widths[j] + 'px';
    }
    table.classList.add('cols-locked');
  }
  return cells;
}

function saveColumnWidths() {
  var table = document.getElementById('proxy-table');
  if (!table || !table.tHead) return;

  var cells = table.tHead.rows[0].cells;
  var widths = {};
  for (var i = 0; i < cells.length; i++) {
    widths[cells[i].getAttribute('data-col')] = Math.round(cells[i].getBoundingClientRect().width);
  }
  safeSetJSON(COL_WIDTH_STORAGE_KEY, widths);
}

function restoreColumnWidths() {
  var table = document.getElementById('proxy-table');
  var saved = safeGetJSON(COL_WIDTH_STORAGE_KEY, null);
  if (!table || !table.tHead || !saved) return;

  var cells = table.tHead.rows[0].cells;
  var applied = false;
  for (var i = 0; i < cells.length; i++) {
    var width = saved[cells[i].getAttribute('data-col')];
    if (typeof width === 'number' && width >= COL_MIN_WIDTH) {
      cells[i].style.width = width + 'px';
      applied = true;
    }
  }
  if (applied) table.classList.add('cols-locked');
}

var DENSITY_STORAGE_KEY = 'proxycat-density';

function setTableDensity(mode) {
  var compact = mode === 'compact';
  $('body').attr('data-density', compact ? 'compact' : 'cozy');
  safeSetItem(DENSITY_STORAGE_KEY, compact ? 'compact' : 'cozy');
  $('#density-btn i').attr('class', compact ? 'fa fa-th-large' : 'fa fa-th-list');
}

function toggleTableDensity() {
  setTableDensity($('body').attr('data-density') === 'compact' ? 'cozy' : 'compact');
}

function initTableDensity() {
  setTableDensity(safeGetItem(DENSITY_STORAGE_KEY) || 'cozy');
}


function resetColumnWidths() {
  var table = document.getElementById('proxy-table');
  if (table && table.tHead) {
    var cells = table.tHead.rows[0].cells;
    for (var i = 0; i < cells.length; i++) {
      cells[i].style.width = '';
    }
    table.classList.remove('cols-locked');
  }
  safeSetJSON(COL_WIDTH_STORAGE_KEY, null);
}

$('#proxy-table .col-resize').on('mousedown', function (e) {
  e.preventDefault();
  e.stopPropagation();

  var table = document.getElementById('proxy-table');
  var cells = lockColumnWidths(table);
  var index = $(this).closest('th').index();

  _colDrag = {
    cell: cells[index],
    startX: e.pageX,
    startWidth: cells[index].getBoundingClientRect().width
  };
  $(this).addClass('dragging');
  $('body').addClass('col-resizing');
});

$('#proxy-table .col-resize').on('click', function (e) {
  e.stopPropagation();
});

$(document).on('mousemove', function (e) {
  if (!_colDrag) return;
  if (e.buttons === 0) { endColumnDrag(); return; }
  var width = _colDrag.startWidth + (e.pageX - _colDrag.startX);
  width = Math.min(COL_MAX_WIDTH, Math.max(COL_MIN_WIDTH, width));
  _colDrag.cell.style.width = width + 'px';
});

$(document).on('mouseup', endColumnDrag);

function endColumnDrag() {
  if (!_colDrag) return;
  _colDrag = null;
  $('#proxy-table .col-resize').removeClass('dragging');
  $('body').removeClass('col-resizing');
  saveColumnWidths();
}

restoreColumnWidths();


function collectFilterParams() {
  currentFilters = {};

  var protocol = $('#filter-protocol').val();
  var status = $('#filter-status').val();
  var favorite = $('#filter-favorite').val();
  var anonymity = $('#filter-anonymity').val();
  var source = $('#filter-source').val();
  var region = $('#filter-region').val();
  var ip = $('#filter-ip').val();
  var minDelay = $('#filter-min-delay').val();
  var maxDelay = $('#filter-max-delay').val();
  var minHealth = $('#filter-min-health').val();

  if (protocol) currentFilters.protocol = protocol;
  if (status) currentFilters.status = status;
  if (favorite) currentFilters.is_favorite = favorite;
  if (anonymity) currentFilters.anonymity_level = anonymity;
  if (source) currentFilters.source = source;
  if (region) currentFilters.region = region;
  if (ip) currentFilters.ip = ip;
  if (minDelay !== '') currentFilters.min_delay = minDelay;
  if (maxDelay !== '') currentFilters.max_delay = maxDelay;
  if (minHealth !== '') currentFilters.min_health_score = minHealth;

  return currentFilters;
}

function applyFilters() {
  currentPage = 1;
  selectedIds = {};
  updateSelectionUI();
  saveFiltersToStorage();
  loadProxies();
}


function saveFiltersToStorage() {
  safeSetJSON(FILTER_STORAGE_KEY, {
    filters: collectFilterParams(),
    sortField: sortField,
    sortOrder: sortOrder,
    pageSize: pageSize
  });
}

function readSavedFilters() {
  var saved = safeGetJSON(FILTER_STORAGE_KEY, null);
  return saved && typeof saved === 'object' ? saved : null;
}

function restoreFiltersFromStorage() {
  if (_filtersRestored) return;
  _filtersRestored = true;

  var saved = readSavedFilters();
  if (saved && saved.pageSize) pageSize = parseInt(saved.pageSize, 10) || pageSize;
  $('#page-size').val(pageSize);
  if (!saved) return;

  var filters = saved.filters || {};
  FILTER_FIELDS.forEach(function (entry) {
    if (entry[1] === 'source') return;
    if (filters[entry[1]] !== undefined) $(entry[0]).val(filters[entry[1]]);
  });

  if (saved.sortField) { sortField = saved.sortField; sortOrder = saved.sortOrder || 'asc'; }

  var advanced = ['region', 'ip', 'min_delay', 'max_delay', 'min_health_score'];
  if (advanced.some(function (k) { return filters[k]; })) {
    $('#advanced-filters').show();
    $('#advanced-icon').removeClass('fa-chevron-down').addClass('fa-chevron-up');
  }

  updateSortIcons();
}

var _filterTimer = null;

function onFilterInput() {
  clearTimeout(_filterTimer);
  _filterTimer = setTimeout(applyFilters, FILTER_DEBOUNCE_MS);
}

function resetFilters() {
  $('#filter-protocol, #filter-status, #filter-favorite, #filter-anonymity, #filter-source').val('');
  $('#filter-region, #filter-ip, #filter-min-delay, #filter-max-delay, #filter-min-health').val('');
  applyFilters();
}

function toggleAdvancedFilters() {
  var box = $('#advanced-filters');
  var hidden = box.is(':hidden');
  box.toggle(hidden);
  $('#advanced-icon').toggleClass('fa-chevron-down', !hidden).toggleClass('fa-chevron-up', hidden);
}

function loadSources() {
  onLangRender(loadSources);
  $.get(appendToken('/api/pool/sources'), function (d) {
    var select = $('#filter-source');
    var current = select.val();
    select.empty().append('<option value="">' + escapeHtml(T().filter_all_source) + '</option>');
    (d.sources || []).forEach(function (name) {
      select.append('<option value="' + escapeHtml(name) + '">' + escapeHtml(name) + '</option>');
    });

    var saved = readSavedFilters();
    var savedSource = saved && saved.filters ? saved.filters.source : '';
    select.val(current || savedSource || '');
  });
}


function sortBy(field) {
  if (sortField === field) {
    sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    sortField = field;
    sortOrder = 'asc';
  }
  updateSortIcons();
  currentPage = 1;
  saveFiltersToStorage();
  loadProxies();
}

function updateSortIcons() {
  $('.sort-icon').removeClass('active fa-sort-asc fa-sort-desc').addClass('fa-sort');
  var icon = $('#sort-' + sortField);
  icon.addClass('active').removeClass('fa-sort')
    .addClass(sortOrder === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc');
}

function totalPages() {
  return Math.max(1, Math.ceil(totalCount / pageSize));
}

function gotoPage(page) {
  var last = totalPages();
  var target = page === -1 || page === '-1' ? last : parseInt(page, 10);

  if (isNaN(target)) { renderPager(); return; }
  target = Math.min(Math.max(1, target), last);

  if (target === currentPage) { renderPager(); return; }

  currentPage = target;
  selectedIds = {};
  updateSelectionUI();
  loadProxies();
}

function nextPage() { gotoPage(currentPage + 1); }

function previousPage() { gotoPage(currentPage - 1); }

function changePageSize() {
  pageSize = parseInt($('#page-size').val(), 10) || 50;
  currentPage = 1;
  selectedIds = {};
  updateSelectionUI();
  saveFiltersToStorage();
  loadProxies();
}

function renderPager() {
  var last = totalPages();
  var start = totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  var end = Math.min(currentPage * pageSize, totalCount);

  var jump = $('#page-jump');
  if (!jump.is(':focus')) jump.val(currentPage).attr('max', last);

  $('#total-count').text(last <= 1
    ? fillTemplate(T().pager_total, totalCount)
    : fillTemplate(T().pager_range, start, end) + T().sep_mid +
      fillTemplate(T().pager_total, totalCount) + T().sep_mid +
      fillTemplate(T().page_of, currentPage, last));

  $('#prev-btn, #first-btn').prop('disabled', currentPage <= 1);
  $('#next-btn, #last-btn').prop('disabled', currentPage >= last);
  $('#proxy-count-badge').text(totalCount + ' ' + T().items_unit).toggle(totalCount > 0);
}


function toggleRow(id, index, event) {
  if (event) event.stopPropagation();

  if (event && event.shiftKey && lastCheckedIndex >= 0) {
    selectRange(lastCheckedIndex, index, !selectedIds[id]);
  } else if (event && (event.ctrlKey || event.metaKey)) {
    if (selectedIds[id]) delete selectedIds[id];
    else selectedIds[id] = true;
  } else if (selectedIds[id]) {
    delete selectedIds[id];
  } else {
    Object.keys(selectedIds).forEach(function (key) { delete selectedIds[key]; });
    selectedIds[id] = true;
  }

  lastCheckedIndex = index;
  syncRowSelection();
}

function selectRange(from, to, select) {
  var lo = Math.min(from, to), hi = Math.max(from, to);
  for (var i = lo; i <= hi; i++) {
    var p = pageProxies[i];
    if (!p) continue;
    if (select) selectedIds[p.id] = true;
    else delete selectedIds[p.id];
  }
}

function toggleSelectAll(checked) {
  if (checked) {
    pageProxies.forEach(function (p) { selectedIds[p.id] = true; });
  } else {
    pageProxies.forEach(function (p) { delete selectedIds[p.id]; });
  }
  syncRowSelection();
}

function syncRowSelection() {
  $('#proxy-tbody tr[data-id]').each(function () {
    $(this).toggleClass('selected', !!selectedIds[$(this).data('id')]);
  });
  updateSelectionUI();
}

function updateSelectionUI() {
  var count = Object.keys(selectedIds).length;
  $('#selected-count').text(count ? fillTemplate(T().selected_count, count) : '');

  var barOpen = count > 0;
  $('#batch-bar').toggle(barOpen);
  $('body').toggleClass('batch-bar-open', barOpen);

  var canAct = count > 0 && poolReady();
  $('#btn-batch-validate, #btn-batch-validate-full, #btn-batch-delete')
    .prop('disabled', !canAct);

  var allSelected = pageProxies.length > 0 && pageProxies.every(function (p) { return selectedIds[p.id]; });
  $('#select-all').prop('checked', allSelected);
}

function validateSelected(mode) {
  var ids = Object.keys(selectedIds).map(Number);
  if (!ids.length) return;
  var btn = $(mode === 'full' ? '#btn-batch-validate-full' : '#btn-batch-validate');
  btnLoad(btn, true);
  poolRequest('POST', 'proxies/batch/validate', { proxy_ids: ids, mode: mode }, function (r) {
    toast(r.message, r.success === false ? 'error' : 'success');
    if (r.task_id) {
      trackTask(r.task_id, mode === 'full' ? T().task_validate_full : T().task_validate_selected);
    }
  }).always(function () { btnLoad(btn, false); });
}

function deleteSelected() {
  var ids = Object.keys(selectedIds).map(Number);
  if (!ids.length) return;

  showConfirm(T().delete_selected_btn,
    fillTemplate(T().confirm_delete_selected, ids.length), function (ok) {
    if (!ok) return;
    poolRequest('DELETE', 'proxies/batch/delete', { proxy_ids: ids }, function (r) {
      toast(r.message, 'success');
      selectedIds = {};
      updateSelectionUI();
      loadProxies();
      updatePoolStatus();
    });
  }, { danger: true });
}

function deleteAllInvalid() {
  if (!poolReady()) return;

  $.get(appendToken('/api/pool/count?status=invalid'))
    .done(function (d) {
      var count = d.count || 0;
      if (count === 0) { toast(T().no_invalid_proxies, 'success'); return; }

      showConfirm(
        T().delete_invalid_btn,
        fillTemplate(T().confirm_delete_invalid_count, count),
        function (ok) { if (ok) performDeleteInvalid(); },
        { danger: true }
      );
    })
    .fail(function (x) { toast(poolErrorText(x), 'error'); });
}

function performDeleteInvalid() {
  poolRequest('DELETE', 'delete/invalid', null, function (r) {
    toast(r.message, 'success');
    selectedIds = {};
    updateSelectionUI();
    loadProxies();
    updatePoolStatus();
  });
}


function toggleFavorite(id) {
  var p = proxyById(id);
  var next = p ? !p.is_favorite : true;
  paintFavorite(id, next);
  poolRequest('POST', 'proxies/' + id + '/favorite', null, function (r) {
    var on = r.is_favorite === undefined ? next : !!r.is_favorite;
    paintFavorite(id, on);
    toast(r.message, r.success === false ? 'error' : 'success');
  }).fail(function () {
    paintFavorite(id, !next);
  });
}

function paintFavorite(id, on) {
  var p = proxyById(id);
  if (p) p.is_favorite = on;
  var $btn = $('#proxy-tbody tr[data-id="' + id + '"] [data-act="favorite"]');
  if (!$btn.length) return;
  $btn.toggleClass('on', on);
  $btn.find('i').toggleClass('fa-star', on).toggleClass('fa-star-o', !on);
}

function copyProxy(text) {
  if (!text) return;

  copyToClipboard(text, function () {
    toast(T().addr_copied + T().sep_colon + text, 'success');
  });
}
