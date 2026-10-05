/**
 * 模块名称：命令面板与全局快捷键（palette.js）
 * 功能描述：Ctrl/⌘+K 命令面板的取词、过滤、渲染与执行，把跳转、服务启停、批量校验、
 *           导入导出、切主题切语言等动作收成可搜索入口，并提供全局快捷键分发、说明弹窗与直达链接复制。
 * 职责边界：负责：命令面板与快捷键说明弹窗的渲染、过滤、键盘导航与全局快捷键分发，以及当前视图直达链接的复制。
 *           不负责：表格键盘操作（tables.js）与命令背后的业务动作（由 app.js / pool.js / proxies.js / i18n.js 提供）。
 * 关键依赖：jQuery；i18n.js 的 T() / onLangRender / toggleLang；common.js 的 escapeHtml / getToken；
 *           运行期调用 app.js / pool.js / proxies.js 的全局函数。
 * 已知限制：
 * 1. 普通单键快捷键在输入态让路（isTypingTarget），新增键位无需各自判断；Ctrl/⌘+K 为全局例外，命令面板打开时搜索框内的 Esc/方向键/Enter 由面板接管。
 * 2. 单键快捷键（1-4、r、/、?、Esc）只在无 Ctrl / ⌘ / Alt 修饰时生效。
 * 3. Esc 只接管命令面板与快捷键说明弹窗两层，右键菜单、抽屉等浮层由各自脚本处理。
 * 4. 过滤是大小写不敏感的子串匹配（同时匹配文案与命令 id），不做拼音或模糊评分。
 * 5. 关闭面板时必须把焦点从搜索框 blur 掉，否则隐藏的输入框仍占着 document.activeElement 吞掉单键快捷键。
 * 6. 「刷新当前页」遇到未保存的服务器表单修改会跳过并提示，不会用 loadConfig() 整份重写表单。
 * 7. 命令文案在打开面板时按当前语言重新取词（_commandEntries），不在加载期固化，否则切换语言后仍显示旧文案。
 */
var _paletteEntries = [];
var _paletteFocus = -1;

function _commandDefs() {
  return [
    { id: 'view-config', group: 'cmd_group_view', label: 'config_tab', icon: 'fa-sliders',
      run: function () { switchTab('tab-config'); } },
    { id: 'view-pool-manage', group: 'cmd_group_view', label: 'pool_view_manage', icon: 'fa-list',
      run: function () { switchTab('tab-pool', { view: 'pool-view-manage' }); } },
    { id: 'view-pool-settings', group: 'cmd_group_view', label: 'pool_config_tab', icon: 'fa-cogs',
      run: function () { switchTab('tab-pool', { view: 'pool-view-settings' }); } },
    { id: 'view-pool-db', group: 'cmd_group_view', label: 'db_maintain_title', icon: 'fa-database',
      run: function () { switchTab('tab-pool', { view: 'pool-view-db' }); } },
    { id: 'view-access', group: 'cmd_group_view', label: 'access_control_tab', icon: 'fa-shield',
      run: function () { switchTab('tab-access'); } },
    { id: 'view-logs', group: 'cmd_group_view', label: 'logs_tab', icon: 'fa-file-text',
      run: function () { switchTab('tab-logs'); } },

    { id: 'go-source', group: 'cmd_group_config', label: 'cfg_group_source', icon: 'fa-plug',
      run: function () { switchTab('tab-config', { group: 'source' }); } },
    { id: 'go-listen', group: 'cmd_group_config', label: 'cfg_group_listen', icon: 'fa-server',
      run: function () { switchTab('tab-config', { group: 'listen' }); } },
    { id: 'go-exits', group: 'cmd_group_config', label: 'cfg_group_exits', icon: 'fa-random',
      run: function () { switchTab('tab-config', { group: 'exits' }); } },
    { id: 'go-check', group: 'cmd_group_config', label: 'cfg_group_check', icon: 'fa-check-circle-o',
      run: function () { switchTab('tab-config', { group: 'check' }); } },
    { id: 'go-perf', group: 'cmd_group_config', label: 'cfg_group_perf', icon: 'fa-tachometer',
      run: function () { switchTab('tab-config', { group: 'perf' }); } },
    { id: 'go-logs-cfg', group: 'cmd_group_config', label: 'cfg_group_logs', icon: 'fa-file-text-o',
      run: function () { switchTab('tab-config', { group: 'logs' }); } },
    { id: 'go-advanced', group: 'cmd_group_config', label: 'advanced_config_title', icon: 'fa-cog',
      run: function () { switchTab('tab-config', { group: 'advanced' }); } },

    { id: 'svc-start', group: 'cmd_group_action', label: 'start_service', icon: 'fa-play',
      run: function () { controlService('start'); } },
    { id: 'svc-stop', group: 'cmd_group_action', label: 'stop_service', icon: 'fa-stop',
      run: function () { controlService('stop'); } },
    { id: 'svc-restart', group: 'cmd_group_action', label: 'restart_service', icon: 'fa-refresh',
      run: function () { controlService('restart'); } },
    { id: 'switch-proxy', group: 'cmd_group_action', label: 'manual_switch_btn', icon: 'fa-exchange',
      run: function () { switchProxy(); } },
    { id: 'validate-valid', group: 'cmd_group_action', label: 'validate_valid_btn', icon: 'fa-check-circle',
      run: function () { validateAllProxies(true); } },
    { id: 'validate-invalid', group: 'cmd_group_action', label: 'validate_invalid_btn', icon: 'fa-question-circle',
      run: function () { validateAllProxies(false); } },
    { id: 'full-check', group: 'cmd_group_action', label: 'full_check_btn', icon: 'fa-globe',
      run: function () { updateAllGeo(); } },
    { id: 'import', group: 'cmd_group_action', label: 'import_btn', icon: 'fa-upload',
      run: function () { openImportModal(); } },
    { id: 'export', group: 'cmd_group_action', label: 'export_btn', icon: 'fa-download',
      run: function () { openExportModal(); } },
    { id: 'copy-api-link', group: 'cmd_group_action', label: 'copy_api_link_btn', icon: 'fa-link',
      run: function () { copyPoolApiLink(); } },
    { id: 'delete-invalid', group: 'cmd_group_action', label: 'delete_invalid_btn', icon: 'fa-broom',
      danger: true, run: function () { deleteAllInvalid(); } },

    { id: 'toggle-theme', group: 'cmd_group_panel', label: 'theme_toggle_btn', icon: 'fa-moon-o',
      run: function () { cycleTheme(); } },
    { id: 'toggle-lang', group: 'cmd_group_panel', label: 'lang_toggle_btn', icon: 'fa-globe',
      run: function () { toggleLang(); } },
    { id: 'copy-view-link', group: 'cmd_group_panel', label: 'cmd_copy_view_link', icon: 'fa-share-alt',
      run: function () { copyCurrentViewLink(); } },
    { id: 'shortcut-help', group: 'cmd_group_panel', label: 'shortcut_title', icon: 'fa-keyboard-o',
      run: function () { showShortcutHelp(); } }
  ];
}

function _commandEntries() {
  return _commandDefs().map(function (c) {
    return {
      id: c.id, icon: c.icon, danger: c.danger, run: c.run,
      label: T()[c.label],
      group: T()[c.group]
    };
  });
}

function isCommandPaletteOpen() {
  return $('#cmd-palette').hasClass('show');
}

function openCommandPalette() {
  _paletteEntries = _commandEntries();
  _paletteFocus = -1;
  $('#palette-input').val('');
  renderPaletteList('');
  $('#cmd-palette').addClass('show');
  setTimeout(function () { $('#palette-input').trigger('focus'); }, 60);
}

function closeCommandPalette() {
  $('#cmd-palette').removeClass('show');
  $('#palette-input').trigger('blur');
  _paletteFocus = -1;
}

function _highlight(label, query) {
  if (!query) return escapeHtml(label);
  var at = label.toLowerCase().indexOf(query.toLowerCase());
  if (at < 0) return escapeHtml(label);
  return escapeHtml(label.slice(0, at)) +
    '<mark>' + escapeHtml(label.slice(at, at + query.length)) + '</mark>' +
    escapeHtml(label.slice(at + query.length));
}

function _paletteMatches(e, q) {
  if (!q) return true;
  var needle = q.toLowerCase();
  return e.label.toLowerCase().indexOf(needle) >= 0 ||
         e.id.toLowerCase().indexOf(needle) >= 0;
}

function renderPaletteList(query) {
  var q = (query || '').trim();
  var list = $('#palette-list').empty();
  var matched = _paletteEntries.filter(function (e) { return _paletteMatches(e, q); });

  if (!matched.length) {
    list.append('<div class="palette-empty">' + escapeHtml(T().cmd_no_match) + '</div>');
    _paletteFocus = -1;
    return;
  }

  _paletteFocus = 0;
  matched.forEach(function (e, i) {
    var btn = $('<button class="palette-item' + (i === 0 ? ' focus' : '') + '"></button>')
      .html('<i class="fa ' + e.icon + '"></i>' +
            '<span class="palette-label">' + _highlight(e.label, q) + '</span>' +
            '<span class="palette-group">' + escapeHtml(e.group) + '</span>');
    btn.on('click', function () {
      closeCommandPalette();
      if (e.run) e.run();
    });
    list.append(btn);
  });
}

function movePaletteFocus(delta) {
  var items = $('#palette-list .palette-item');
  if (!items.length) return;
  _paletteFocus = Math.min(items.length - 1, Math.max(0, _paletteFocus + delta));
  items.removeClass('focus').eq(_paletteFocus).addClass('focus');
  items[_paletteFocus].scrollIntoView({ block: 'nearest' });
}

function runFocusedPaletteCommand() {
  var focused = $('#palette-list .palette-item.focus');
  if (focused.length) focused.trigger('click');
}

function copyCurrentViewLink() {
  var token = getToken();
  var url = location.origin + '/web' + (token ? '?token=' + encodeURIComponent(token) : '') + currentHash();
  copyToClipboard(url, function () {
    toast(T().cmd_link_copied, 'success');
  });
}

var SHORTCUT_ROWS = [
  { keys: ['1', '2', '3', '4'], label: 'shortcut_switch_view' },
  { keys: ['/'], label: 'shortcut_focus_search' },
  { keys: ['r'], label: 'shortcut_refresh' },
  { keys: ['Ctrl', 'K'], label: 'shortcut_palette' },
  { keys: ['?'], label: 'shortcut_help' },
  { keys: ['Esc'], label: 'shortcut_close' }
];
var SHORTCUT_TABLE_ROWS = [
  { keys: ['↑', '↓'], label: 'shortcut_row_move' },
  { keys: ['Space'], label: 'shortcut_row_toggle' },
  { keys: ['Shift', '↑↓'], label: 'shortcut_row_extend' },
  { keys: ['Ctrl', 'A'], label: 'shortcut_row_all' },
  { keys: ['Enter'], label: 'shortcut_row_detail' }
];

function renderShortcutHelp() {
  var grid = $('#shortcut-grid').empty();
  grid.append('<div class="shortcut-sub">' + escapeHtml(T().shortcut_group_panel) + '</div>');
  SHORTCUT_ROWS.forEach(function (r) { grid.append(_shortcutRow(r)); });
  grid.append('<div class="shortcut-sub">' + escapeHtml(T().shortcut_group_table) + '</div>');
  SHORTCUT_TABLE_ROWS.forEach(function (r) { grid.append(_shortcutRow(r)); });
}

function _shortcutRow(r) {
  var keys = r.keys.map(function (k) { return '<kbd>' + escapeHtml(k) + '</kbd>'; }).join('');
  return $('<div class="shortcut-row"></div>')
    .append($('<span class="shortcut-keys"></span>').html(keys))
    .append($('<span></span>').text(T()[r.label]));
}

function showShortcutHelp() {
  onLangRender(renderShortcutHelp);
  renderShortcutHelp();
  $('#shortcut-modal').addClass('show');
}

function isTypingTarget(el) {
  if (!el) return false;
  var tag = (el.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return true;
  return !!(el.isContentEditable || (el.closest && el.closest('[contenteditable="true"]')));
}

function focusActiveSearch() {
  var $box = $('#tab-logs').hasClass('show') ? $('#log-search')
    : ($('#tab-pool').hasClass('show') ? $('#filter-ip') : $());
  if ($box.length && $box.is(':visible')) { $box.trigger('focus'); return true; }
  return false;
}

function refreshActiveView() {
  if ($('#tab-logs').hasClass('show')) { updateLogs(true); loadLogFiles(); return; }
  if ($('#tab-pool').hasClass('show')) { loadProxies(); loadPlugins(); updatePoolStatus(); return; }
  if ($('#tab-access').hasClass('show')) { loadUsers(); loadIpLists(); loadBypassWhitelist(); return; }
  if (serverFormDirty()) { toast(T().refresh_skipped_dirty, 'error'); return; }
  loadConfig({ serverOnly: true });
}

function _onShortcutKeydown(e) {
  if (isCommandPaletteOpen()) {
    if (e.key === 'Escape') { closeCommandPalette(); e.preventDefault(); return; }
    if (e.key === 'ArrowDown') { movePaletteFocus(1); e.preventDefault(); return; }
    if (e.key === 'ArrowUp') { movePaletteFocus(-1); e.preventDefault(); return; }
    if (e.key === 'Enter') { runFocusedPaletteCommand(); e.preventDefault(); }
    return;
  }

  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    openCommandPalette();
    return;
  }
  if (isTypingTarget(e.target)) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;

  if (e.key === 'Escape' && $('#shortcut-modal').hasClass('show')) {
    closeModal('shortcut-modal');
    return;
  }
  if (e.key === '?') { e.preventDefault(); showShortcutHelp(); return; }
  if (e.key === '/') { if (focusActiveSearch()) e.preventDefault(); return; }
  if (e.key === 'r') { refreshActiveView(); return; }

  var views = ['tab-config', 'tab-pool', 'tab-access', 'tab-logs'];
  var n = parseInt(e.key, 10);
  if (n >= 1 && n <= 4) { switchTab(views[n - 1]); }
}

$(document).on('keydown', _onShortcutKeydown);
$(document).on('input', '#palette-input', function () { renderPaletteList(this.value); });

$(document).on('click', '#cmd-palette', function (e) {
  if (e.target === this) closeCommandPalette();
});
$(document).on('click', '#shortcut-modal', function (e) {
  if (e.target === this) closeModal('shortcut-modal');
});
