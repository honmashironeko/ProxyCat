/**
 * 模块名称：面板外壳与「代理配置 / 访问控制 / 运行日志」页（app.js）
 * 功能描述：面板骨架与三个自持视图：侧栏导航与 hash 路由、主题切换、toast 通知中心、通用弹窗、剪贴板、
 *           全局请求反馈与 ajax 错误兜底、代理配置页的表单与名单、运行日志页的筛选与访问统计、出口气泡与广告位。
 * 职责边界：负责：面板外壳与配置 / 访问控制 / 运行日志三个页签。不负责：池页签的业务与代理列表
 *           （pool.js、proxies.js）、浮层组件与表格状态占位（tables.js）、快捷键面板（palette.js）。
 * 关键依赖：jQuery；i18n.js 的 T() / onLangRender / initLang；common.js 的 escapeHtml 等工具；
 *           tables.js 的表格占位、抽屉与键盘函数；pool.js 与 proxies.js 的池函数（tables.js 反向
 *           调用本文件的 _overlayOpen / _overlayClosed）；脚本加载顺序由 index.html 固定。
 * 已知限制：
 *           1. 脚本顺序为 jquery→i18n→common→tables→app→pool→proxies→palette；typeof 守卫只覆盖少量可选模块调用。
 *           2. 视图切换只有 switchTab 一个入口，首次进入无 hash 也要走一遍；hash 写入走 replaceState，applyHash 必须幂等。
 *           3. 本文件自持 /api/status 与日志轮询，池状态轮询归 pool.js；后台轮询失败只计数，判据须精确路径（indexOf 会吞掉主动请求的失败）。
 *           4. 按钮三态：flashSaved / flashFailed 必须在 btnLoad(btn, false) 之后调，否则被 .loading 守卫跳过。
 *           5. 动态拼 HTML 的用户可控文本必须经 escapeHtml 或 .text() 写入；用户名与密码不得拼进内联 onclick。
 *           6. 主题无存档时跟随系统且不写存档，仅手动切换才持久化；index.html 首帧内联脚本判据须与 initTheme 一致。
 *           7. 密码列打码时可见文本是圆点，collectUsers 必须读 .user-pass 的 data-pass，否则会把掩码存回。
 *           8. loadUsers 失败时若清空表格，随后的保存会用空表覆盖真实账号（等于关掉认证），须保留旧行。
 *           9. 弹窗回调只有 _modalCallback 一个槽位，OK / 取消须先取出并清空再调用；回调里再开弹窗（如 addUser 的两步
 *              输入）时，调用后清空会抹掉内层刚注册的回调，表现为确认后毫无反应。
 */

var _focusReturn = null;

function _focusablesIn(sel) {
  return $(sel).find('a[href], button:not(:disabled), input:not(:disabled), ' +
    'select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])')
    .filter(':visible');
}

function _overlayOpen(sel, focusTarget, lockScroll) {
  if (_focusReturn === null) _focusReturn = document.activeElement;
  if (lockScroll) {
    var sbw = window.innerWidth - document.documentElement.clientWidth;
    $('body').addClass('modal-open');
    if (sbw > 0) $('body').css('padding-right', sbw + 'px');
  }
  setTimeout(function () {
    var $t = (focusTarget && $(focusTarget).length) ? $(focusTarget) : _focusablesIn(sel).first();
    if ($t.length) $t.trigger('focus');
  }, 60);
}

function _overlayClosed() {
  if ($('.modal-overlay.show, #row-drawer.show').length) return;
  $('body').removeClass('modal-open').css('padding-right', '');
  if (_focusReturn && document.body.contains(_focusReturn)) $(_focusReturn).trigger('focus');
  _focusReturn = null;
}

$(document).on('keydown', function (e) {
  if (e.key !== 'Tab') return;
  var $box = $('.modal-overlay.show, #row-drawer.show').last();
  if (!$box.length) return;
  var $items = _focusablesIn('#' + $box.attr('id'));
  if (!$items.length) return;
  var first = $items[0], last = $items[$items.length - 1];
  if (e.shiftKey && (document.activeElement === first || !$box[0].contains(document.activeElement))) {
    e.preventDefault(); last.focus();
  } else if (!e.shiftKey && (document.activeElement === last || !$box[0].contains(document.activeElement))) {
    e.preventDefault(); first.focus();
  }
});

function openModal(id) {
  $('#' + id).addClass('show');
  _overlayOpen('#' + id, null, true);
}

function closeModal(id) {
  $('#' + id).removeClass('show');
  _overlayClosed();
}

function copyToClipboard(text, onDone, onFail) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onDone, function () {
      _copyFallback(text, onDone, onFail);
    });
    return;
  }
  _copyFallback(text, onDone, onFail);
}

function _copyFallback(text, onDone, onFail) {
  if (copyViaTextarea(text)) onDone();
  else if (onFail) onFail();
  else window.prompt(T().copy_manually, text);
}

var TOAST_LIMIT = 4;
var TOAST_TTL = { ok: 3200, info: 3800, warn: 5200, err: 7000 };
var _toastLive = [];
var logTimer = null;

function _toastType(t) {
  if (t === 'error') return 'err';
  if (t === 'warn') return 'warn';
  if (t === 'info') return 'info';
  return 'ok';
}

function _toastIcon(type) {
  if (type === 'err') return 'fa-times-circle';
  if (type === 'warn') return 'fa-exclamation-triangle';
  if (type === 'info') return 'fa-info-circle';
  return 'fa-check-circle';
}

function _toastDrop(entry) {
  var at = _toastLive.indexOf(entry);
  if (at >= 0) _toastLive.splice(at, 1);
  clearTimeout(entry.timer);
  entry.timer = null;
  entry.el.classList.add('leaving');
  setTimeout(function () {
    if (entry.el.parentNode) entry.el.parentNode.removeChild(entry.el);
  }, 220);
}

function _toastArm(entry) {
  clearTimeout(entry.timer);
  entry.timer = setTimeout(function () { _toastDrop(entry); }, entry.ttl);
}

function dismissToast() {
  _toastLive.slice().forEach(_toastDrop);
}

function _toastRestartBar(el, ttl) {
  var old = el.querySelector('.toast-bar');
  if (!old) return;
  var bar = old.cloneNode(false);
  bar.style.animationDuration = ttl + 'ms';
  old.parentNode.replaceChild(bar, old);
}

function toast(m, t) {
  m = m || (t === 'error' ? T().operation_failed_bare : T().operation_success);
  var type = _toastType(t);
  var stack = document.getElementById('toast-stack');
  if (!stack) return;

  for (var i = 0; i < _toastLive.length; i++) {
    var live = _toastLive[i];
    if (live.type !== type || live.text !== m) continue;
    live.count++;
    live.el.querySelector('.toast-count').textContent = '×' + live.count;
    _toastRestartBar(live.el, live.ttl);
    _toastArm(live);
    return;
  }

  var el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML =
    '<i class="fa ' + _toastIcon(type) + ' toast-ico"></i>' +
    '<span class="toast-msg"></span>' +
    '<span class="toast-count"></span>' +
    '<button type="button" class="toast-x"><i class="fa fa-times"></i></button>' +
    '<span class="toast-bar" style="animation-duration:' + TOAST_TTL[type] + 'ms"></span>';
  el.querySelector('.toast-msg').textContent = m;
  var close = el.querySelector('.toast-x');
  close.setAttribute('aria-label', T().drawer_close);

  var entry = { el: el, type: type, text: m, count: 1, ttl: TOAST_TTL[type], timer: null };
  close.addEventListener('click', function () { _toastDrop(entry); });
  el.addEventListener('mouseenter', function () {
    clearTimeout(entry.timer);
    entry.timer = null;
  });
  el.addEventListener('mouseleave', function () {
    if (!entry.timer) _toastArm(entry);
  });

  stack.appendChild(el);
  _toastLive.push(entry);
  while (_toastLive.length > TOAST_LIMIT) _toastDrop(_toastLive[0]);
  _toastArm(entry);
}

function btnLoad(btn, loading) {
  btn.prop('disabled', loading).toggleClass('loading', loading);
}

function markSavedHint(btn) {
  var bar = $(btn).closest('.cfg-actions');
  if (!bar.length) return;
  bar.find('.dirty-hint').hide();
  bar.find('.saved-hint')
    .removeAttr('data-idle-hint')
    .html('<i class="fa fa-check-circle"></i> ' +
          escapeHtml(T().saved_at_hint + T().sep_colon + new Date().toLocaleTimeString()))
    .show();
}

function idleSavedHintHtml() {
  return '<i class="fa fa-check-circle"></i> ' + escapeHtml(T().saved_at_hint);
}

function refreshIdleSavedHints() {
  $('.saved-hint[data-idle-hint]').html(idleSavedHintHtml());
}

onLangRender(refreshIdleSavedHints);

function setActionsIdle(selector, idle) {
  var bar = $(selector).closest('.cfg-actions');
  if (!bar.length) return;
  bar.find('button').attr('aria-disabled', idle ? 'true' : null);
}

var _stickySyncRaf = null;

function syncStickyBars() {
  $('.cfg-actions.sticky').each(function () {
    var bar = $(this);
    if (!bar.is(':visible')) { bar.removeClass('stuck'); return; }
    var offset = parseFloat(window.getComputedStyle(this).bottom) || 0;
    bar.toggleClass('stuck',
      this.getBoundingClientRect().bottom >= window.innerHeight - offset - 1);
  });
}

function scheduleStickySync() {
  if (_stickySyncRaf) return;
  _stickySyncRaf = window.requestAnimationFrame(function () {
    _stickySyncRaf = null;
    syncStickyBars();
  });
}

$(window).on('scroll resize', scheduleStickySync);

function flashSaved(btn) {
  var el = $(btn);
  if (!el.length || el.hasClass('loading')) return;
  el.addClass('done');
  setTimeout(function () { el.removeClass('done'); }, 1200);
}

function flashResult(btn, ok) {
  var el = $(btn);
  if (!el.length) return;
  btnLoad(el, false);
  if (ok) flashSaved(el); else flashFailed(el);
}

function flashFailed(btn) {
  var el = $(btn);
  if (!el.length || el.hasClass('loading')) return;
  el.addClass('failed');
  setTimeout(function () { el.removeClass('failed'); }, 1600);
}


var _modalCallback = null;

function showModal(opts) {
  var o = opts || {};
  $('#modal-icon').attr('class', 'modal-icon ' + (o.icon || 'info'));
  $('#modal-icon i').attr('class', 'fa ' + (o.iconClass || 'fa-question-circle'));
  $('#modal-title').text(o.title || '');
  $('#modal-body').text(o.body || '');
  var input = $('#modal-input');
  if (o.input) {
    input.show().val(o.value || '').attr('placeholder', o.placeholder || '');
    setTimeout(function () { input.focus(); }, 150);
  } else {
    input.hide().val('');
  }
  $('#modal-cancel').toggle(!!o.showCancel);
  $('#modal-ok').find('span').text(o.okText || T().modal_confirm);
  $('#modal-cancel').find('span').text(o.cancelText || T().modal_cancel);
  $('#modal-ok').toggleClass('bad', !!o.danger).toggleClass('pri', !o.danger);
  $('#modal-overlay').addClass('show');
  _modalCallback = o.callback || null;
  _overlayOpen('#modal-overlay', o.input ? input : $('#modal-ok'), true);

  $('#modal-ok').off('click').on('click', function () {
    var val = o.input ? input.val().trim() : true;
    closeModal('modal-overlay');
    var cb = _modalCallback;
    _modalCallback = null;
    if (cb) cb(val);
  });
  $('#modal-cancel').off('click').on('click', function () {
    closeModal('modal-overlay');
    var cb = _modalCallback;
    _modalCallback = null;
    if (cb) cb(null);
  });

  input.off('keydown').on('keydown', function (e) {
    if (e.key === 'Enter') $('#modal-ok').click();
    if (e.key === 'Escape') $('#modal-cancel').click();
  });
  $(document).off('keydown.modal').on('keydown.modal', function (e) {
    if (e.key === 'Escape' && !o.input) $('#modal-cancel').click();
  });
}

function showConfirm(title, body, cb, opts) {
  showModal({
    icon: 'warning', iconClass: 'fa-exclamation-triangle',
    title: title, body: body, showCancel: true,
    danger: !!(opts && opts.danger),
    okText: T().modal_confirm, cancelText: T().modal_cancel,
    callback: function (ok) { if (cb) cb(ok === true); }
  });
}

function showPrompt(title, body, value, placeholder, cb) {
  showModal({
    icon: 'info', iconClass: 'fa-pencil',
    title: title, body: body, input: true,
    value: value || '', placeholder: placeholder || '',
    showCancel: true,
    okText: T().modal_confirm, cancelText: T().modal_cancel,
    callback: function (val) { if (cb) cb(val); }
  });
}


function nextTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
}

function cycleTheme() {
  setTheme(nextTheme());
}

function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  renderThemeLabel();
  safeSetItem('proxycat-theme', t);
}

function renderThemeLabel() {
  onLangRender(renderThemeLabel);
  var isDark = nextTheme() === 'dark';
  var icon = isDark ? 'fa-sun-o' : 'fa-moon-o';
  $('#theme-btn i').attr('class', 'fa ' + icon);
  $('#theme-label').text(isDark ? T().theme_toggle_light : T().theme_toggle_dark);
}

function initTheme() {
  var saved = safeGetItem('proxycat-theme');
  if (saved) { setTheme(saved); return; }
  var prefersDark = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
  renderThemeLabel();
}


function _startLogRefresh() {
  if (isPolling('log')) return;
  updateLogs();
  startPolling('log', updateLogs, 2000);
  loadLogFiles();
  _startDomainRefresh();
}

function _stopLogRefresh() {
  stopPolling('log');
  _stopDomainRefresh();
}
var TAB_STORAGE_KEY = 'proxycat-active-tab';
var CONFIG_GROUP_STORAGE_KEY = 'proxycat-config-group';

var VIEW_SLUGS = {
  'tab-config': 'config',
  'tab-pool': 'pool',
  'tab-access': 'access',
  'tab-logs': 'logs'
};
var POOL_VIEW_SLUGS = {
  'pool-view-manage': 'manage',
  'pool-view-settings': 'settings',
  'pool-view-db': 'db'
};
var CONFIG_GROUPS = ['source', 'listen', 'exits', 'check', 'perf', 'logs', 'advanced'];
var VIEW_TITLE_KEYS = {
  'tab-config': 'config_tab',
  'tab-pool': 'pool_tab',
  'tab-access': 'access_control_tab',
  'tab-logs': 'logs_tab'
};
var POOL_VIEW_SUB_KEYS = {
  'pool-view-manage': 'view_sub_pool_manage',
  'pool-view-settings': 'view_sub_pool_settings',
  'pool-view-db': 'view_sub_pool_db'
};

function currentHash() {
  var tabId = $('.tab-body.show').attr('id') || 'tab-config';
  if (tabId === 'tab-config') {
    return '#/config/' + (safeGetItem(CONFIG_GROUP_STORAGE_KEY) || 'source');
  }
  if (tabId === 'tab-pool') {
    var view = safeGetItem(POOL_VIEW_STORAGE_KEY);
    return '#/pool/' + (POOL_VIEW_SLUGS[view] || 'manage');
  }
  return '#/' + (VIEW_SLUGS[tabId] || 'config');
}

function writeHash() {
  var next = currentHash();
  if (location.hash === next) return;
  history.replaceState(null, '', location.pathname + location.search + next);
}

function parseHash() {
  var m = /^#\/([a-z]+)(?:\/([a-z]+))?/.exec(location.hash || '');
  if (!m) return null;
  var tabId = null;
  for (var k in VIEW_SLUGS) { if (VIEW_SLUGS[k] === m[1]) tabId = k; }
  return tabId ? { tab: tabId, section: m[2] || null } : null;
}

function applyHash() {
  var r = parseHash();
  if (!r) return false;
  if (r.tab === 'tab-config') {
    switchTab('tab-config', { group: CONFIG_GROUPS.indexOf(r.section) >= 0 ? r.section : null });
  } else if (r.tab === 'tab-pool') {
    var view = null;
    for (var k in POOL_VIEW_SLUGS) { if (POOL_VIEW_SLUGS[k] === r.section) view = k; }
    switchTab('tab-pool', { view: view });
  } else {
    switchTab(r.tab);
  }
  return true;
}

function toggleSidebar(open) {
  var isOpen = open === undefined ? !$('body').hasClass('sb-open') : !!open;
  $('body').toggleClass('sb-open', isOpen);
  $('#sidebar').toggleClass('open', isOpen);
}

function syncSidebarActive(tabId, view) {
  $('#sb-nav .sb-item').removeClass('cur');
  $('#sb-nav .sb-item[data-tab="' + tabId + '"]').addClass('cur');
  if (tabId === 'tab-pool' && view) {
    $('#sb-nav .sb-item[data-view="' + view + '"]').addClass('cur');
  }
}

function renderViewHead() {
  onLangRender(renderViewHead);
  var tabId = $('.tab-body.show').attr('id') || 'tab-config';
  var titleKey = VIEW_TITLE_KEYS[tabId] || 'title';
  var subKey = 'view_sub_' + (VIEW_SLUGS[tabId] || 'config');
  if (tabId === 'tab-pool') {
    var view = safeGetItem(POOL_VIEW_STORAGE_KEY);
    if (POOL_VIEW_SUB_KEYS[view]) subKey = POOL_VIEW_SUB_KEYS[view];
  }
  $('#view-title').attr('data-i18n', titleKey).text(T()[titleKey]);
  $('#view-sub').text(T()[subKey]);
}

function switchTab(tabId, opts) {
  var o = opts || {};
  if (!$('#' + tabId).length) return;

  $('.tab-body').removeClass('show');
  $('#' + tabId).addClass('show');
  $('body').attr('data-tab', tabId);
  safeSetItem(TAB_STORAGE_KEY, tabId);

  if (tabId === 'tab-config') {
    showConfigGroup(o.group || safeGetItem(CONFIG_GROUP_STORAGE_KEY) || 'source');
  }

  var view = null;
  if (tabId === 'tab-pool') {
    view = o.view || safeGetItem(POOL_VIEW_STORAGE_KEY) || 'pool-view-manage';
    switchPoolView(view);
  }

  syncSidebarActive(tabId, view);
  renderViewHead();

  if (tabId === 'tab-logs') _startLogRefresh(); else _stopLogRefresh();
  if (tabId === 'tab-pool') {
    startPoolPolling();
    restoreFiltersFromStorage();
    if (poolReady()) {
      loadPlugins();
      loadSources();
      loadProxies();
    }
  } else {
    stopPoolPolling();
  }

  writeHash();
  toggleSidebar(false);
  window.scrollTo(0, 0);
  scheduleStickySync();
}

$(document).on('click', '.sb-item[data-tab]', function () {
  switchTab($(this).data('tab'));
});

$(document).on('click', '.sb-item[data-view]', function () {
  var view = $(this).data('view');
  if ($('#tab-pool').hasClass('show')) {
    switchPoolView(view);
    toggleSidebar(false);
  } else {
    switchTab('tab-pool', { view: view });
  }
});

function initSidebar() {
  $(window).on('resize', function () {
    if (window.innerWidth > 1024) toggleSidebar(false);
  });
  $(window).on('hashchange', function () { applyHash(); });
}

function restoreActiveView() {
  if (applyHash()) return;
  var saved = safeGetItem(TAB_STORAGE_KEY);
  switchTab(saved && $('#' + saved).length ? saved : 'tab-config');
}


function controlService(a) {
  if (a !== 'start') {
    showConfirm(T().svc_confirm_title,
      a === 'stop' ? T().svc_stop_confirm_body : T().svc_restart_confirm_body,
      function (ok) { if (ok) _doControlService(a); });
    return;
  }
  _doControlService(a);
}

function _doControlService(a) {
  var btn = $('#svc-' + a), ok = false;
  btnLoad(btn, true);
  $.ajax({
    url: appendToken('/api/service'), method: 'POST', contentType: 'application/json',
    data: JSON.stringify({ action: a }),
    success: function (r) {
      if (r.status === 'success') { ok = true; updateStatusAndGauge(); toast(r.message, 'success'); }
      else toast(r.message, 'error');
    },
    error: function (x) { toast(fillTemplate(T().operation_failed, jqErrorText(x, T().network_error)), 'error'); },
    complete: function () { flashResult(btn, ok); }
  });
}

function svcBtns(s) {
  var r = s === 'running';
  $('#svc-start').prop('disabled', r);
  $('#svc-stop, #svc-restart').prop('disabled', !r);
}

function toggleExitPop() {
  $('#exit-pop').toggleClass('show');
  $('#tag-exits').toggleClass('on', $('#exit-pop').hasClass('show'));
}

function closeExitPop() {
  $('#exit-pop').removeClass('show');
  $('#tag-exits').removeClass('on');
}

$(document).on('mousedown', function (e) {
  if (!$('#exit-pop').hasClass('show')) return;
  if ($(e.target).closest('#exit-pop, #tag-exits').length) return;
  closeExitPop();
});

function renderSidebarStatus(serviceRunning, poolRunning) {
  $('#sb-svc-dot').attr('class', 'dot ' + (serviceRunning ? 'on' : 'off'));
  $('#sb-svc-text').text(T().service_status[serviceRunning ? 'running' : 'stopped'] || (serviceRunning ? 'running' : 'stopped'));
  $('#sb-pool-dot').attr('class', 'dot ' + (poolRunning ? 'on' : 'off'));
  $('#sb-pool-text').text(T().service_status[poolRunning ? 'running' : 'stopped'] || (poolRunning ? 'running' : 'stopped'));
}


$(document).on('click', '[data-copy]:not([data-act])', function () {
  var text = $(this).attr('data-copy') || '';
  if (!text) return;
  copyToClipboard(text, function () {
    toast(T().addr_copied + T().sep_colon + text, 'success');
  }, function () {
    toast(T().copy_failed_manual, 'error');
  });
});


function copyAddr(t) {
  var e = t === 'http' ? $('#addr-http') : $('#addr-socks5');
  var x = e.find('span').text();
  var done = function () {
    e.addClass('copied');
    toast(T().addr_copied + T().sep_colon + x, 'success');
    setTimeout(function () { e.removeClass('copied'); }, 1500);
  };
  copyToClipboard(x, done, function () {
    toast(T().copy_failed_manual, 'error');
  });
}

function collectUsers() {
  var users = {};
  $('#user-table tbody tr').each(function () {
    var tds = $(this).find('td');
    var $pass = tds.eq(1).find('.user-pass');
    users[tds.eq(0).text()] = $pass.length ? ($pass.attr('data-pass') || '') : tds.eq(1).text();
  });
  return users;
}

function pickAuth() {
  var users = collectUsers();
  var names = Object.keys(users).filter(function (n) { return n; });
  var name = names.length ? names[0] : '';
  return (name && users[name]) ? name + ':' + users[name] + '@' : '';
}

function updAddr(c) {
  var port = c.port || '1080', a = pickAuth();
  $('#http-addr').text('http://' + a + '127.0.0.1:' + port);
  $('#socks5-addr').text('socks5://' + a + '127.0.0.1:' + port);
}



function startGlobalPolling() {
  if (isPolling('status')) return;
  startPolling('status', updateStatusAndGauge, 1000);
}

function pauseGlobalPolling() {
  stopPolling('status');
  if (typeof _stopLogRefresh === 'function') _stopLogRefresh();
  if (typeof stopPoolPolling === 'function') stopPoolPolling();
}

function exitRemainingText(e, cm) {
  var parts = [];
  if (cm === 'time' && e.expires_in !== null && e.expires_in !== undefined) {
    parts.push(escapeHtml(Math.ceil(e.expires_in)) + T().seconds);
  }
  if ((cm === 'time' || cm === 'request_count')
      && e.requests_left !== null && e.requests_left !== undefined) {
    parts.push(escapeHtml(e.requests_left) + T().times);
  }
  return parts.length ? parts.join(' · ') : '--';
}

function _sinceText(iso) {
  if (!iso) return '';
  var at = Date.parse(iso);
  if (isNaN(at)) return '';
  return fillTemplate(T().source_error_ago, fmtDuration((Date.now() - at) / 1000));
}

function renderExitRows(exits, cm) {
  var $list = $('#exit-list'), $rows = $('#exit-rows');
  if (!exits || !exits.length) { $rows.empty(); $list.hide(); return; }
  $rows.html(exits.map(function (e) {
    var load = e.capacity > 0
      ? escapeHtml(e.active) + '/' + escapeHtml(e.capacity)
      : fillTemplate(T().exit_load_unlimited, e.active);
    var flags = '';
    if (e.suspect) {
      flags += '<i class="fa fa-exclamation-triangle exit-flag" title="' +
               escapeHtml(T().exit_suspect) + '"></i>';
    }
    if (e.failures > 0) {
      flags += '<span class="exit-fails" title="' +
               escapeHtml(fillTemplate(T().exit_failures, e.failures)) + '">' +
               escapeHtml(e.failures) + '</span>';
    }
    var tip = e.requests_served
      ? fillTemplate(T().exit_served, e.requests_served)
      : '';
    return '<div class="exit-row"' + (tip ? ' title="' + escapeHtml(tip) + '"' : '') + '>' +
      '<span class="exit-url">' + escapeHtml(e.url) + '</span>' + flags +
      '<span class="exit-load">' + load + '</span>' +
      '<span class="exit-left">' + exitRemainingText(e, cm) + '</span>' +
      '</div>';
  }).join(''));
  $list.show();
}

function updateStatusAndGauge() {
  onLangRender(updateStatusAndGauge);
  $.get(appendToken('/api/status'), function (d) {
    var s = d.service_status || 'stopped', r = s === 'running';
    $('#svc-dot').attr('class', 'dot ' + (r ? 'on' : 'off'));
    $('#svc-text').text(T().service_status[s] || s);
    renderSidebarStatus(r, !!d.pool_running);
    svcBtns(s);
    var m = d.proxy_source_mode || 'local', modes = {
      local: T().proxy_source_mode_local, api: T().proxy_source_mode_api, pool: T().proxy_source_mode_pool
    };
    $('#tag-source').text((modes[m] || m));
    if (m === 'local') $('#tag-mode').show().text(T().proxy_mode[d.mode] || d.mode || '--');
    else $('#tag-mode').hide();
    var iv = parseInt(d.interval) || 0;
    var cm = d.switch_countdown_mode || 'time';
    var exitList = d.active_proxies || [];
    var exitText = fillTemplate(
      d.elastic_active ? T().upstream_exits_expanding : T().upstream_exits, exitList.length);
    if (exitList.length > 1) $('#tag-exits').show().text(exitText);
    else $('#tag-exits').hide();
    renderExitRows(exitList, cm);
    if (!exitList.length) closeExitPop();
    if (cm === 'per_request') { $('#tag-interval').text(T().pool_per_request_swap); $('#tip-zero').show(); }
    else if (cm === 'request_count') { $('#tag-interval').text((parseInt(d.request_interval) || 0) + ' ' + T().times); $('#tip-zero').hide(); }
    else { $('#tag-interval').text(iv + T().seconds); $('#tip-zero').hide(); }
    if (d.source_error && d.source_error.message) {
      $('#tip-source-error-text').text(
        fillTemplate(T().source_error_hint, d.source_error.message) +
        _sinceText(d.source_error.at));
      $('#tip-source-error').show();
    } else {
      $('#tip-source-error').hide();
    }
    updAddr(d);

    if (cm === 'none') { $('#gauge-bar').css('width', '100%'); $('#next-switch').text('--'); return; }
    if (cm === 'per_request') { $('#gauge-bar').css('width', '100%'); $('#next-switch').text(T().pool_per_request_swap); return; }
    if (!exitList.length) {
      $('#gauge-bar').css('width', '0%');
      $('#next-switch').text(T().pool_waiting_exits);
      return;
    }
    var tl = Math.max(0, d.time_left || 0);
    if (tl <= 0) {
      $('#gauge-bar').css('width', '100%');
      $('#next-switch').text(T().pool_rotate_waiting);
      return;
    }
    if (cm === 'request_count') {
      var ri = parseInt(d.request_interval) || 0;
      if (ri <= 0) { $('#gauge-bar').css('width', '100%'); $('#next-switch').text('--'); return; }
      $('#next-switch').text(Math.ceil(tl) + ' ' + T().times);
      $('#gauge-bar').css('width', Math.min(100, ((ri - tl) / ri) * 100) + '%');
      return;
    }
    $('#next-switch').text(Math.ceil(tl) + ' ' + T().seconds);
    $('#gauge-bar').css('width', (iv > 0 ? Math.min(100, ((iv - tl) / iv) * 100) : 0) + '%');
  });
}


function setSourceMode(mode) {
  $('#source-mode-group .source-mode-btn').removeClass('active');
  $('#source-mode-group .source-mode-btn[data-mode="' + mode + '"]').addClass('active');
  $('#proxy-source-mode').val(mode);
  onSourceChange();
  updateServerDirtyState();
}

function loadConfig(opts) {
  var o = opts || {};
  $.get(appendToken('/api/config'), function (d) {
    if (!o.poolOnly) applyServerConfigToForm(d.server || {});
    if (!o.serverOnly && typeof applyPoolConfigToForm === 'function') {
      applyPoolConfigToForm(d.pool || {}, o.force);
    }
  });
}

function discardServerChanges() {
  if (!serverFormDirty()) { toast(T().no_changes, 'error'); return; }
  loadConfig({ serverOnly: true });
}

var SERVER_FORM_DEFAULTS = {
  proxy_source_mode: 'local', proxy_file: 'ip.txt', mode: 'cycle',
  api_proxy_url: '', proxy_username: '', proxy_password: '', pool_remote_url: '',
  client_idle_timeout: '300',
  max_pool_size: '500',
  client_max_connections: '1000',
  port: '1080', interval: '300', request_interval: '0', exit_count: '5',
  test_url: 'https://www.baidu.com', ip_auth_priority: 'whitelist', log_level: 'INFO',
  check_proxies_on_startup: 'True', check_proxies_on_use: 'True',
  log_access_enabled: 'true', access_records_enabled: 'true', domain_stats_enabled: 'true',
  access_records_real_ip_probe: 'false',
  access_records_retention_days: '7', access_records_max_rows: '200000',
  domain_stats_retention_days: '30',
  exit_wait_timeout: '15', max_concurrent_per_proxy: '0',
  auto_expand_enabled: 'true',
  client_idle_timeout: '300', client_max_keepalive: '8',
  client_max_connections: '1000', client_keepalive_expiry: '30',
  max_concurrent_requests: '1000', max_pool_size: '500', buffer_size: '8192',
  check_concurrency: '50', tunnel_idle_timeout: '10', web_port: '5001',
  proxy_check_ttl: '60', check_cooldown: '10', proxy_failure_cooldown: '3',
  switch_cooldown: '2', access_records_flush_interval: '5',
  access_records_buffer_size: '20000', domain_stats_flush_interval: '15',
  log_max_bytes: '10485760', log_backup_count: '3',
  whitelist_file: 'whitelist.txt', blacklist_file: 'blacklist.txt',
  bypass_whitelist_file: 'bypass_whitelist.txt', display_level: '1'
};

var SERVER_CHECKBOX_FIELDS = {
  check_proxies_on_startup: true, check_proxies_on_use: true,
  log_access_enabled: true, access_records_enabled: true,
  access_records_real_ip_probe: true,
  domain_stats_enabled: true, auto_expand_enabled: true
};

var _serverFormBaseline = null;

function _serverField(key) { return $('[name="' + key + '"]'); }

function _isServerCheckbox(key) { return SERVER_CHECKBOX_FIELDS[key] === true; }

function _normalizeDisplayLevel(value) {
  var n = parseInt(value, 10);
  if (isNaN(n) || n < 0) return SERVER_FORM_DEFAULTS.display_level;
  return n >= 2 ? '2' : String(n);
}

function _writeServerField(key, rawValue) {
  var missing = (rawValue === undefined || rawValue === null || rawValue === '');
  var value = missing ? SERVER_FORM_DEFAULTS[key] : rawValue;
  if (_isServerCheckbox(key)) {
    _serverField(key).prop('checked', String(value).toLowerCase() === 'true');
    return;
  }
  if (key === 'display_level') value = _normalizeDisplayLevel(value);
  _serverField(key).val(key === 'log_level' ? String(value).toUpperCase() : value);
}

function _readServerField(key) {
  if (_isServerCheckbox(key)) return _serverField(key).prop('checked').toString();
  return _serverField(key).val();
}

function applyServerConfigToForm(c) {
  var m = c.proxy_source_mode || 'local';
  $('#source-mode-group .source-mode-btn').removeClass('active');
  $('#source-mode-group .source-mode-btn[data-mode="' + m + '"]').addClass('active');
  syncModeField(m);
  for (var key in SERVER_FORM_DEFAULTS) _writeServerField(key, c[key]);
  if ($('#proxy-auth').length) {
    $('#proxy-auth').val(_joinProxyAuth(c.proxy_username, c.proxy_password));
  }
  syncProxyAuthHint();
  onSourceChange(); onIntervalChange(); updAddr(c);
  markServerFormClean();
  updateLogLevelWarning();
}

function getSourceMode() { return _serverField('proxy_source_mode').val() || 'local'; }

function _splitProxyAuth(text) {
  var raw = String(text === null || text === undefined ? '' : text);
  var at = raw.indexOf(':');
  if (at === -1) return { username: raw, password: '' };
  return { username: raw.slice(0, at), password: raw.slice(at + 1) };
}

function _joinProxyAuth(username, password) {
  var user = String(username || '');
  return user ? (user + ':' + String(password || '')) : '';
}

function syncProxyAuthHint() {
  var text = String($('#proxy-auth').val() || '');
  $('#proxy-auth-warn').toggle(text !== '' && text.indexOf(':') === -1);
}

function collectServerConfig() {
  var values = {};
  for (var key in SERVER_FORM_DEFAULTS) {
    if (!_serverField(key).length) continue;
    values[key] = _readServerField(key);
  }
  if ($('#proxy-auth').length) {
    var auth = _splitProxyAuth($('#proxy-auth').val());
    values.proxy_username = auth.username;
    values.proxy_password = auth.password;
  }
  var idle = parseInt(values.client_keepalive_expiry, 10);
  values.client_idle_timeout = String(Math.max(isNaN(idle) ? 0 : idle, 30));
  return values;
}

function serverConfigChanges() {
  var current = collectServerConfig();
  var changes = {};
  for (var key in current) {
    if (String(current[key]) !== String(_serverFormBaseline ? _serverFormBaseline[key] : undefined)) {
      changes[key] = current[key];
    }
  }
  return changes;
}

function markServerFormClean() {
  _serverFormBaseline = collectServerConfig();
  updateServerDirtyState();
}

function syncServerBaseline(keys) {
  if (!_serverFormBaseline) return;
  var current = collectServerConfig();
  keys.forEach(function (key) {
    _serverFormBaseline[key] = (key in current) ? current[key] : _readServerField(key);
  });
  updateServerDirtyState();
}

function serverFormDirty() {
  return Object.keys(serverConfigChanges()).length > 0;
}

function updateServerDirtyState() {
  var ready = _serverFormBaseline !== null;
  var dirty = ready && serverFormDirty();
  $('#server-dirty-hint').toggle(dirty);
  $('#btn-save-config').toggleClass('dirty', dirty);

  var saved = $('#server-saved-hint');
  if (dirty) {
    saved.hide();
  } else if (ready) {
    if (!saved.children().length) saved.html(idleSavedHintHtml()).attr('data-idle-hint', '1');
    saved.show();
  }
  setActionsIdle('#btn-save-config', ready && !dirty);

  if (!ready) return;
  $('#config-nav .settings-nav-item').each(function () {
    var group = $(this).data('group');
    var groupDirty = $('#tab-config .settings-group[data-group="' + group + '"]')
      .find('[name]').toArray().some(function (el) {
        if (!(el.name in SERVER_FORM_DEFAULTS)) return false;
        return String(_readServerField(el.name)) !== String(_serverFormBaseline[el.name]);
      });
    $(this).find('.settings-dirty-dot').toggle(groupDirty);
  });
}

$(document).on('input change', '#tab-config [name]', updateServerDirtyState);

function updateLogLevelWarning() {
  var level = String(_serverField('log_level').val() || 'INFO').toUpperCase();
  var suppressesAccessLog = level !== 'DEBUG' && level !== 'INFO';
  var recordsEnabled = _serverField('log_access_enabled').prop('checked');
  $('#log-level-warning').toggle(suppressesAccessLog && recordsEnabled);
}

$(document).on('change', 'select[name="log_level"], input[name="log_access_enabled"]',
  updateLogLevelWarning);

function showSettingsGroup(navSelector, group) {
  var layout = $(navSelector).closest('.settings-layout');
  layout.find('.settings-nav-item').removeClass('cur');
  layout.find('.settings-nav-item[data-group="' + group + '"]').addClass('cur');
  layout.find('.settings-group').removeClass('show');
  layout.find('.settings-group[data-group="' + group + '"]').addClass('show');
  scheduleStickySync();
}

function showConfigGroup(group) {
  showSettingsGroup('#config-nav', group);
  safeSetItem(CONFIG_GROUP_STORAGE_KEY, group);
  writeHash();
}

$(document).on('click', '#config-nav .settings-nav-item', function () {
  showConfigGroup($(this).data('group'));
});

$(window).on('beforeunload', function (e) {
  if (serverFormDirty()) {
    e.preventDefault();
    e.originalEvent.returnValue = '';
    return '';
  }
});

function submitConfig(sections, btn, onSaved) {
  if (btn) btnLoad(btn, true);
  var ok = false;
  $.ajax({
    url: appendToken('/api/config'), method: 'POST', contentType: 'application/json',
    data: JSON.stringify(sections),
    success: function (r) {
      if (r.status !== 'success') { toast(r.message, 'error'); return; }
      ok = true;
      toast(T().config_save_success, 'success');
      if (btn) { btnLoad(btn, false); flashSaved(btn); markSavedHint(btn); }
      if (typeof onSaved === 'function') onSaved();
      if (r.applied && r.applied.proxy === false) {
        toast(T().config_apply_failed, 'error');
      }
      if (r.applied && r.applied.pool === false) {
        toast(T().pool_config_apply_failed, 'error');
      }
      if (r.port_changed) {
        if (r.service_status === 'running') {
          $.ajax({
            url: appendToken('/api/service'), method: 'POST', contentType: 'application/json',
            data: JSON.stringify({ action: 'restart' }),
            success: function (rr) {
              if (rr && rr.status === 'success') toast(rr.message, 'success');
              else toast((rr && rr.message) || T().config_save_failed, 'error');
              updateStatusAndGauge();
            },
            error: function (x) {
              toast(fillTemplate(T().operation_failed, jqErrorText(x)), 'error');
              updateStatusAndGauge();
            }
          });
        } else {
          toast(T().port_saved_stopped, 'success');
        }
      }
      loadConfig({ poolOnly: !sections.server && !!sections.pool });
    },
    error: function (x) { toastServerConfigError(x); },
    complete: function () {
      if (btn && !ok) flashResult(btn, false);
    }
  });
}

function _configField(key) {
  var named = _serverField(key);
  if (named.length) return named;
  var found = $();
  $('#pool-form [data-pool-key]').each(function () {
    if ($(this).data('pool-key') === key) { found = $(this); return false; }
  });
  return found;
}

function _configFieldLabel(field) {
  return field.closest('.fg')
              .find('.fg-label, .fg-check label').first().text();
}

function _revealServerField(key) {
  var group = _configField(key).closest('.settings-group');
  if (!group.length) return;
  var nav = group.closest('.settings-layout').find('.settings-nav');
  if (nav.length) showSettingsGroup('#' + nav.attr('id'), group.data('group'));
}

function toastServerConfigError(x) {
  var details = null;
  try { details = JSON.parse(x.responseText).details; } catch (e) { details = null; }
  var reason = details && details.reason;
  if (details && details.key && reason) {
    var label = _configFieldLabel(_configField(details.key));
    if (label) {
      _revealServerField(details.key);
      toast(fillTemplate(T().config_field_invalid, label + T().sep_colon + reason), 'error');
      return;
    }
  }
  toast(T().config_save_failed + T().sep_colon + jqErrorText(x), 'error');
}

function saveAllConfig() {
  var changes = serverConfigChanges();
  if (!Object.keys(changes).length) {
    toast(T().no_changes, 'info');
    return;
  }
  if (changes.port === undefined) {
    submitConfig({ server: changes }, $('#btn-save-config'));
    return;
  }
  showConfirm(T().config_port_restart_title, T().config_port_restart_body, function (ok) {
    if (ok) submitConfig({ server: changes }, $('#btn-save-config'));
  });
}

var MODE_FIELD_BY_SOURCE = {
  local: {
    label: 'run_mode_label', hint: 'run_mode_hint', doc: 'run_mode_doc',
    options: [['cycle', 'cycle_mode'], ['loadbalance', 'loadbalance_mode']]
  },
  api: {
    label: 'rotation_mode_label', hint: 'rotation_mode_hint', doc: 'rotation_mode_doc',
    options: [['request', 'mode_request'], ['continuous', 'mode_continuous']]
  }
};
MODE_FIELD_BY_SOURCE.pool = MODE_FIELD_BY_SOURCE.api;

function syncModeField(sourceMode) {
  var spec = MODE_FIELD_BY_SOURCE[sourceMode] || MODE_FIELD_BY_SOURCE.api;
  var $sel = $('#mode-select');
  if (!$sel.length) return;

  var allowed = spec.options.map(function (o) { return o[0]; });
  var current = $sel.val();
  if (allowed.indexOf(current) === -1) current = allowed[0];

  $sel.html(spec.options.map(function (o) {
    return '<option value="' + o[0] + '" data-i18n="' + o[1] + '">' +
           escapeHtml(T()[o[1]] || o[1]) + '</option>';
  }).join(''));
  $sel.val(current);

  $('#mode-label').attr('data-i18n', spec.label).text(T()[spec.label] || spec.label);
  $('#mode-hint').attr('data-i18n', spec.hint).text(T()[spec.hint] || spec.hint);
  $('#mode-tip').attr('data-i18n-title', spec.doc)
               .attr('title', T()[spec.doc] || '');
}

function _visibilityClauseHolds(clause) {
  clause = clause.trim();
  if (!clause) return true;
  var negate = clause.indexOf('!=') !== -1;
  var splitAt = negate ? clause.indexOf('!=') : clause.indexOf('=');
  var key = clause.slice(0, splitAt).trim();
  var wanted = clause.slice(splitAt + (negate ? 2 : 1)).split('|')
                     .map(function (v) { return v.trim(); });
  var field = _serverField(key);
  if (!field.length) field = $('#pool-form [data-pool-key="' + key + '"]');
  if (!field.length) return true;
  var actual = field.prop('type') === 'checkbox'
    ? field.prop('checked').toString()
    : String(field.val() === null || field.val() === undefined ? '' : field.val()).trim();
  var hit = wanted.indexOf(actual) !== -1;
  return negate ? !hit : hit;
}

function syncFieldVisibility() {
  $('[data-visible-when]').each(function () {
    var clauses = String($(this).attr('data-visible-when') || '').split(';');
    var show = true;
    for (var i = 0; i < clauses.length; i++) {
      if (!_visibilityClauseHolds(clauses[i])) { show = false; break; }
    }
    $(this).toggle(show);
  });
}

$(document).on('change', '#tab-config input, #tab-config select, #pool-form input, #pool-form select',
  function () {
    syncFieldVisibility();
    syncProxyAuthHint();
  });

function onSourceChange() {
  var m = getSourceMode();
  syncModeField(m);
  syncFieldVisibility();
  if (m === 'pool') updatePoolStatus();
  if (m === 'api') loadApiCredentials();
}

function onIntervalChange() {
  var seconds = parseInt($('input[name="interval"]').val()) || 0;
  var requests = parseInt($('input[name="request_interval"]').val()) || 0;
  $('#tip-zero').toggle(seconds === 0 && requests === 0);
}


function switchProxy() {
  var btn = $('#switch-btn'); if (btn.prop('disabled')) return;
  btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> <span>' + T().switching + '</span>');
  $.get(appendToken('/api/switch_proxy'), function (d) {
    if (d.status === 'success') { toast(d.message, 'success'); updateStatusAndGauge(); btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> <span>' + T().manual_switch_btn + '</span>'); }
    else if (d.cooldown) {
      toast(d.message, 'error');
      var rem = d.cooldown_remaining || 2;
      btn.prop('disabled', true).html('<i class="fa fa-clock-o"></i> <span>' + Math.ceil(rem) + 's</span>');
      var iv = setInterval(function () {
        rem -= 0.1;
        if (rem <= 0) { clearInterval(iv); btn.prop('disabled', false); btn.html('<i class="fa fa-refresh"></i> <span>' + T().manual_switch_btn + '</span>'); }
        else btn.html('<i class="fa fa-clock-o"></i> <span>' + Math.ceil(rem) + 's</span>');
      }, 100);
    } else if (d.switching) {
      toast(d.message, 'error');
      btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> <span>' + T().manual_switch_btn + '</span>');
    } else {
      toast(d.message, 'error');
      updateStatusAndGauge();
      btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> <span>' + T().manual_switch_btn + '</span>');
    }
  }).fail(function () {
    toast(T().switch_failed_network, 'error');
    btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> <span>' + T().manual_switch_btn + '</span>');
  });
}


function loadLocalProxies() {
  $.get(appendToken('/api/proxies'), function (d) {
    var h = [], hs = [], s = [], f = [];
    (d.proxies || []).forEach(function (p) {
      if (p.indexOf('@') >= 0 || (p.indexOf('://') >= 0 && !p.match(/^(http|https|socks5):\/\/[^@]+:\d+$/))) f.push(p);
      else if (p.indexOf('http://') === 0) h.push(p.replace('http://', ''));
      else if (p.indexOf('https://') === 0) hs.push(p.replace('https://', ''));
      else if (p.indexOf('socks5://') === 0) s.push(p.replace('socks5://', ''));
      else h.push(p);
    });
    $('#http-proxy-list').val(h.join('\n')); $('#https-proxy-list').val(hs.join('\n'));
    $('#socks5-proxy-list').val(s.join('\n')); $('#full-proxy-list').val(f.join('\n'));
  });
}

function saveProxies() {
  var b = $('#btn-save-proxy'); btnLoad(b, true);
  var ok = false;
  var a = [];
  $('#http-proxy-list').val().split('\n').forEach(function (l) { if (l.trim()) a.push('http://' + l.trim()); });
  $('#https-proxy-list').val().split('\n').forEach(function (l) { if (l.trim()) a.push('https://' + l.trim()); });
  $('#socks5-proxy-list').val().split('\n').forEach(function (l) { if (l.trim()) a.push('socks5://' + l.trim()); });
  $('#full-proxy-list').val().split('\n').forEach(function (l) { if (l.trim()) a.push(l.trim()); });
  $.ajax({
    url: appendToken('/api/proxies'), method: 'POST', contentType: 'application/json', data: JSON.stringify({ proxies: a }),
    success: function (r) {
      if (r.status === 'success') { ok = true; toast(T().proxy_save_success, 'success'); btnLoad(b, false); flashSaved(b); loadLocalProxies(); }
      else toast(r.message, 'error');
    },
    error: function (x) { toast(T().proxy_save_failed + T().sep_colon + jqErrorText(x), 'error'); },
    complete: function () { if (!ok) flashResult(b, false); }
  });
}

function checkProxies() {
  var b = $('#btn-check-proxy'); btnLoad(b, true);
  var u = $('input[name="test_url"]').val() || 'https://www.baidu.com';
  var ok = false;
  $.get(appendToken('/api/check_proxies'), { test_url: u }, function (d) {
    if (d.status === 'success') {
      ok = true;
      loadLocalProxies();
      toast(fillTemplate(T().proxy_check_result, d.total), 'success');
    } else {
      toast(d.message, 'error');
    }
  }).fail(function (x) {
    toast(T().proxy_check_failed + T().sep_colon + jqErrorText(x), 'error');
  }).always(function () {
    btnLoad(b, false);
    if (!ok) flashResult(b, false);
  });
}


function loadIpLists() {
  $.get(appendToken('/api/ip_lists'), function (d) {
    $('#whitelist').val((d.whitelist || []).join('\n'));
    $('#blacklist').val((d.blacklist || []).join('\n'));
  });
}

function saveIpLists(btn) {
  var b = $(btn);
  if (b.length) btnLoad(b, true);
  var wl = $('#whitelist').val().split('\n').filter(function (l) { return l.trim(); });
  var bl = $('#blacklist').val().split('\n').filter(function (l) { return l.trim(); });
  $.ajax({
    url: appendToken('/api/config'), method: 'POST', contentType: 'application/json',
    data: JSON.stringify({ server: { ip_auth_priority: $('select[name="ip_auth_priority"]').val() } }),
    success: function () {
      syncServerBaseline(['ip_auth_priority']);
      var saveWl = $.ajax({ url: appendToken('/api/ip_lists'), method: 'POST', contentType: 'application/json',
        data: JSON.stringify({ type: 'whitelist', list: wl }) });
      var saveBl = $.ajax({ url: appendToken('/api/ip_lists'), method: 'POST', contentType: 'application/json',
        data: JSON.stringify({ type: 'blacklist', list: bl }) });
      $.when(saveWl, saveBl).done(function () {
        toast(T().ip_list_save_success, 'success');
        if (b.length) { btnLoad(b, false); flashSaved(b); }
        loadIpLists();
      }).fail(function (x) {
        toast(T().ip_list_save_failed, 'error');
        if (b.length) flashResult(b, false);
      });
    },
    complete: function () { if (b.length) btnLoad(b, false); }
  });
}


function loadBypassWhitelist() {
    $.get(appendToken('/api/bypass_whitelist'), function(d) {
        $('#bypass-whitelist').val((d.list || []).join('\n'));
    });
}

function saveBypassWhitelist(btn) {
    var b = $(btn);
    if (b.length) btnLoad(b, true);
    var list = $('#bypass-whitelist').val().split('\n').filter(function(l) { return l.trim(); });
    $.ajax({
        url: appendToken('/api/bypass_whitelist'), method: 'POST', contentType: 'application/json',
        data: JSON.stringify({ list: list }),
        success: function(r) {
            if (r.status === 'success') {
                toast(T().bypass_save_success, 'success');
                if (b.length) { btnLoad(b, false); flashSaved(b); }
                loadBypassWhitelist();
            } else toast(r.message || T().save_failed, 'error');
        },
        error: function() { toast(T().bypass_save_failed || T().save_failed, 'error'); },
        complete: function() { if (b.length) btnLoad(b, false); }
    });
}


var USER_PASS_MASK = '••••••••';

function toggleUserPassword($pass, btn) {
  var masked = $pass.hasClass('masked');
  if (masked) $pass.text($pass.attr('data-pass') || '').removeClass('masked');
  else $pass.text(USER_PASS_MASK).addClass('masked');
  var label = masked ? T().user_hide_password : T().user_show_password;
  $(btn).find('i').attr('class', 'fa ' + (masked ? 'fa-eye-slash' : 'fa-eye'));
  $(btn).attr('title', label).attr('aria-label', label);
}

function loadUsers() {
  onLangRender(loadUsers);
  beginTableLoad('#user-table tbody', 3, 2);
  $.ajax({ url: appendToken('/api/users'), timeout: 15000 })
    .done(function (d) {
    if (d.status === 'error' || !d.users) {
      showTableAlert('#user-table tbody', 3, d.message || T().users_load_failed, 'users');
      return;
    }
    clearTableAlert('#user-table tbody');
    var t = $('#user-table tbody').empty();
    var users = d.users || {}, count = Object.keys(users).length;
    if (count === 0) t.append(emptyRow(3, T().no_users));
    $.each(users, function (u, p) {
      var $row = $('<tr>');
      $('<td>').append($('<span class="user-name">').text(u)).appendTo($row);

      var $pass = $('<span class="user-pass masked">')
        .attr('data-pass', p).text(USER_PASS_MASK);
      var $passCell = $('<td>').append($pass).appendTo($row);

      var $actions = $('<td class="user-actions">');
      var $eye = $('<button type="button" class="icon-btn user-eye">')
        .html('<i class="fa fa-eye"></i>')
        .attr('title', T().user_show_password).attr('aria-label', T().user_show_password)
        .on('click', function () { toggleUserPassword($pass, this); });
      $('<button class="btn xs" type="button">').append('<i class="fa fa-edit"></i>')
        .attr('title', T().edit_user_title).attr('aria-label', T().edit_user_title)
        .on('click', function () { editUser(u); }).appendTo($actions);
      $('<button class="btn xs bad" type="button">').append('<i class="fa fa-trash"></i>')
        .attr('title', T().confirm_delete_title).attr('aria-label', T().confirm_delete_title)
        .on('click', function () { deleteUser(u); }).appendTo($actions);
      $actions.appendTo($row);
      $row.appendTo(t);
      $passCell.append($eye);
    });
    if (count > 0) $('#user-count').show().text(count + ' ' + T().user_count_label);
    else $('#user-count').hide();
    updAddr({});
    })
    .fail(function (x) {
      showTableAlert('#user-table tbody', 3,
        jqErrorText(x, T().network_error), 'users');
    });
}

registerTableRetry('users', loadUsers);

function addUser() {
  showPrompt(T().add_user_btn, T().enter_username, '', '', function (u) {
    if (!u) return;
    showPrompt(T().add_user_btn, T().enter_password, '', '', function (p) {
      if (!p) return;
      var o = collectUsers();
      o[u] = p; saveUsers(o);
    });
  });
}

function editUser(u) {
  showPrompt(T().edit_user_title, fillTemplate(T().edit_user_msg, u), '', '', function (p) {
    if (!p) return;
    var o = collectUsers();
    if (u in o) o[u] = p;
    saveUsers(o);
  });
}

function deleteUser(u) {
  showConfirm(T().confirm_delete_title, fillTemplate(T().confirm_delete_user, u), function (ok) {
    if (!ok) return;
    var o = collectUsers();
    delete o[u];
    saveUsers(o);
  });
}

function saveUsers(o) {
  $.ajax({
    url: appendToken('/api/users'), method: 'POST', contentType: 'application/json', data: JSON.stringify({ users: o }),
    success: function (r) { if (r.status === 'success') { toast(T().users_save_success, 'success'); loadUsers(); } else toast(r.message, 'error'); },
    error: function (x) { toast(T().users_save_failed + T().sep_colon + jqErrorText(x), 'error'); }
  });
}


function loadApiCredentials() {
  onLangRender(loadApiCredentials);
  $.get(appendToken('/api/api_credentials'), function (d) {
    var sel = $('#api-credential-select').empty();
    sel.append('<option value="">-- ' + T().api_no_selection + ' --</option>');
    if (d.status === 'success' && d.sets) {
      d.sets.forEach(function (s) {
        sel.append('<option value="' + escapeHtml(s.name) + '">' + escapeHtml(s.name) +
                   (s.url ? '  ·  ' + escapeHtml(s.url) : '') + '</option>');
      });
      if (d.active_credential) sel.val(d.active_credential);
    }
    $('#btn-delete-credential').prop('disabled', !d.active_credential);
    window._apiSets = d.sets || [];
  });
}

function onCredentialSelect() {
  var name = $('#api-credential-select').val();
  $('#btn-delete-credential').prop('disabled', !name);
  if (!name) return;
  var sets = window._apiSets || [];
  var target = sets.find(function (s) { return s.name === name; });
  if (target) {
    $('input[name="api_proxy_url"]').val(target.url || '');
    $('#proxy-auth').val(_joinProxyAuth(target.username, target.password));
    syncProxyAuthHint();
    $.ajax({
      url: appendToken('/api/api_credentials'), method: 'POST', contentType: 'application/json',
      data: JSON.stringify({ action: 'set_active', name: name }),
      success: function (r) {
        if (r.status === 'success') {
          syncServerBaseline(['api_proxy_url', 'proxy_username', 'proxy_password']);
          updateStatusAndGauge();
          toast(T().api_credential_switched + T().sep_colon + name, 'success');
        } else {
          toast(r.message || fillTemplate(T().operation_failed, name), 'error');
        }
      },
      error: function () {
        toast(fillTemplate(T().operation_failed, name), 'error');
      }
    });
  }
}

function saveApiCredential() {
  showPrompt(T().api_save_credential, T().api_enter_name, '', T().api_name_placeholder, function (name) {
    if (!name) return;
    $.ajax({
      url: appendToken('/api/api_credentials'), method: 'POST', contentType: 'application/json',
      data: JSON.stringify({ action: 'save', name: name,
        url: $('input[name="api_proxy_url"]').val(),
        username: _splitProxyAuth($('#proxy-auth').val()).username,
        password: _splitProxyAuth($('#proxy-auth').val()).password
      }),
      success: function (r) { if (r.status === 'success') { toast(T().api_credential_saved, 'success'); loadApiCredentials(); } else toast(r.message, 'error'); },
      error: function (x) { toast(T().request_failed + T().sep_colon + jqErrorText(x, T().network_error), 'error'); }
    });
  });
}

function deleteApiCredential() {
  var name = $('#api-credential-select').val(); if (!name) return;
  showConfirm(T().api_confirm_delete, fillTemplate(T().api_confirm_delete_msg, name), function (ok) {
    if (!ok) return;
    $.ajax({
      url: appendToken('/api/api_credentials'), method: 'POST', contentType: 'application/json',
      data: JSON.stringify({ action: 'delete', name: name }),
      success: function (r) { if (r.status === 'success') { toast(T().api_credential_deleted, 'success'); loadApiCredentials(); } else toast(r.message, 'error'); },
      error: function (x) { toast(T().request_failed + T().sep_colon + jqErrorText(x, T().network_error), 'error'); }
    });
  });
}


function controlPool(a) {
  var b = $('#pool-' + a); btnLoad(b, true);
  $.ajax({
    url: appendToken('/api/pool/' + a), method: 'POST',
    success: function (r) { if (r.status === 'success') toast(r.message, 'success'); else toast(r.message, 'error'); setTimeout(updatePoolStatus, 1500); },
    error: function (x) { toast(fillTemplate(T().operation_failed, x.responseText), 'error'); },
    complete: function () { btnLoad(b, false); }
  });
}


var _logFollow = true;
var _logAuto = true;
var _logCategory = 'all';
var _logFile = '';
var _logFileCache = null;
var _logHasRendered = false;

var CATEGORY_LABELS = {
  all: function () { return T().log_cat_all; },
  main: function () { return T().log_cat_main; },
  proxy: function () { return T().log_cat_proxy; },
  access: function () { return T().log_cat_access; },
  pool: function () { return T().log_cat_pool; },
  error: function () { return T().log_cat_error; }
};

function setLogCategory(cat) {
  _logCategory = cat;
  $('#log-category').val(cat);
  $('#log-cat-pills .log-cat-pill').removeClass('cur');
  $('#log-cat-pills .log-cat-pill[data-cat="' + cat + '"]').addClass('cur');
  loadLogFiles();
  _updateAccessPanelVisibility();
  updateLogs(true);
}

function setLogLevel(lv) {
  $('#log-level').val(lv);
  $('#log-level-pills .log-lv-pill').removeClass('cur');
  $('#log-level-pills .log-lv-pill[data-lv="' + lv + '"]').addClass('cur');
  updateLogs(true);
}

function toggleLogFollow() {
  _logFollow = !_logFollow;
  $('#log-follow-btn').toggleClass('on', _logFollow);
  if (_logFollow) updateLogs(true);
}

function toggleLogAuto() {
  _logAuto = !_logAuto;
  $('#log-auto-btn').toggleClass('on', _logAuto);
  if (_logAuto) updateLogs(true);
}

function onLogSourceChange() {
  _logFile = $('#log-file-select').val() || '';
  _logFileCache = null;
  $('#log-container').toggleClass('showing-file', !!_logFile);
  _updateAccessPanelVisibility();
  updateLogs(true);
}

function loadLogFiles() {
  onLangRender(loadLogFiles);
  $.get(appendToken('/api/logs/files'), function (d) {
    if (d.status !== 'success') return;
    var sel = $('#log-file-select'), keep = _logFile;
    sel.empty().append($('<option>').val('').text(T().log_source_live));
    (d.files || []).forEach(function (f) {
      var cat = CATEGORY_LABELS[f.category];
      var label = (cat ? cat() : f.category) + ' · ' + f.name + ' · ' + fmtLogSize(f.size);
      sel.append($('<option>').val(f.name).text(label));
    });
    if (keep && sel.find('option[value="' + keep + '"]').length) {
      sel.val(keep);
    } else if (_logFile) {
      _logFile = '';
      _logFileCache = null;
      sel.val('');
      $('#log-container').removeClass('showing-file');
      _updateAccessPanelVisibility();
      updateLogs(true);
    }
  });
}


function renderLogMessage(msg, kw) {
  var text = (msg === null || msg === undefined) ? '' : String(msg);
  if (!kw) return escapeHtml(text);
  var key = String(kw).toLowerCase();
  if (!key) return escapeHtml(text);
  var out = '', i = 0, low = text.toLowerCase();
  for (;;) {
    var at = low.indexOf(key, i);
    if (at < 0) { out += escapeHtml(text.slice(i)); break; }
    out += escapeHtml(text.slice(i, at)) +
           '<span class="log-hit">' + escapeHtml(text.slice(at, at + key.length)) + '</span>';
    i = at + key.length;
  }
  return out;
}

function _applyLevelFilter(entries) {
  var lv = $('#log-level').val();
  if (!lv || lv === 'ALL') return entries;
  if (lv === 'IMPORTANT') {
    return entries.filter(function (e) {
      return e.level === 'WARNING' || e.level === 'ERROR' || e.level === 'CRITICAL';
    });
  }
  return entries.filter(function (e) { return e.level === lv; });
}

function parseLogLine(line) {
  var m = String(line).match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([A-Z]+) - ([\s\S]*)$/);
  if (m) return { time: m[1], level: m[2], message: m[3] };
  return { time: '', level: 'INFO', message: line };
}

function _renderLogEntries(entries, kw) {
  var c = $('#log-container');
  c.empty();
  if (!entries.length) {
    c.addClass('is-empty').append('<div class="empty-hint">' + escapeHtml(T().no_logs) + '</div>');
    return;
  }
  c.removeClass('is-empty');

  var prevKey = null, prevEl = null;
  entries.forEach(function (l) {
    var lvName = l.level || 'INFO';
    var key = lvName + '|' + l.message;
    if (prevEl && key === prevKey) {
      var n = (prevEl.data('repeat') || 1) + 1;
      prevEl.data('repeat', n).addClass('folded');
      prevEl.find('.log-repeat').text('×' + n);
      return;
    }
    var cat = CATEGORY_LABELS[l.category];
    prevKey = key;
    prevEl = $('<div class="log-line log-' + lvName + '">' +
      (l.time ? '<span class="log-time">' + escapeHtml(l.time) + '</span>' : '') +
      '<span class="log-level-badge ' + lvName + '">' + escapeHtml(lvName) + '</span>' +
      (l.category ? '<span class="log-cat log-cat-' + escapeHtml(l.category) + '">' +
        escapeHtml(cat ? cat() : l.category) + '</span>' : '') +
      '<span class="log-repeat"></span>' +
      '<span class="log-msg">' + renderLogMessage(l.message, kw) + '</span>' +
      '<button type="button" class="log-copy" title="' + escapeHtml(T().copy_line) +
        '" aria-label="' + escapeHtml(T().copy_line) + '"><i class="fa fa-copy"></i></button>' +
      '</div>');
    c.append(prevEl);
  });
}

function updateLogs(force) {
  onLangRender(updateLogs);
  if (_logFile && !force) return;
  if (!_logAuto && !force && _logHasRendered) return;

  var kw = $('#log-search').val() || '';
  var c = $('#log-container');
  var wasAtBottom = c.scrollTop() + c.innerHeight() >= c[0].scrollHeight - 4;
  var prevScroll = c.scrollTop();

  function done(entries) {
    _renderLogEntries(entries, kw);
    _logHasRendered = true;
    if (_logFollow && wasAtBottom) c.scrollTop(c[0].scrollHeight);
    else c.scrollTop(prevScroll);
  }

  if (_logFile) {
    var cacheFresh = _logFileCache && _logFileCache.name === _logFile &&
                     (Date.now() - _logFileCache.at) < 1000;
    if (cacheFresh) {
      done(_applyLevelFilter(_logFileCache.entries));
      updateLogStats();
      return;
    }
    $.get(appendToken('/api/logs/file?name=' + encodeURIComponent(_logFile) + '&lines=2000'), function (d) {
      if (d.status !== 'success') { toast(d.message || T().log_file_read_failed, 'error'); return; }
      _logFileCache = { name: _logFile, entries: (d.lines || []).map(parseLogLine), at: Date.now() };
      done(_applyLevelFilter(_logFileCache.entries));
    });
  } else {
    $.get(appendToken('/api/logs?category=' + encodeURIComponent(_logCategory) +
                      '&level=' + $('#log-level').val() +
                      '&search=' + encodeURIComponent(kw)), function (d) {
      if (d.status !== 'success') return;
      done(d.logs || []);
    });
  }
  updateLogStats();
}

function updateLogStats() {
  onLangRender(updateLogStats);
  $.get(appendToken('/api/logs/stats'), function (d) {
    if (d.status !== 'success') return;
    var s = d.stats, lvs = s.levels || {}, cats = s.categories || {}, a = [];
    a.push('<span class="log-stat-item total"><b>' + escapeHtml(T().log_total) + '</b> ' + s.total + '</span>');
    ['INFO', 'WARNING', 'ERROR', 'CRITICAL'].forEach(function (k) {
      if (lvs[k] !== undefined) a.push('<span class="log-stat-item ' + k + '">' + k + ' ' + lvs[k] + '</span>');
    });
    Object.keys(CATEGORY_LABELS).forEach(function (k) {
      if (k === 'all' || cats[k] === undefined) return;
      var label = CATEGORY_LABELS[k];
      a.push('<span class="log-stat-item log-stat-cat">' + escapeHtml(label ? label() : k) + ' ' + cats[k] + '</span>');
    });
    $('#log-stats').html(a.join(''));
    _paintCategoryCounts(s);
  });
}

function _paintCategoryCounts(s) {
  var cats = (s && s.categories) || {};
  $('#log-cat-pills .log-cat-pill').each(function () {
    var cat = $(this).attr('data-cat');
    var n = cat === 'all' ? s.total : cats[cat];
    var $count = $(this).find('.pill-count');
    if (n === undefined || n === null) { $count.remove(); return; }
    if (!$count.length) $count = $('<span class="pill-count"></span>').appendTo(this);
    $count.text(n);
  });
}

$(document).on('click', '.log-copy', function () {
  var $line = $(this).closest('.log-line');
  var text = [
    $line.find('.log-time').text(),
    $line.find('.log-level-badge').text(),
    $line.find('.log-msg').text()
  ].filter(function (v) { return v; }).join(' ');
  copyToClipboard(text, function () {
    toast(T().log_line_copied, 'success');
  });
});

function exportLogs() {
  var url = '/api/logs/export?';
  if (_logFile) url += 'file=' + encodeURIComponent(_logFile);
  else url += 'category=' + encodeURIComponent(_logCategory) +
              '&level=' + $('#log-level').val() +
              '&search=' + encodeURIComponent($('#log-search').val() || '');
  window.open(appendToken(url), '_blank');
  toast(T().log_export_started, 'success');
}

function onLogSearch() {
  var v = $('#log-search').val(); $('#log-clear-btn').toggle(!!v);
  clearTimeout(logTimer); logTimer = setTimeout(function () { updateLogs(true); }, 300);
}

function clearLogSearch() {
  $('#log-search').val('');
  $('#log-clear-btn').hide();
  updateLogs(true);
}

function clearLogs() {
  var label = CATEGORY_LABELS[_logCategory];
  var scope = label ? label() : _logCategory;
  showConfirm(T().confirm_clear_title,
    T().confirm_clear_logs + T().sep_paren_open + scope + T().sep_paren_close, function (ok) {
    if (!ok) return;
    $.ajax({
      url: appendToken('/api/logs/clear'), method: 'POST', contentType: 'application/json',
      data: JSON.stringify({ category: _logCategory }),
      success: function (r) {
        if (r.status !== 'success') { toast(r.message || T().clear_logs_failed, 'error'); return; }
        toast(T().logs_cleared, 'success');
        $('#log-container').empty(); $('#log-stats').empty();
        loadLogFiles();
      },
      error: function () { toast(T().clear_logs_failed, 'error'); }
    });
  }, { danger: true });
}

var _domainSearchTimer = null;
var _domainSort = 'last_seen';
var _domainOrder = 'desc';
var _upstreamRows = [];
var _domainPayload = null;
var _expandedUpstreams = {};

var _accessMode = 'summary';
var _recordsPage = 1;
var _recordsPageSize = 100;
var _recordsTotal = 0;
var _recordsAuto = true;
var _recordsSearchTimer = null;
var _recordsPayload = null;
var _recordsOptionsLoaded = false;

function _startDomainRefresh() {
  if (isPolling('domain')) return;
  _updateAccessPanelVisibility();
  _refreshAccessPanel();
  startPolling('domain', _refreshAccessPanel, 5000);
}

function _refreshAccessPanel() {
  if (_accessMode === 'records') {
    if (_recordsAuto) loadAccessRecords();
  } else {
    loadDomainStats();
  }
}

function _stopDomainRefresh() {
  stopPolling('domain');
}

function _updateAccessPanelVisibility() {
  $('#log-cat-pills').toggle(!_logFile);
  $('#log-clear-btn-wrap').toggle(!_logFile);

  var show = _logCategory === 'access' && !_logFile;
  var wasHidden = !$('#access-stats-panel').is(':visible');
  $('#access-stats-panel').toggle(show);
  $('#access-hint').toggle(!show && !_logFile);
  if (show && wasHidden) {
    if (_accessMode === 'records') _loadRecordOptions(function () { loadAccessRecords(); });
    else loadDomainStats();
  }
}

function showAccessStats() {
  _logFile = '';
  $('#log-file-select').val('');
  $('#log-container').removeClass('showing-file');
  setLogCategory('access');
}


function setAccessMode(mode) {
  _accessMode = mode === 'records' ? 'records' : 'summary';
  $('#access-mode-pills .log-lv-pill').removeClass('cur');
  $('#access-mode-pills .log-lv-pill[data-access-mode="' + _accessMode + '"]').addClass('cur');
  $('#access-summary-view').toggle(_accessMode === 'summary');
  $('#access-records-view').toggle(_accessMode === 'records');

  if (_accessMode === 'records') _loadRecordOptions(function () { loadAccessRecords(); });
  else loadDomainStats();
}

function _loadRecordOptions(onReady) {
  var done = onReady || function () {};
  if (_recordsOptionsLoaded) { done(); return; }

  $.ajax({
    url: appendToken('/api/logs/records/options'),
    success: function (d) {
      if (d.status !== 'success') { done(); return; }
      var html = '<option value="">' + escapeHtml(T().records_upstream_all) + '</option>';
      (d.upstreams || []).forEach(function (item) {
        html += '<option value="' + escapeHtml(item.value) + '">' +
                escapeHtml(item.label || item.value) + ' (' + item.count + ')</option>';
      });
      $('#records-upstream').html(html);
      _recordsOptionsLoaded = true;
      done();
    },
    error: done
  });
}

function _recordRangeParams() {
  var since = $('#records-since').val() || '';
  var until = $('#records-until').val() || '';
  return '&since=' + encodeURIComponent(since) + '&until=' + encodeURIComponent(until);
}

function _recordsFilterParams() {
  return '&outcome=' + encodeURIComponent($('#records-outcome').val() || '') +
         '&upstream=' + encodeURIComponent($('#records-upstream').val() || '') +
         '&search=' + encodeURIComponent($('#records-search').val() || '') +
         _recordRangeParams();
}

function _toLocalInputValue(date) {
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) +
         'T' + pad(date.getHours()) + ':' + pad(date.getMinutes());
}

function setRecordsRange(preset) {
  var now = new Date();
  var since;
  if (preset === 'today') {
    since = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  } else {
    var minutes = { '5m': 5, '1h': 60, '24h': 1440 }[preset] || 60;
    since = new Date(now.getTime() - minutes * 60000);
  }

  $('#records-since').val(_toLocalInputValue(since));
  $('#records-until').val('');
  $('#access-records-view .log-lv-pill').removeClass('cur');
  $('#access-records-view .log-lv-pill[data-records-range="' + preset + '"]').addClass('cur');
  _recordsPage = 1;
  loadAccessRecords();
}

function onRecordsRangeChange() {
  $('#access-records-view .log-lv-pill').removeClass('cur');
  _recordsPage = 1;
  loadAccessRecords();
}

function onRecordsFilterChange() {
  _recordsPage = 1;
  loadAccessRecords();
}

function onRecordsSearch() {
  clearTimeout(_recordsSearchTimer);
  _recordsSearchTimer = setTimeout(function () {
    _recordsPage = 1;
    loadAccessRecords();
  }, 300);
}

function toggleRecordsAuto() {
  _recordsAuto = !_recordsAuto;
  $('#records-auto-btn').toggleClass('on', _recordsAuto);
  if (_recordsAuto) loadAccessRecords();
}

function _pauseRecordsAutoOnPaging() {
  if (_recordsPage > 1 && _recordsAuto) {
    _recordsAuto = false;
    $('#records-auto-btn').removeClass('on');
  }
}

function recordsPrevPage() {
  if (_recordsPage <= 1) return;
  _recordsPage -= 1;
  _pauseRecordsAutoOnPaging();
  loadAccessRecords();
}

function recordsNextPage() {
  if (_recordsPage * _recordsPageSize >= _recordsTotal) return;
  _recordsPage += 1;
  _pauseRecordsAutoOnPaging();
  loadAccessRecords();
}

function loadAccessRecords() {
  onLangRender(loadAccessRecords);
  if (_accessMode !== 'records') return;
  if (!$('#access-stats-panel').is(':visible')) return;

  var q = '/api/logs/records?limit=' + _recordsPageSize +
          '&offset=' + ((_recordsPage - 1) * _recordsPageSize) +
          _recordsFilterParams();
  beginTableLoad('#records-tbody', 9, 6);
  $.ajax({
    url: appendToken(q),
    timeout: 15000,
    success: function (d) {
      if (d.status !== 'success') { toast(d.message || '', 'error'); return; }
      clearTableAlert('#records-tbody');
      _recordsPayload = d;
      _recordsTotal = d.total || 0;
      _renderRecordTable();
    },
    error: function (x) {
      showTableAlert('#records-tbody', 9,
        jqErrorText(x, T().network_error) + T().sep_mid + T().stale_data_note, 'records');
    }
  });
}

registerTableRetry('records', loadAccessRecords);

function _renderRecordTable() {
  var payload = _recordsPayload || {};
  var tbody = $('#records-tbody');
  tbody.empty();

  if (payload.enabled === false) {
    tbody.append(emptyRow(9, T().records_disabled));
  } else if (!(payload.records || []).length) {
    tbody.append(emptyRow(9, T().records_no_data));
  } else {
    payload.records.forEach(function (record) { tbody.append(_recordRow(record)); });
  }

  var counts = payload.outcome_counts || {};
  var parts = [
    T().records_summary_range + ' ' + (payload.total || 0) + ' ' + T().records_summary_unit,
    T().access_outcome_success + ' ' + (counts.success || 0),
    T().access_outcome_failure + ' ' + (counts.failure || 0),
    T().access_outcome_aborted + ' ' + (counts.aborted || 0)
  ];
  if (payload.pending) {
    parts.push(fillTemplate(T().records_summary_pending, payload.pending));
  }
  if (payload.dropped) {
    parts.push(fillTemplate(T().records_summary_dropped, payload.dropped));
  }
  $('#records-summary').text(parts.join(' · '));

  var pages = Math.max(1, Math.ceil(_recordsTotal / _recordsPageSize));
  $('#records-page-info').text(fillTemplate(
    T().records_page_info, _recordsPage, pages));
  $('#records-prev-btn').prop('disabled', _recordsPage <= 1);
  $('#records-next-btn').prop('disabled', _recordsPage >= pages);
}

function _recordRow(record) {
  var outcome = record.outcome || '';
  return $('<tr data-id="' + escapeHtml(record.id) + '">' +
    '<td class="cell-mono">' + escapeHtml(record.ts || '') + '</td>' +
    '<td class="cell-mono">' + escapeHtml(record.client || '') + '</td>' +
    '<td class="cell-mono">' + escapeHtml(record.target || '') + '</td>' +
    '<td class="cell-mono">' + escapeHtml(record.upstream_label || record.upstream || '') + '</td>' +
    '<td class="cell-mono">' + escapeHtml(record.real_ip || '--') + '</td>' +
    '<td><span class="record-outcome ' + escapeHtml(outcome) + '">' +
      escapeHtml(_outcomeLabel(outcome)) + '</span></td>' +
    '<td class="cell-num">' + _statusCell(record.status_code) + '</td>' +
    '<td class="cell-num">' + (record.elapsed_ms || 0) + ' ms</td>' +
    '<td class="domain-reason" title="' + escapeHtml(record.reason || '') + '">' +
      escapeHtml(record.reason || '--') + '</td></tr>');
}

function _statusCell(code) {
  if (code === null || code === undefined) return '<span class="status-code">--</span>';
  var cls = 'status-code';
  if (code >= 200 && code < 300) cls += ' ok';
  else if (code >= 300 && code < 400) cls += ' redirect';
  else if (code >= 400 && code < 500) cls += ' client';
  else if (code >= 500) cls += ' server';
  return '<span class="' + cls + '">' + escapeHtml(code) + '</span>';
}

function _outcomeLabel(outcome) {
  if (outcome === 'success') return T().access_outcome_success;
  if (outcome === 'failure') return T().access_outcome_failure;
  if (outcome === 'aborted') return T().access_outcome_aborted;
  return outcome || '--';
}

function openRecordDrawer(id) {
  var list = (_recordsPayload && _recordsPayload.records) || [];
  var r = null;
  for (var i = 0; i < list.length; i++) {
    if (String(list[i].id) === String(id)) { r = list[i]; break; }
  }
  if (!r) return;

  openRowDrawer({
    title: r.target || '--',
    subtitle: (r.ts || '') + ' · ' + _outcomeLabel(r.outcome),
    fields: drawerSections([
      [T().drawer_group_request, [
        { label: T().records_col_time, value: r.ts, mono: true },
        { label: T().records_col_client, value: r.client, mono: true },
        { label: T().records_col_target, value: r.target, mono: true, copy: true },
        { label: T().records_method, value: r.method || '' },
        { label: T().records_kind, value: r.kind || '' }
      ]],
      [T().drawer_group_upstream, [
        { label: T().records_col_upstream, value: r.upstream_label || r.upstream, mono: true, copy: true },
        { label: T().records_col_real_ip, value: r.real_ip, mono: true }
      ]],
      [T().drawer_group_result, [
        { label: T().records_col_outcome, value: _outcomeLabel(r.outcome) },
        { label: T().records_col_status, value: (r.status_code === null || r.status_code === undefined) ? '' : String(r.status_code), mono: true },
        { label: T().records_col_elapsed, value: (r.elapsed_ms || 0) + ' ms', mono: true },
        { label: T().records_col_reason, value: r.reason || '' }
      ]]
    ])
  });
}

function initAccessRecordsTable() {
  var table = $('#records-table');
  if (!table.length) return;
  table.on('click', 'tbody tr[data-id]', function () {
    openRecordDrawer($(this).attr('data-id'));
  });
  attachTableKeyboard(table, {
    onActivate: function (i) {
      var row = table.find('tbody tr[data-id]').eq(i);
      if (row.length) openRecordDrawer(row.attr('data-id'));
    }
  });
}

function exportAccessRecords() {
  var url = '/api/logs/records/export?format=' + encodeURIComponent($('#records-format').val() || 'csv') +
            _recordsFilterParams();
  var limit = (_recordsPayload && _recordsPayload.export_limit) || 0;

  if (limit && _recordsTotal > limit) {
    showConfirm(
      T().records_export_btn,
      fillTemplate(T().records_export_truncated,
                   _recordsTotal, limit),
      function (ok) {
        if (!ok) return;
        window.open(appendToken(url));
        toast(T().log_export_started, 'success');
      }
    );
    return;
  }
  window.open(appendToken(url));
  toast(T().log_export_started, 'success');
}

function clearAccessRecords() {
  showConfirm(T().confirm_clear_title,
              T().confirm_clear_records,
              function (ok) {
    if (!ok) return;
    $.ajax({
      url: appendToken('/api/logs/records/clear'), method: 'POST',
      success: function (r) {
        if (r.status !== 'success') { toast(r.message || '', 'error'); return; }
        toast(r.message || '', 'success');
        _recordsPage = 1;
        _recordsOptionsLoaded = false;
        _loadRecordOptions(function () { loadAccessRecords(); });
      },
      error: function () { toast(T().clear_logs_failed, 'error'); }
    });
  }, { danger: true });
}

function sortDomainStats(field) {
  if (_domainSort === field) _domainOrder = _domainOrder === 'desc' ? 'asc' : 'desc';
  else { _domainSort = field; _domainOrder = 'desc'; }
  loadDomainStats();
}

function onDomainSearch() {
  clearTimeout(_domainSearchTimer);
  _domainSearchTimer = setTimeout(loadDomainStats, 300);
}

function loadDomainStats() {
  onLangRender(loadDomainStats);
  if (!$('#access-stats-panel').is(':visible')) return;
  var q = '/api/logs/domains?sort=' + _domainSort + '&order=' + _domainOrder +
          '&limit=200&search=' + encodeURIComponent($('#domain-search').val() || '');
  beginTableLoad('#domain-tbody', 7, 6);
  $.ajax({ url: appendToken(q), timeout: 15000 })
    .done(function (d) {
      if (d.status !== 'success') return;
      clearTableAlert('#domain-tbody');
      _upstreamRows = d.proxies || [];
      _domainPayload = d;
      _renderDomainTable();
    })
    .fail(function (x) {
      showTableAlert('#domain-tbody', 7,
        jqErrorText(x, T().network_error) + T().sep_mid + T().stale_data_note, 'domains');
    });
}

registerTableRetry('domains', loadDomainStats);

function _rateCell(row) {
  var total = row.total || 0;
  var rate = total ? Math.round((row.success / total) * 100) : 0;
  var cls = total && row.failure ? (rate < 50 ? 'domain-rate bad' : 'domain-rate warn') : 'domain-rate';
  return '<span class="' + cls + '">' + rate + '%</span>';
}

function _renderDomainTable() {
  var payload = _domainPayload || {};
  var tbody = $('#domain-tbody');
  tbody.empty();

  if (payload.enabled === false) {
    tbody.append(emptyRow(7, T().domain_disabled));
  } else if (!_upstreamRows.length) {
    tbody.append(emptyRow(7, T().domain_no_data));
  } else {
    _upstreamRows.forEach(function (row) {
      tbody.append(_upstreamRow(row));
      var detail = _expandedUpstreams[row.upstream];
      if (detail === undefined) return;
      if (detail === 'loading') {
        tbody.append(emptyRow(7, T().loading, 'domain-detail'));
        return;
      }
      detail.forEach(function (d) { tbody.append(_domainDetailRow(d)); });
    });
  }

  var s = payload.summary || {};
  $('#domain-summary').text(
    T().access_summary + ' ' + (payload.total || 0) +
    ' · ' + T().access_summary_hosts + ' ' + (s.hosts || 0) +
    ' · ' + T().domain_summary_ok + ' ' + (s.success || 0) +
    ' / ' + T().domain_summary_fail + ' ' + (s.failure || 0));
}

function _upstreamRow(row) {
  var expanded = _expandedUpstreams[row.upstream] !== undefined;
  var label = row.upstream_label || row.upstream;
  return $('<tr class="domain-row' + (expanded ? ' expanded' : '') + '">' +
    '<td class="cell-mono domain-toggle"><i class="fa fa-caret-' + (expanded ? 'down' : 'right') +
      '"></i> <span class="domain-name">' + escapeHtml(label) + '</span>' +
      '<span class="domain-count" title="' + escapeHtml(T().access_col_hosts) + '">' +
      row.host_count + '</span></td>' +
    '<td class="domain-ok cell-num">' + row.success + '</td>' +
    '<td class="domain-fail cell-num">' + row.failure + '</td>' +
    '<td class="cell-num">' + row.total + '</td>' +
    '<td>' + _rateCell(row) + '</td>' +
    '<td class="cell-mono">' + escapeHtml(row.last_seen || '--') + '</td>' +
    '<td class="domain-reason" title="' + escapeHtml(row.last_error || '') + '">' +
      escapeHtml(row.last_error || '--') + '</td></tr>')
    .data('upstream', row.upstream);
}

function _domainDetailRow(d) {
  return $('<tr class="domain-detail">' +
    '<td class="cell-mono domain-name">' + escapeHtml(d.host) + '</td>' +
    '<td class="domain-ok cell-num">' + d.success + '</td>' +
    '<td class="domain-fail cell-num">' + d.failure + '</td>' +
    '<td>' + d.total + '</td>' +
    '<td>' + _rateCell(d) + '</td>' +
    '<td class="cell-mono">' + escapeHtml(d.last_seen || '--') + '</td>' +
    '<td class="domain-reason" title="' + escapeHtml(d.last_error || '') + '">' +
      escapeHtml(d.last_error || '--') + '</td></tr>');
}

function toggleUpstreamRow(upstream) {
  if (_expandedUpstreams[upstream] !== undefined) {
    delete _expandedUpstreams[upstream];
    _renderDomainTable();
    return;
  }
  _expandedUpstreams[upstream] = 'loading';
  _renderDomainTable();
  $.ajax({
    url: appendToken('/api/logs/domains?limit=200&upstream=' + encodeURIComponent(upstream)),
    success: function (d) {
      _expandedUpstreams[upstream] = (d.status === 'success' && d.domains) ? d.domains : [];
      _renderDomainTable();
    },
    error: function () {
      _expandedUpstreams[upstream] = [];
      _renderDomainTable();
    }
  });
}

$(document).on('click', '.domain-row', function () {
  toggleUpstreamRow($(this).data('upstream'));
});

function clearDomainStats() {
  showConfirm(T().confirm_clear_title, T().confirm_clear_domains, function (ok) {
    if (!ok) return;
    $.ajax({
      url: appendToken('/api/logs/domains/clear'), method: 'POST',
      success: function (r) {
        if (r.status !== 'success') { toast(r.message || '', 'error'); return; }
        toast(r.message || T().domain_cleared, 'success');
        _expandedUpstreams = {};
        loadDomainStats();
      },
      error: function () { toast(T().clear_logs_failed, 'error'); }
    });
  }, { danger: true });
}


function checkVer() {
  onLangRender(checkVer);
  $.get(appendToken('/api/version'), function (d) {
    if (d.status === 'success') {
      $('#hdr-ver').text(d.current_version || 'ProxyCat');
      if (d.is_latest) $('#ver-stat').html('<span class="ver-ok"> ' + T().latest_version + '</span>');
      else $('#ver-stat').html('<span class="ver-new"> ' + T().new_version_available + ': ' + (d.latest_version || '') + '</span>');
    }
  });
}


var _ads = [];
var _adIndex = 0;
var _adCountdown = null;
var _adDismissed = false;

function loadAds() {
  onLangRender(loadAds);
  $.get(appendToken('/api/ads'), function (d) {
    if (d.status !== 'success' || !d.ads || !d.ads.length) return;
    _ads = d.ads;
    _adIndex = 0;
    _adDismissed = !!d.dismissed;
    if (_adDismissed) {
      showReopenBtn();
    } else {
      showAdBar();
      renderAdPair(0);
      startAdRotation();
    }
  }).fail(function () {
  });
}

function renderAdCard(slot, ad) {
  var s = String(slot);
  if (!ad) {
    $('#ad-card-' + s).hide();
    return;
  }
  $('#ad-card-' + s).show();
  $('#ad-title-' + s).text(ad.title || '');
  $('#ad-body-' + s).text(ad.body || '');

  if (ad.image_url) {
    $('#ad-img-' + s).attr('src', ad.image_url).show()
      .off('click').on('click', function (e) {
        e.stopPropagation();
        openImgLightbox(ad.image_url);
      });
  } else {
    $('#ad-img-' + s).hide().attr('src', '').off('click');
  }

  if (ad.link_url) {
    $('#ad-link-' + s).attr('href', ad.link_url).show();
    $('#ad-link-text-' + s).text(ad.link_text || T().ad_link_default);
  } else {
    $('#ad-link-' + s).hide();
  }
}

function renderAdPair(startIdx) {
  if (!_ads.length) return;
  _adIndex = startIdx;
  var left = _ads[startIdx] || null;
  var right = (_ads.length > startIdx + 1) ? _ads[startIdx + 1] : null;

  renderAdCard(0, left);
  renderAdCard(1, right);

  var totalPairs = Math.ceil(_ads.length / 2);
  if (totalPairs > 1) {
    var curPair = Math.floor(startIdx / 2);
    var dots = '';
    for (var i = 0; i < totalPairs; i++) {
      dots += '<span class="ad-dot' + (i === curPair ? ' active' : '') +
              '" data-index="' + (i * 2) + '"></span>';
    }
    $('#ad-pagination').html(dots).show();
    $('#ad-pagination .ad-dot').off('click').on('click', function () {
      var i = parseInt($(this).data('index'));
      if (i !== _adIndex) {
        resetAdCountdown();
        renderAdPair(i);
        startAdRotation();
      }
    });
  } else {
    $('#ad-pagination').empty().hide();
  }

  var dt = 15;
  if (left) dt = left.display_time || 15;
  if (right) dt = Math.max(dt, right.display_time || 15);
  updateAdTimer(dt);
}

function updateAdTimer(seconds) {
  $('#ad-timer').text(seconds + 's');
}

function startAdRotation() {
  resetAdCountdown();
  if (!_ads.length) return;
  var left = _ads[_adIndex] || null;
  var right = (_ads.length > _adIndex + 1) ? _ads[_adIndex + 1] : null;
  var remaining = 15;
  if (left) remaining = left.display_time || 15;
  if (right) remaining = Math.max(remaining, right.display_time || 15);
  _adCountdown = setInterval(function () {
    remaining--;
    if (remaining <= 0) {
      clearInterval(_adCountdown);
      var next = (_adIndex + 2) % _ads.length;
      renderAdPair(next);
      startAdRotation();
    } else {
      updateAdTimer(remaining);
    }
  }, 1000);
}

function resetAdCountdown() {
  clearInterval(_adCountdown);
}

function showAdBar() {
  $('#ad-bar').removeClass('hidden').show();
  $('#ad-reopen-btn').hide();
  _adDismissed = false;
  $.post(appendToken('/api/ads/reopen'));
}

function hideAdBar() {
  $('#ad-bar').addClass('hidden');
  setTimeout(function () {
    if (_adDismissed) {
      $('#ad-bar').hide();
      showReopenBtn();
    }
  }, 260);
}

function showReopenBtn() {
  $('#ad-reopen-btn').show();
}


function openImgLightbox(src) {
  if (!src) return;
  $('#img-lightbox-img').attr('src', src);
  $('#img-lightbox').addClass('show');
}

function closeImgLightbox() {
  $('#img-lightbox').removeClass('show');
}

$(document).on('keydown', function (e) {
  if (e.key === 'Escape' && $('#img-lightbox').hasClass('show')) {
    closeImgLightbox();
  }
});

function closeAd() {
  resetAdCountdown();
  _adDismissed = true;
  $.post(appendToken('/api/ads/dismiss'));
  hideAdBar();
}

function reopenAd() {
  if (!_ads.length) {
    loadAds();
    return;
  }
  _adIndex = 0;
  renderAdPair(0);
  showAdBar();
  startAdRotation();
}


function scrollToTop() {
  window.scrollTo({ top: 0, behavior: 'smooth' });
}


var POLL_FAIL_THRESHOLD = 3;
var _pollFailCount = 0;

function setConnBanner(lost) {
  var el = $('#conn-banner');
  if (!lost) {
    el.removeClass('show');
    return;
  }
  $('#conn-banner-text').text(T().conn_lost);
  el.addClass('show');
}

var _activeAjax = 0;

function syncGlobalProgress() {
  $('#global-progress').toggleClass('on', _activeAjax > 0);
}

function retryConnection() {
  _pollFailCount = 0;
  setConnBanner(false);
  updateStatusAndGauge();
  startGlobalPolling();
  if ($('#tab-pool').hasClass('show')) startPoolPolling();
  if ($('#tab-logs').hasClass('show')) _startLogRefresh();
}

$(function () {
  initTheme(); initLang(); loadConfig(); loadLocalProxies(); loadIpLists(); loadBypassWhitelist(); loadUsers(); checkVer(); initSidebar(); loadAds();

  restoreActiveView();
  if (typeof initFieldTips === 'function') initFieldTips();
  if (typeof initTableDensity === 'function') initTableDensity();
  if (typeof initProxyTableKeyboard === 'function') initProxyTableKeyboard();
  if (typeof initAccessRecordsTable === 'function') initAccessRecordsTable();
  if (typeof restoreActiveTasks === 'function') restoreActiveTasks();

  var $scrollBtn = $('#scroll-top-btn');
  $(window).on('scroll', function () {
    $scrollBtn.toggleClass('visible', window.scrollY > window.innerHeight * 0.6);
  });

  startGlobalPolling();

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      pauseGlobalPolling();
    } else {
      startGlobalPolling();
      if ($('#tab-logs').hasClass('show')) _startLogRefresh();
      if ($('#tab-pool').hasClass('show')) startPoolPolling();
    }
  });

  var _POLLED_PATHS = ['/api/status', '/api/logs', '/api/logs/stats',
                       '/api/logs/domains', '/api/logs/records',
                       '/api/pool/status'];
  function isBackgroundPoll(settings) {
    if (!settings || !settings.url) return false;
    var path = String(settings.url).split('?')[0];
    if (_POLLED_PATHS.indexOf(path) >= 0) return true;
    return /^\/api\/pool\/tasks\/[^/]+$/.test(path);
  }

  $(document).ajaxSend(function (event, xhr, settings) {
    if (isBackgroundPoll(settings)) return;
    _activeAjax++;
    syncGlobalProgress();
  });
  $(document).ajaxComplete(function (event, xhr, settings) {
    if (isBackgroundPoll(settings)) return;
    _activeAjax = Math.max(0, _activeAjax - 1);
    syncGlobalProgress();
  });
  $(document).ajaxError(function (event, xhr, settings) {
    if (isBackgroundPoll(settings)) {
      _pollFailCount++;
      if (_pollFailCount >= POLL_FAIL_THRESHOLD) setConnBanner(true);
      return;
    }
    var path = settings && settings.url ? String(settings.url).split('?')[0] : '';
    if (path.indexOf('/api/pool/') === 0 || path === '/api/users') return;
    var msg = T().request_failed + T().sep_colon + jqErrorText(xhr, T().network_error);
    toast(msg, 'error');
  });
  $(document).ajaxSuccess(function (event, xhr, settings) {
    if (!isBackgroundPoll(settings)) return;
    _pollFailCount = 0;
    setConnBanner(false);
  });

});
