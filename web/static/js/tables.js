/**
 * 模块名称：浮层与表格增强组件（tables.js）
 * 功能描述：与具体页面无关的浮层与表格增强：行详情抽屉、右键菜单、说明气泡、表格漫游键盘，以及加载中／加载失败占位。
 * 职责边界：负责：浮层的摆放与键盘交互、表格占位渲染、说明气泡的可键盘化；
 *           不负责：取数、业务字段与表格的筛选排序分页、选中语义，由 proxies.js 与 app.js 负责。
 * 关键依赖：jQuery；common.js 的 escapeHtml、skeletonRows、tableAlertHtml；i18n.js 的 T()、onLangRender；
 *           app.js 的 _overlayOpen、_overlayClosed；palette.js 的 isCommandPaletteOpen；index.html 的
 *           #row-drawer、#drawer-scrim、#ctx-menu、#tip-pop 容器。
 * 已知限制：
 *           1. 抽屉、右键菜单、说明气泡均为单例，开新的会顶掉旧的，不排队、不叠加。
 *           2. 说明气泡的文案现读现用；显示期间原生 title 被摘走，此时别处读 title 会读到空。
 *           3. fields 的 value 一律按纯文本转义，html 字段由调用方保证已转义，两者都写时 html 优先。
 *           4. 判断字段是否为空的口径在 drawerSections 与 openRowDrawer 两处必须一致，只给 html 的字段不能被当成空值。
 *           5. 骨架行只在表格没有真实行时铺；键盘漫游只认 tr[data-id]，失败提示行不参与。
 *           6. 抽屉不锁 body 滚动；抽屉的 Esc 让给命令面板与右键菜单，右键菜单与说明气泡不避让上层，一次 Esc 可能关掉多层。
 *           7. 右键菜单要先加 show 再量尺寸：display: none 时 outerWidth/Height 为 0，越界翻转失效。
 */
var _ctxFocus = -1;

function drawerSections(groups) {
  var out = [];
  (groups || []).forEach(function (entry) {
    var kept = (entry[1] || []).filter(function (f) {
      return f.html !== undefined ||
        (f.value !== undefined && f.value !== null && f.value !== '');
    });
    if (!kept.length) return;
    out.push({ section: entry[0] });
    out = out.concat(kept);
  });
  return out;
}

function openRowDrawer(spec) {
  var s = spec || {};

  $('#drawer-title').text(s.title || '');
  $('#drawer-sub').text(s.subtitle || '').toggle(!!s.subtitle);

  var body = $('#drawer-body').empty();
  (s.fields || []).forEach(function (f) {
    if (f.section !== undefined) {
      body.append($('<div class="drawer-section"></div>').text(f.section));
      return;
    }
    if (f.html === undefined &&
        (f.value === undefined || f.value === null || f.value === '')) return;
    var inner = f.html !== undefined ? f.html : escapeHtml(f.value) + (f.suffix || '');
    var cls = 'drawer-val' + (f.mono ? ' mono' : '') + (f.copy ? ' copyable' : '');
    var val = $('<div></div>').attr('class', cls).html(inner);
    if (f.copy) val.attr('data-copy', f.value).attr('title', T().click_to_copy);
    body.append(
      $('<div class="drawer-field"></div>')
        .append($('<span class="drawer-label"></span>').text(f.label || ''))
        .append(val));
  });

  var ft = $('#drawer-ft').empty();
  var actions = s.actions || [];
  actions.forEach(function (a) {
    var btn = $('<button></button>')
      .attr('class', 'btn sm' + (a.danger ? ' bad' : ''))
      .html('<i class="fa ' + (a.icon || 'fa-angle-right') + '"></i> ' + escapeHtml(a.label));
    btn.on('click', function () {
      closeRowDrawer();
      if (a.onClick) a.onClick();
    });
    ft.append(btn);
  });
  ft.toggle(actions.length > 0);

  $('#drawer-scrim').addClass('show');
  $('#row-drawer').addClass('show');
  if (typeof _overlayOpen === 'function') _overlayOpen('#row-drawer', $('#row-drawer .icon-btn'), false);
}

function closeRowDrawer() {
  $('#row-drawer').removeClass('show');
  $('#drawer-scrim').removeClass('show');
  if (typeof _overlayClosed === 'function') _overlayClosed();
}

$(document).on('keydown', function (e) {
  if (e.key !== 'Escape') return;
  if (typeof isCommandPaletteOpen === 'function' && isCommandPaletteOpen()) return;
  if (isContextMenuOpen()) return;
  if ($('#row-drawer').hasClass('show')) closeRowDrawer();
});

function openContextMenu(x, y, items) {
  var menu = $('#ctx-menu').empty();
  _ctxFocus = -1;

  (items || []).forEach(function (it) {
    if (!it) return;
    if (it.separator) { menu.append('<div class="ctx-sep"></div>'); return; }
    var btn = $('<button></button>')
      .attr('class', 'ctx-item' + (it.danger ? ' danger' : ''))
      .html('<i class="fa ' + (it.icon || 'fa-angle-right') + '"></i> ' + escapeHtml(it.label));
    btn.on('click', function () {
      closeContextMenu();
      if (it.onClick) it.onClick();
    });
    menu.append(btn);
  });

  menu.addClass('show');
  var w = menu.outerWidth(), h = menu.outerHeight();
  var left = x, top = y;
  if (left + w > window.innerWidth - 8) left = x - w;
  if (top + h > window.innerHeight - 8) top = y - h;
  menu.css({
    left: Math.max(8, left) + 'px',
    top: Math.max(8, top) + 'px'
  });
}

function closeContextMenu() {
  $('#ctx-menu').removeClass('show').empty();
  _ctxFocus = -1;
}

function isContextMenuOpen() {
  return $('#ctx-menu').hasClass('show');
}

function moveContextFocus(delta) {
  var items = $('#ctx-menu .ctx-item');
  if (!items.length) return;
  _ctxFocus = (_ctxFocus + delta + items.length) % items.length;
  items.removeClass('focus').eq(_ctxFocus).addClass('focus');
}

$(document).on('keydown', function (e) {
  if (!isContextMenuOpen()) return;
  if (e.key === 'Escape') { closeContextMenu(); e.stopPropagation(); return; }
  if (e.key === 'ArrowDown') { moveContextFocus(1); e.preventDefault(); return; }
  if (e.key === 'ArrowUp') { moveContextFocus(-1); e.preventDefault(); return; }
  if (e.key === 'Enter') {
    var focused = $('#ctx-menu .ctx-item.focus');
    if (focused.length) { focused.trigger('click'); e.preventDefault(); }
  }
});

$(document).on('mousedown', function (e) {
  if (isContextMenuOpen() && !$(e.target).closest('#ctx-menu').length) closeContextMenu();
});

function attachTableKeyboard(table, handlers) {
  var $t = $(table);
  if (!$t.length) return;

  var h = handlers || {};
  $t.attr('tabindex', '0');

  function rows() {
    return $t.find('tbody tr[data-id]');
  }

  function focusRow(index) {
    var list = rows();
    if (!list.length) return -1;
    var i = Math.min(list.length - 1, Math.max(0, index));
    list.removeClass('row-focus').eq(i).addClass('row-focus');
    list[i].scrollIntoView({ block: 'nearest' });
    return i;
  }

  function focusedIndex() {
    var list = rows();
    return list.index(list.filter('.row-focus'));
  }

  $t.on('keydown', function (e) {
    if (e.target !== this) return;
    var list = rows();
    if (!list.length) return;
    var cur = focusedIndex();

    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      var next = focusRow(cur < 0
        ? (e.key === 'ArrowDown' ? 0 : list.length - 1)
        : cur + (e.key === 'ArrowDown' ? 1 : -1));
      if (e.shiftKey && h.onExtend) h.onExtend(next);
      return;
    }
    if (e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      if (cur >= 0 && h.onToggle) h.onToggle(cur);
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      if (h.onSelectAll) h.onSelectAll();
      return;
    }
    if (e.key === 'Enter') {
      if (cur >= 0 && h.onActivate) { e.preventDefault(); h.onActivate(cur); }
      return;
    }
    if (e.key === 'Escape') {
      $t.find('tbody tr').removeClass('row-focus');
      if (h.onClear) h.onClear();
    }
  });

  $t.on('click', 'tbody tr[data-id]', function () {
    $t.find('tbody tr').removeClass('row-focus');
    $(this).addClass('row-focus');
  });
}


var _tableRetries = {};

function registerTableRetry(key, fn) { _tableRetries[key] = fn; }

$(document).on('click', '[data-retry]', function () {
  var fn = _tableRetries[$(this).attr('data-retry')];
  if (fn) fn();
});

function _tableHasData($tbody) {
  return $tbody.children('tr').not('.skel-row, .tbl-alert').length > 0;
}

function beginTableLoad(tbody, colspan, rows) {
  var $t = $(tbody);
  if (!$t.length || _tableHasData($t) || $t.find('tr.skel-row').length) return;
  $t.html(skeletonRows(colspan, rows || 6));
}

function showTableAlert(tbody, colspan, text, retryKey) {
  var $t = $(tbody);
  if (!$t.length) return;
  $t.children('tr').filter(function () {
    return $(this).hasClass('skel-row') || $(this).hasClass('tbl-alert') ||
           $(this).find('td.empty-hint').length > 0;
  }).remove();
  $t.prepend(tableAlertHtml(colspan, text, retryKey));
}

function clearTableAlert(tbody) {
  $(tbody).find('tr.tbl-alert').remove();
}


var TIP_SHOW_DELAY = 380;
var TIP_HIDE_DELAY = 140;

var _tipTarget = null;
var _tipShown = false;
var _tipShowTimer = null;
var _tipHideTimer = null;

function _tipElement() {
  var el = document.getElementById('tip-pop');
  if (!el) {
    el = document.createElement('div');
    el.className = 'tip-pop';
    el.id = 'tip-pop';
    el.setAttribute('role', 'tooltip');
    document.body.appendChild(el);
  }
  return el;
}

function _tipTextOf(el) {
  var text = el.getAttribute('data-tip');
  if (text === null) text = el.getAttribute('title');
  return text === null ? '' : text;
}

function _tipTrigger(node) {
  if (!node || node.nodeType !== 1 || !node.closest) return null;
  if (node.closest('#tip-pop')) return null;
  var el = node.closest('[data-tip], [title]');
  if (!el) return null;
  return _tipTextOf(el) ? el : null;
}

function _tipPlace(el, pop) {
  var rect = el.getBoundingClientRect();
  var w = pop.offsetWidth, h = pop.offsetHeight;
  var gap = 10;
  var left = rect.left + rect.width / 2 - w / 2;
  var top = rect.bottom + gap;
  if (top + h > window.innerHeight - 8 && rect.top - gap - h > 8) top = rect.top - gap - h;
  left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
  top = Math.max(8, Math.min(top, window.innerHeight - h - 8));
  pop.style.left = Math.round(left) + 'px';
  pop.style.top = Math.round(top) + 'px';
}

function _tipOpen(el) {
  var text = _tipTextOf(el);
  if (!text || !document.body.contains(el)) return;
  if (el.hasAttribute('title')) {
    el.setAttribute('data-tip-stash', el.getAttribute('title'));
    el.removeAttribute('title');
  }
  var pop = _tipElement();
  pop.textContent = text;
  pop.classList.add('show');
  _tipPlace(el, pop);
  _tipShown = true;
}

function _tipClose() {
  var el = _tipTarget;
  if (!el) return;
  var pop = document.getElementById('tip-pop');
  if (pop) pop.classList.remove('show');
  if (el.hasAttribute('data-tip-stash') && !el.hasAttribute('title')) {
    el.setAttribute('title', el.getAttribute('data-tip-stash'));
  }
  el.removeAttribute('data-tip-stash');
  _tipTarget = null;
  _tipShown = false;
}

function hideTip() {
  clearTimeout(_tipShowTimer);
  clearTimeout(_tipHideTimer);
  _tipShowTimer = null;
  _tipHideTimer = null;
  _tipClose();
}

function _tipScheduleShow(el, delay) {
  _tipTarget = el;
  clearTimeout(_tipShowTimer);
  _tipShowTimer = setTimeout(function () {
    _tipShowTimer = null;
    if (_tipTarget === el) _tipOpen(el);
  }, delay);
}

$(document).on('mouseover', function (e) {
  var el = _tipTrigger(e.target);
  if (el && el === _tipTarget) { clearTimeout(_tipHideTimer); _tipHideTimer = null; return; }
  if (!el) return;
  hideTip();
  _tipScheduleShow(el, TIP_SHOW_DELAY);
});

$(document).on('mouseover', '#tip-pop', function () {
  clearTimeout(_tipHideTimer);
  _tipHideTimer = null;
});

$(document).on('mouseout', function (e) {
  if (!_tipTarget) return;
  var to = e.relatedTarget;
  if (to && _tipTarget.contains(to)) return;
  if (to && to.closest && to.closest('#tip-pop')) return;
  clearTimeout(_tipShowTimer);
  _tipShowTimer = null;
  clearTimeout(_tipHideTimer);
  _tipHideTimer = setTimeout(hideTip, TIP_HIDE_DELAY);
});

$(document).on('focusin', function (e) {
  var el = _tipTrigger(e.target);
  if (!el || el === _tipTarget) return;
  hideTip();
  _tipScheduleShow(el, 0);
});

$(document).on('focusout', function (e) {
  if (_tipTarget && e.target === _tipTarget) hideTip();
});

$(window).on('scroll resize', hideTip);
$(document).on('mousedown', hideTip);

$(document).on('keydown', function (e) {
  if (e.key === 'Escape' && _tipShown) hideTip();
});

function refreshFieldTips() {
  $('.fg-tip').each(function () {
    var text = this.getAttribute('title') || this.getAttribute('data-tip') || '';
    if (text) this.setAttribute('aria-label', text);
  });
}

function initFieldTips() {
  $('.fg-tip').each(function () {
    this.removeAttribute('aria-hidden');
    if (!this.hasAttribute('tabindex')) this.setAttribute('tabindex', '0');
  });
  refreshFieldTips();
  onLangRender(refreshFieldTips);
}
