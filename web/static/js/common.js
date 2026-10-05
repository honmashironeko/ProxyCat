/**
 * 模块名称：面板前端共享工具（web/static/js/common.js）
 * 功能描述：app.js / pool.js / proxies.js / tables.js / palette.js / i18n.js 共用的前端工具：HTML 转义、
 *   plainDoc 星号剥离、{} 占位符填充、时间与体积格式化、token 拼装、剪贴板兜底、localStorage 安全读写、
 *   轮询注册表、表格占位串与 sparklineSvg 迷你趋势线。
 * 职责边界：负责：与具体页面无关的纯工具与字符串生成；不负责：业务状态、接口请求、数据渲染与页面级反馈
 *   （toast、按钮 loading、弹窗），这些由 app.js / pool.js / proxies.js 等页面脚本负责。
 * 关键依赖：i18n.js 的 T()（fmtTime 的空值文案与 tableAlertHtml 的重试按钮文案）；无第三方组件与外部服务。
 *   加载顺序由 index.html 保证：jquery → i18n → common，common 排在其它页面脚本之前。
 * 已知限制：
 *   1. escapeHtml 把 null/undefined 映射为 ''，其余走 String()（0 得 "0"）；非幂等，同一份数据不得重复转义。
 *   2. getToken/appendToken 不做 encodeURIComponent，token 含 & / + 等字符时外发链接会损坏；外发链接的调用方须自行编码。
 *   3. 四个 safe 存储在 localStorage 不可用（隐私模式 / 配额 / 策略）时静默降级：读回 fallback、写返回 false，不抛出；新增读写必须走它们。
 *   4. copyViaTextarea 为剪贴板兜底：非安全上下文无 clipboard API、或 writeText 被拒时都会走它，成败均在 finally 移除 textarea。
 *   5. jqErrorText 取 message、非 0 status 的 statusText、fallback；收尾仍可能取 statusText，x.status 守卫不可删。
 *   6. plainDoc 用于字段文档展示前剥离双星号加粗标记，去掉剥离逻辑会让提示里露出星号。
 *   7. sparklineSvg 的 y 轴按数据自身取极值，只表达趋势形状；自身过滤 null/undefined/NaN，剩余点数不足 2 或全段同值返回空串。
 */

function escapeHtml(s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


function plainDoc(text) {
  return String(text === null || text === undefined ? '' : text).replace(/\*\*/g, '');
}


function getToken() {
  var p = new URLSearchParams(location.search);
  return p.get('token') || '';
}


var _pollers = {};

function startPolling(key, fn, ms) {
  stopPolling(key);
  _pollers[key] = setInterval(fn, ms);
}

function stopPolling(key) {
  if (_pollers[key]) {
    clearInterval(_pollers[key]);
    delete _pollers[key];
  }
}

function isPolling(key) {
  return !!_pollers[key];
}


function emptyRow(colspan, text, rowClass) {
  return '<tr' + (rowClass ? ' class="' + rowClass + '"' : '') +
    '><td colspan="' + colspan + '" class="empty-hint">' +
    escapeHtml(text) + '</td></tr>';
}


function skeletonRows(colspan, count) {
  var widths = ['skel-60', 'skel-45', 'skel-80', 'skel-30', 'skel-100'];
  var out = '';
  for (var i = 0; i < count; i++) {
    out += '<tr class="skel-row" aria-hidden="true">';
    for (var c = 0; c < colspan; c++) {
      out += '<td><span class="skel ' + widths[(i + c) % widths.length] + '"></span></td>';
    }
    out += '</tr>';
  }
  return out;
}


function tableAlertHtml(colspan, text, retryKey) {
  return '<tr class="tbl-alert"><td colspan="' + colspan + '">' +
    '<div class="tbl-alert-in">' +
      '<i class="fa fa-exclamation-triangle"></i>' +
      '<span class="tbl-alert-text">' + escapeHtml(text) + '</span>' +
      '<button class="btn xs" data-retry="' + escapeHtml(retryKey || '') + '">' +
        escapeHtml(T().conn_retry) + '</button>' +
    '</div></td></tr>';
}


function skeletonBlock(rows) {
  var widths = ['skel-60', 'skel-45', 'skel-80', 'skel-30', 'skel-100'];
  var out = '<div class="skel-block" aria-hidden="true">';
  for (var i = 0; i < (rows || 3); i++) {
    out += '<span class="skel ' + widths[i % widths.length] + '"></span>';
  }
  return out + '</div>';
}

function appendToken(u) {
  var t = getToken();
  return t ? u + (u.indexOf('?') >= 0 ? '&' : '?') + 'token=' + t : u;
}


function fillTemplate(text) {
  var out = String(text || '');
  for (var i = 1; i < arguments.length; i++) {
    out = out.replace('{}', arguments[i]);
  }
  return out;
}


function fmtTime(iso) {
  if (!iso) return T().never_run;
  var d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '';
  var s = Math.max(0, Math.round(seconds));
  if (s < 60) return s + 's';
  var m = Math.floor(s / 60);
  var rest = s % 60;
  if (m < 60) return m + 'm' + (rest ? ' ' + rest + 's' : '');
  return Math.floor(m / 60) + 'h' + (m % 60 ? ' ' + (m % 60) + 'm' : '');
}

function fmtLogSize(bytes) {
  var n = Number(bytes) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}


function copyViaTextarea(text) {
  var area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.cssText = 'position:fixed;top:-1000px;left:0;opacity:0';

  document.body.appendChild(area);
  var copied = false;
  try {
    area.select();
    copied = document.execCommand('copy');
  } catch (e) {
    copied = false;
  } finally {
    document.body.removeChild(area);
  }
  return copied;
}


function safeGetItem(key, fallback) {
  if (fallback === undefined) fallback = null;
  try {
    var v = localStorage.getItem(key);
    return v === null || v === undefined ? fallback : v;
  } catch (e) {
    return fallback;
  }
}

function safeSetItem(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (e) {
    return false;
  }
}

function safeGetJSON(key, fallback) {
  var raw = safeGetItem(key, null);
  if (raw === null) return fallback;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

function safeSetJSON(key, value) {
  try {
    var raw = JSON.stringify(value);
    if (raw === undefined) return false;
    localStorage.setItem(key, raw);
    return true;
  } catch (e) {
    return false;
  }
}


function sparklineSvg(values, opts) {
  var o = opts || {};
  var width = o.width || 68;
  var height = o.height || 22;
  var points = (values || []).filter(function (v) {
    return v !== null && v !== undefined && !isNaN(v);
  });
  if (points.length < 2) return '';

  var min = Math.min.apply(null, points);
  var max = Math.max.apply(null, points);
  if (max === min) return '';
  var span = max - min;
  var step = width / (points.length - 1);

  var poly = points.map(function (v, i) {
    return (i * step).toFixed(1) + ',' + (height - ((v - min) / span) * height).toFixed(1);
  }).join(' ');

  return '<svg class="spark" viewBox="0 0 ' + width + ' ' + height + '" ' +
    'width="' + width + '" height="' + height + '" preserveAspectRatio="none" ' +
    'aria-hidden="true">' +
    '<polyline points="' + poly + '" fill="none" stroke="currentColor" ' +
    'stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/></svg>';
}


function jqErrorText(x, fallback) {
  var r = x && x.responseJSON;
  if (r && r.message) return r.message;
  if (x && x.status && x.statusText) return x.statusText;
  if (fallback) return fallback;
  return (x && x.statusText) || '';
}
