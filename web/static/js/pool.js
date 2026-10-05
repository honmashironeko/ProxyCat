/**
 * 模块名称：代理池管理页（pool.js）
 * 功能描述：代理池页签的全部前端行为：池状态与启停按钮门控、概览卡与内存趋势线、抓取插件管理、
 *           批量任务提交与进度跟踪、schema 驱动的池参数表单、导入导出、数据库与归属地维护。
 * 职责边界：负责：池自身接口的调用与渲染、启停按钮的禁用门控；不负责：池启停请求的实现
 *           （app.js 的 controlPool）、代理列表的筛选排序分页与批量选择（proxies.js）、面板外壳与配置页、日志页（app.js）。
 * 关键依赖：common.js 的请求、存储、格式化、轮询与渲染工具；tables.js 的表格加载/重试/提示；
 *           app.js 的 toast、btnLoad、弹窗、controlPool、配置页共享组件与视图切换；
 *           i18n.js 的 T、onLangRender；proxies.js 的 loadProxies、collectFilterParams、
 *           updateSelectionUI、totalCount；jQuery。
 * 已知限制：
 *           1. POOL_TRUE_WORDS 与后端 modules.TRUE_WORDS 是同一份词表，修改需两边同步。
 *           2. 池表单重绘会覆盖未保存的编辑，需过 poolFormDirty() 守卫；保存只提交与基线不同的键。
 *           3. 池相关控件靠 data-requires-pool 统一禁用，新加的行内控件必须带该属性。
 *           4. poolErrorText 特化 503/504、status 0 视为网络错误，不能与 jqErrorText 合并。
 *           5. 归属地下载任务 progress/total 是字节、重算任务是 IP 条数，均走独立渲染，不能并入批量任务区。
 *           6. 带 visible_when 的字段不得折进高级区，折叠会让用户看不到已启用功能的从属阈值。
 *           7. .settings-nav-item 被代理配置页复用，池页选择器必须限定在 #pool-settings-nav 内。
 *           8. 全部函数为全局作用域，与 app.js / proxies.js 重名会静默覆盖。
 */

var _poolSchema = null;
var _pluginRows = {};
var _activeTasks = {};

var POOL_TASK_POLL_MS = 2000;
var POOL_STATUS_POLL_MS = 5000;

var _poolRunning = false;

function setPoolRunning(running) {
  _poolRunning = running;
  $('#tab-pool [data-requires-pool]').prop('disabled', !running);
  $('#pool-ctl-dot').attr('class', 'dot ' + (running ? 'on' : 'off'));
  $('#pool-ctl-text').text(T().service_status[running ? 'running' : 'stopped'] || (running ? 'running' : 'stopped'));
  $('#pool-start').prop('disabled', running);
  $('#pool-stop').prop('disabled', !running);
  if (typeof updateSelectionUI === 'function') updateSelectionUI();
  syncGeoControls();
}

function poolReady() { return _poolRunning; }


function poolRequest(method, path, body, onOk, opts) {
  var o = opts || {};
  var settings = { url: appendToken('/api/pool/' + path), method: method };
  if (body !== null && body !== undefined) {
    settings.contentType = 'application/json';
    settings.data = JSON.stringify(body);
  }
  return $.ajax(settings)
    .done(function (r) { if (onOk) onOk(r); })
    .fail(function (x) {
      if (o.silent) return;
      toast(poolErrorText(x), 'error');
    });
}

function poolErrorText(x) {
  if (x && (x.status === 503 || x.status === 504)) {
    var m = x.responseJSON && x.responseJSON.message;
    if (m) return m;
    return x.status === 503 ? T().pool_unavailable_hint : T().pool_timeout_hint;
  }
  if (x && !x.status) return T().network_error;
  return jqErrorText(x, fillTemplate(T().operation_failed, (x && x.status) || ''));
}


function startPoolPolling() {
  stopPoolPolling();
  updatePoolStatus();
  loadHostIp();
  startPolling('pool', updatePoolStatus, POOL_STATUS_POLL_MS);
}

function stopPoolPolling() {
  stopPolling('pool');
}

function updatePoolStatus() {
  onLangRender(updatePoolStatus);
  $.get(appendToken('/api/pool/status'))
    .done(function (d) {
      var wasRunning = _poolRunning;
      setPoolRunning(!!d.is_running);
      renderPoolStats(d.stats);
      showPoolNotice(d.is_running, d.last_error);
      if (!wasRunning && d.is_running && $('#tab-pool').hasClass('show')) {
        loadPlugins();
        loadSources();
        loadProxies();
        loadDbMaintain();
      }
    })
    .fail(function () {
      setPoolRunning(false);
      renderPoolStats(null);
    });
}

var _poolStatsHistory = [];
var POOL_STATS_HISTORY_MAX = 24;

function renderPoolStats(stats) {
  if (!stats) {
    $('#st-total, #st-valid, #st-invalid, #st-rate').text('--');
    $('#st-rate').closest('.stat-card').removeClass('ok warn bad');
    $('#st-invalid').closest('.stat-card').removeClass('bad');
    $('#st-total-spark, #st-valid-spark, #st-rate-spark').empty();
    $('#stats-fallback-hint').hide();
    return;
  }
  var total = stats.total_proxies || 0;
  var valid = stats.valid_proxies || 0;
  var rate = total > 0 ? (valid / total) * 100 : null;

  $('#st-total').text(total);
  $('#st-valid').text(valid);
  var invalid = stats.invalid_proxies || 0;
  $('#st-invalid').text(invalid);
  $('#st-rate').text(rate === null ? '--' : Math.round(rate) + '%');
  $('#st-rate').closest('.stat-card').removeClass('ok warn bad')
    .addClass(rate === null ? '' : (rate >= 70 ? 'ok' : (rate >= 30 ? 'warn' : 'bad')));
  $('#st-invalid').closest('.stat-card').toggleClass('bad', invalid > 0);

  _poolStatsHistory.push({ total: total, valid: valid, rate: rate });
  if (_poolStatsHistory.length > POOL_STATS_HISTORY_MAX) _poolStatsHistory.shift();
  _renderPoolSparks();

  var fallback = stats.anonymity_fallback_proxies || 0;
  $('#stats-fallback-text').text(fillTemplate(T().anonymity_fallback_hint, fallback));
  $('#stats-fallback-hint').toggle(fallback > 0);
}

function _renderPoolSparks() {
  var h = _poolStatsHistory;
  $('#st-total-spark').html(sparklineSvg(h.map(function (s) { return s.total; })));
  $('#st-valid-spark').html(sparklineSvg(h.map(function (s) { return s.valid; })));
  $('#st-rate-spark').html(sparklineSvg(h.map(function (s) { return s.rate; })));
}

function loadHostIp() {
  onLangRender(loadHostIp);
  $.ajax({
    url: appendToken('/api/pool/host-ip'),
    success: function (d) {
      var hint = $('#host-ip-hint');
      if (!d || !d.check_anonymity) {
        hint.hide();
        return;
      }

      var v4 = d.host_public_ipv4 || '';
      var v6 = d.host_public_ipv6 || '';
      var primary = v4 || v6 || d.host_public_ip || '';
      var srcLabel = d.source === 'configured' ? T().host_ip_manual : T().host_ip_auto;

      var missing = !primary;
      $('#host-ip-text').text(missing ? T().host_ip_missing
        : (v4 && v6 ? fillTemplate(T().host_ip_line_dual, v4, srcLabel, v6)
                    : fillTemplate(T().host_ip_line, primary, srcLabel)));
      hint.toggleClass('notice-warn', missing);
      hint.find('i').attr('class', 'fa ' + (missing ? 'fa-exclamation-triangle' : 'fa-info-circle'));
      hint.show();
    },
    error: function () { $('#host-ip-hint').hide(); }
  });
}

function showPoolNotice(running, lastError) {
  var box = $('#pool-notice');
  if (running) { box.hide(); return; }

  var text = lastError
    ? T().pool_start_failed + T().sep_colon + lastError
    : T().pool_stopped_hint;
  $('#pool-notice-text').text(text);
  box.show();
}


function loadPlugins() {
  onLangRender(loadPlugins);
  var btn = $('#btn-reload-plugins');
  btnLoad(btn, true);

  beginTableLoad('#plugin-tbody', 7, 4);

  $.ajax({ url: appendToken('/api/pool/plugins'), timeout: 15000 })
    .done(function (plugins) {
      clearTableAlert('#plugin-tbody');
      renderPluginTable(plugins || []);
    })
    .fail(function (x) {
      showTableAlert('#plugin-tbody', 7,
        poolErrorText(x) + T().sep_mid + T().stale_data_note, 'plugins');
    })
    .always(function () {
      btnLoad(btn, false);
    });
}

registerTableRetry('plugins', loadPlugins);

function renderPluginTable(plugins) {
  var tbody = $('#plugin-tbody');
  tbody.empty();
  $('#plugin-count').text(plugins.length + ' ' + T().items_unit).toggle(plugins.length > 0);

  _pluginRows = {};
  plugins.forEach(function (p) { _pluginRows[p.name] = p; });

  if (!plugins.length) {
    tbody.append(emptyRow(7, T().no_plugins));
    return;
  }

  var attrs = ' data-requires-pool' + (poolReady() ? '' : ' disabled');

  plugins.forEach(function (p) {
    var name = escapeHtml(p.name);

    tbody.append(
      '<tr data-plugin="' + name + '">' +
        '<td><div class="plugin-name"><i class="fa fa-plug"></i>' + name + '</div>' +
          (p.last_error ? '<div class="plugin-sub">' + escapeHtml(p.last_error) + '</div>' : '') +
        '</td>' +
        '<td><label class="chk-inline switch">' +
          '<input type="checkbox" data-act="plugin-toggle"' + (p.enabled ? ' checked' : '') + attrs + '>' +
          '<span>' + (p.enabled ? escapeHtml(T().plugin_enabled) : escapeHtml(T().plugin_disabled)) + '</span>' +
        '</label></td>' +
        '<td><button class="icon-btn" data-act="plugin-interval" title="' +
          escapeHtml(T().plugin_set_interval) + '" data-minutes="' + (p.interval_minutes || 60) + '"' + attrs + '>' +
          (p.interval_minutes || 0) + ' ' + escapeHtml(T().minutes_unit) +
          ' <i class="fa fa-pencil"></i></button></td>' +
        '<td class="cell-mono">' + escapeHtml(fmtTime(p.last_run)) + '</td>' +
        '<td class="cell-mono">' +
          escapeHtml(p.enabled && p.next_run ? fmtTime(p.next_run) : '--') + '</td>' +
        '<td><button class="icon-btn" data-act="plugin-validation" title="' +
          escapeHtml(T().plugin_settings_title) + '"' + attrs + '>' +
          escapeHtml(_pluginValidationText(p)) +
          ' <i class="fa fa-pencil"></i></button></td>' +
        '<td><div class="plugin-actions">' +
          '<button class="btn sm" data-act="plugin-run"' + attrs + '>' +
            '<i class="fa fa-bolt"></i> ' + escapeHtml(T().plugin_run_btn) + '</button>' +
          '<button class="btn sm' + (p.test_url ? ' pri' : '') + '" data-act="plugin-test-url"' +
            ' data-url="' + escapeHtml(p.test_url || '') + '"' + attrs + '>' +
            '<i class="fa fa-crosshairs"></i> ' +
            escapeHtml(p.test_url ? T().plugin_test_url_custom : T().plugin_test_url_global) +
          '</button>' +
          '<button class="btn sm" data-act="plugin-reload"' + attrs + '>' +
            '<i class="fa fa-refresh"></i> ' + escapeHtml(T().plugin_reload_btn) + '</button>' +
        '</div></td>' +
      '</tr>');
  });
}

function _pluginValidationText(p) {
  var prefix = p.skip_validation ? T().plugin_skip_validation_tag + ' · ' : '';
  if (!p.reval_enabled) return prefix + T().plugin_reval_off;
  if (p.reval_interval_minutes > 0) {
    return prefix + p.reval_interval_minutes + ' ' + T().minutes_unit;
  }
  return prefix + T().plugin_reval_inherit;
}

function openPluginSettingsModal(name, plugin) {
  $('#plugin-settings-name').text(name);
  $('#plugin-reval-enabled').prop('checked', plugin.reval_enabled !== false);
  $('#plugin-reval-interval').val(plugin.reval_interval_minutes || 0);
  $('#plugin-skip-validation').prop('checked', plugin.skip_validation === true);
  openModal('plugin-settings-modal');
}

function closePluginSettingsModal() { closeModal('plugin-settings-modal'); }

function savePluginSettings() {
  var name = $('#plugin-settings-name').text();
  var minutes = parseInt($('#plugin-reval-interval').val(), 10);
  if (isNaN(minutes) || minutes < 0) {
    toast(T().invalid_minutes, 'error');
    return;
  }

  var btn = $('#btn-plugin-settings-save');
  btnLoad(btn, true);
  poolRequest('PUT', 'plugins/' + encodeURIComponent(name) + '/validation', {
    reval_enabled: $('#plugin-reval-enabled').prop('checked'),
    reval_interval_minutes: minutes,
    skip_validation: $('#plugin-skip-validation').prop('checked')
  }, function (r) {
    toast(r.message || '', 'success');
    closePluginSettingsModal();
    loadPlugins();
  }).always(function () { btnLoad(btn, false); });
}

function togglePlugin(name, enabled, el) {
  var $box = $(el).prop('disabled', true);
  poolRequest('POST', 'plugins/' + encodeURIComponent(name) + '/' + (enabled ? 'enable' : 'disable'), null,
    function (r) {
      if (r.success === false) { toast(r.message, 'error'); restorePluginToggle($box, enabled); return; }
      toast(r.message, 'success');
      loadPlugins();
    },
    { silent: false })
    .fail(function () { restorePluginToggle($box, enabled); });
}

function restorePluginToggle($box, attempted) {
  $box.prop('checked', !attempted).prop('disabled', false);
  $box.siblings('span').text(!attempted ? T().plugin_enabled : T().plugin_disabled);
}

function setPluginInterval(name, current) {
  showModal({
    title: T().plugin_set_interval,
    body: T().plugin_interval_hint,
    input: true, value: current, showCancel: true,
    callback: function (val) {
      if (val === null) return;
      var minutes = parseInt(val, 10);
      if (!minutes || minutes < 1) { toast(T().invalid_minutes, 'error'); return; }
      poolRequest('PUT', 'plugins/' + encodeURIComponent(name) + '/interval', { minutes: minutes },
        function (r) { toast(r.message, 'success'); loadPlugins(); });
    }
  });
}

function setPluginTestUrl(name, current) {
  showModal({
    title: T().plugin_set_test_url,
    body: T().plugin_test_url_hint,
    input: true, value: current, showCancel: true,
    callback: function (val) {
      if (val === null) return;
      poolRequest('PUT', 'plugins/' + encodeURIComponent(name) + '/test-url', { test_url: (val || '').trim() },
        function (r) { toast(r.message, 'success'); loadPlugins(); });
    }
  });
}

function runPlugin(name, btn) {
  btnLoad(btn, true);
  poolRequest('POST', 'plugins/' + encodeURIComponent(name) + '/run', null, function (r) {
    if (r.task_id) trackTask(r.task_id, fillTemplate(T().task_plugin_run, name));
  }).always(function () { btnLoad(btn, false); });
}

function reloadPlugin(name, btn) {
  btnLoad(btn, true);
  poolRequest('POST', 'plugins/' + encodeURIComponent(name) + '/reload', null, function (r) {
    toast(r.message, r.success === false ? 'error' : 'success');
    if (r.success) loadPlugins();
  }).always(function () { btnLoad(btn, false); });
}


function validateAllProxies(onlyValid) {
  var path = onlyValid ? 'validate/all-valid' : 'validate/all-invalid';
  var label = onlyValid ? T().task_validate_valid : T().task_validate_invalid;
  startBatchTask(path, label, onlyValid ? $('#btn-validate-valid') : $('#btn-validate-invalid'));
}

function updateAllGeo() {
  startBatchTask('update-geo/all', T().task_full_check, $('#btn-full-check'));
}

function startBatchTask(path, label, btn) {
  var b = btn && btn.length ? btn : $();
  btnLoad(b, true);
  poolRequest('POST', path, null, function (r) {
    toast(r.message, r.success === false ? 'error' : 'success');
    if (r.task_id) trackTask(r.task_id, label);
  }).always(function () { btnLoad(b, false); });
}

var TASK_STORAGE_KEY = 'proxycat-active-tasks';

function trackTask(taskId, label) {
  _activeTasks[taskId] = { label: label || T().task_running };
  _persistTasks();
  renderTasks();
  if (!isPolling('task')) {
    startPolling('task', pollTasks, POOL_TASK_POLL_MS);
  }
  pollTasks();
}

function _persistTasks() {
  safeSetJSON(TASK_STORAGE_KEY, _activeTasks);
}

function removeSavedTask(id) {
  var saved = safeGetJSON(TASK_STORAGE_KEY, null) || {};
  if (saved[id] !== undefined) {
    delete saved[id];
    safeSetJSON(TASK_STORAGE_KEY, saved);
  }
}

function restoreActiveTasks() {
  var saved = safeGetJSON(TASK_STORAGE_KEY, null);
  if (!saved || typeof saved !== 'object') return;

  Object.keys(saved).forEach(function (id) {
    $.get(appendToken('/api/pool/tasks/' + id))
      .done(function (task) {
        if (task.status === 'running' || task.status === 'queued') {
          trackTask(id, saved[id].label || T().task_running);
        } else {
          removeSavedTask(id);
        }
      })
      .fail(function () { removeSavedTask(id); });
  });
}

function pollTasks() {
  var ids = Object.keys(_activeTasks);
  if (!ids.length) {
    stopPolling('task');
    return;
  }

  ids.forEach(function (id) {
    $.get(appendToken('/api/pool/tasks/' + id))
      .done(function (d) { onTaskUpdate(id, d); })
      .fail(function () {
        delete _activeTasks[id];
        removeSavedTask(id);
        renderTasks();
      });
  });
}

function onTaskUpdate(id, task) {
  var entry = _activeTasks[id];
  if (!entry) return;

  entry.status = task.status;
  entry.progress = task.progress || 0;
  entry.total = task.total || 0;
  entry.message = task.message || '';
  entry.stage = task.stage || '';
  entry.stageDone = task.stage_done || 0;
  entry.stageTotal = task.stage_total || 0;
  entry.inFlight = task.in_flight || 0;
  entry.rate = task.rate || 0;
  entry.eta = task.eta_seconds;
  entry.counts = {
    saved: task.valid_count || 0,
    invalid: task.invalid_count || 0,
    prescreened: task.prescreened_out || 0,
    failed: task.failed_count || 0
  };

  if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') {
    delete _activeTasks[id];
    removeSavedTask(id);
    if (task.status === 'completed') toast(entry.message || entry.label, 'success');
    else if (task.status === 'cancelled') toast(entry.message || T().task_cancelled, 'success');
    else toast(entry.message || entry.label, 'error');
    loadPlugins();
    loadProxies();
    updatePoolStatus();
    loadHostIp();
  }
  renderTasks();
}

function taskStageLabel(stage) {
  if (stage === 'prescreen') return T().task_stage_prescreen;
  if (stage === 'validate') return T().task_stage_validate;
  if (stage === 'ingest') return T().task_stage_ingest;
  return '';
}

function renderTaskDock() {
  onLangRender(renderTaskDock);
  var ids = Object.keys(_activeTasks);
  var dock = $('#task-dock');
  var badge = $('#sb-task-badge');

  badge.text(ids.length).toggle(ids.length > 0);
  if (!ids.length) { dock.removeClass('show'); return; }

  var done = 0, total = 0, msg = '';
  ids.forEach(function (id) {
    var t = _activeTasks[id];
    done += t.progress || 0;
    total += t.total || 0;
    if (!msg) {
      var stage = taskStageLabel(t.stage);
      msg = (t.label || '') + (stage ? ' ' + stage : '');
    }
  });
  $('#task-dock-msg').text(msg || T().task_running);
  $('#task-dock-count').text(ids.length + ' ' + T().task_dock_unit);
  $('#task-dock-bar').css('width', (total > 0 ? Math.min(100, (done / total) * 100) : 0) + '%');
  dock.addClass('show');
}

function gotoTaskView() {
  switchTab('tab-pool', { view: 'pool-view-manage' });
}

function renderTasks() {
  onLangRender(renderTasks);
  renderTaskDock();
  var area = $('#task-area');
  var ids = Object.keys(_activeTasks);
  area.empty();
  if (!ids.length) return;

  ids.forEach(function (id) {
    var t = _activeTasks[id];
    var finished = t.status === 'completed' || t.status === 'failed' || t.status === 'cancelled';
    var stateClass = t.status === 'failed' ? ' failed'
      : (finished ? ' done' : '');
    var stateText = t.status === 'failed' ? T().task_failed
      : (t.status === 'cancelled' ? T().task_cancelled
        : (t.status === 'completed' ? T().task_completed : T().task_running));

    var stageLabel = taskStageLabel(t.stage);
    var done = t.stageDone || 0;
    var total = t.stageTotal || 0;
    var percent = total > 0 ? Math.min(100, Math.round(done / total * 100)) : 0;

    var meta = '';
    if (!finished && stageLabel) {
      meta = escapeHtml(stageLabel);
      if (total > 0) meta += ' ' + done + '/' + total;
      if (t.rate > 0) {
        meta += ' · ' + escapeHtml(fillTemplate(T().task_rate, Math.round(t.rate)));
        meta += ' · ' + escapeHtml(
          t.eta === null || t.eta === undefined
            ? T().task_eta_unknown
            : fillTemplate(T().task_eta, fmtDuration(t.eta))
        );
      } else if (done === 0 && t.inFlight > 0) {
        meta += ' · ' + escapeHtml(fillTemplate(T().task_first_batch, t.inFlight));
      }
    } else if (total > 0) {
      meta = done + '/' + total;
    }

    var counts = '';
    if (t.counts) {
      var bits = [];
      if (t.counts.saved) bits.push(fillTemplate(T().task_count_saved, t.counts.saved));
      if (t.counts.invalid) bits.push(fillTemplate(T().task_count_invalid, t.counts.invalid));
      if (t.counts.prescreened) bits.push(fillTemplate(T().task_count_prescreened, t.counts.prescreened));
      if (t.counts.failed) bits.push(fillTemplate(T().task_count_failed, t.counts.failed));
      if (bits.length) counts = bits.map(escapeHtml).join(' · ');
    }

    area.append(
      '<div class="task-item">' +
        '<div class="task-head">' +
          '<i class="fa ' + (finished ? 'fa-check-circle' : 'fa-spinner fa-spin') + '"></i>' +
          '<span class="task-name">' + escapeHtml(t.label) + '</span>' +
          '<span class="task-state' + stateClass + '">' + escapeHtml(stateText) + '</span>' +
          (finished ? '' :
            '<button class="icon-btn task-cancel" data-act="task-cancel" data-id="' + escapeHtml(id) +
              '" title="' + escapeHtml(T().task_cancel_hint) + '">' +
              '<i class="fa fa-times"></i></button>') +
        '</div>' +
        '<div class="task-bar"><div class="task-bar-fill' + stateClass +
          '" style="width:' + percent + '%"></div></div>' +
        (meta ? '<div class="task-msg">' + meta + '</div>' : '') +
        (counts ? '<div class="task-counts">' + counts + '</div>' : '') +
      '</div>');
  });
}

function cancelTask(id, btn) {
  btnLoad($(btn), true);
  poolRequest('POST', 'tasks/' + encodeURIComponent(id) + '/cancel', null,
    function (r) {
      toast(r.message || T().task_cancelled, r.success === false ? 'error' : 'success');
      pollTasks();
    });
}


function loadPoolSchema(onReady) {
  if (_poolSchema) { onReady(_poolSchema); return; }
  $.get(appendToken('/api/pool/schema'), function (d) {
    _poolSchema = d.groups || [];
    onReady(_poolSchema);
  }).fail(function (x) { toast(poolErrorText(x), 'error'); });
}

function refreshPoolFormLanguage() {
  _poolSchema = null;
  if (!_poolFormBaseline) return;
  if (poolFormDirty()) return;
  loadPoolSchema(function (groups) {
    renderPoolForm(groups, collectPoolConfig());
  });
}

function applyPoolConfigToForm(pool, force) {
  if (!force && poolFormDirty()) return;
  loadPoolSchema(function (groups) {
    renderPoolForm(groups, pool || {});
  });
}

function discardPoolChanges() {
  if (!poolFormDirty()) { toast(T().no_changes, 'error'); return; }
  loadConfig({ poolOnly: true, force: true });
}


var _poolFormBaseline = null;

function markPoolFormClean() {
  _poolFormBaseline = collectPoolConfig();
  updatePoolDirtyState();
}

function poolFormDirty() {
  if (!_poolFormBaseline) return false;
  var current = collectPoolConfig();
  return Object.keys(current).some(function (key) {
    return String(current[key]) !== String(_poolFormBaseline[key]);
  });
}

function updatePoolDirtyState() {
  var ready = !!_poolFormBaseline;
  var dirty = ready && poolFormDirty();
  $('#pool-dirty-hint').toggle(dirty);
  $('#btn-save-pool-config').toggleClass('pri', true).toggleClass('dirty', dirty);

  var saved = $('#pool-saved-hint');
  if (dirty) {
    saved.hide();
  } else if (ready) {
    if (!saved.children().length) saved.html(idleSavedHintHtml()).attr('data-idle-hint', '1');
    saved.show();
  }
  setActionsIdle('#btn-save-pool-config', ready && !dirty);

  if (!ready) return;
  $('#pool-form .settings-group').each(function () {
    var groupDirty = false;
    $(this).find('[data-pool-key]').each(function () {
      var key = $(this).data('pool-key');
      var val = this.type === 'checkbox' ? (this.checked ? 'true' : 'false') : $(this).val();
      if (String(val) !== String(_poolFormBaseline[key])) groupDirty = true;
    });
    var idx = $(this).data('group');
    $('#pool-settings-nav .settings-nav-item[data-group="' + idx + '"] .settings-dirty-dot').toggle(groupDirty);
  });
}

$(document).on('input change', '#pool-form [data-pool-key]', updatePoolDirtyState);

$(window).on('beforeunload', function (e) {
  if (poolFormDirty()) {
    e.preventDefault();
    e.originalEvent.returnValue = '';
    return '';
  }
});

var POOL_GROUP_ICONS = {
  database: 'fa-database',
  validator: 'fa-check-circle',
  plugins: 'fa-puzzle-piece',
  auto_revalidation: 'fa-refresh',
  auto_cleanup: 'fa-recycle',
  use_feedback: 'fa-comment-o',
  write_queue: 'fa-tasks',
  logging: 'fa-file-text',
};

function toggleAllAdvanced() {
  var box = $('#pool-form details.adv-config');
  if (!box.length) return;
  var expand = box.filter(':not([open])').length > 0;
  box.prop('open', expand);
  renderAdvancedToggle(expand);
  if (typeof scheduleStickySync === 'function') scheduleStickySync();
}

function renderAdvancedToggle(expanded) {
  $('#adv-toggle-icon').attr('class', 'fa ' + (expanded ? 'fa-chevron-up' : 'fa-chevron-down'));
  $('#adv-toggle-text').text(expanded ? T().adv_collapse_all : T().adv_expand_all);
}

function refreshAdvancedToggle() {
  onLangRender(refreshAdvancedToggle);
  var visible = $('#pool-form details.adv-config').filter(':visible');
  $('#adv-toggle-wrap').toggle(visible.length > 0);
  if (!visible.length) return;
  renderAdvancedToggle(visible.filter(':not([open])').length === 0);
}

function renderPoolForm(groups, values) {
  onLangRender(refreshPoolFormLanguage);
  var container = $('#pool-form');
  var nav = $('#pool-settings-nav');
  container.empty();
  nav.empty();

  groups.forEach(function (group, index) {
    var title = group.title ? group.title : T().pool_group_basic;
    var icon = POOL_GROUP_ICONS[group.id] || 'fa-cog';
    var basicBody = '';
    var advancedBody = '';
    var advancedCount = 0;

    group.fields.forEach(function (field) {
      var value = values[field.key];
      if (value === undefined) value = '';
      var collapsed = field.tier === 'advanced' && !field.visible_when;
      if (collapsed) { advancedBody += renderPoolField(field, value); advancedCount++; }
      else basicBody += renderPoolField(field, value);
    });

    var body = basicBody;
    if (advancedBody) {
      body += '<details class="adv-config settings-adv-config">' +
                '<summary>' + escapeHtml(T().advanced_config_title) +
                  ' <span class="adv-count">' + advancedCount + '</span>' +
                '</summary>' +
                '<div class="settings-adv-grid">' + advancedBody + '</div>' +
              '</details>';
    }

    nav.append(
      '<div class="settings-nav-item' + (index === 0 ? ' cur' : '') + '" data-group="' + index + '">' +
        '<i class="fa ' + icon + '"></i><span>' + escapeHtml(title) + '</span>' +
        '<span class="settings-dirty-dot" style="display:none"></span>' +
      '</div>');

    container.append(
      '<div class="settings-group' + (index === 0 ? ' show' : '') + '" data-group="' + index + '">' +
        '<div class="settings-card">' +
          '<div class="settings-card-hd">' +
            '<i class="fa ' + icon + '"></i><span>' + escapeHtml(title) + '</span>' +
            (group.sub ? '<span class="settings-card-sub">' + escapeHtml(group.sub) + '</span>' : '') +
            '<span class="settings-card-count">' + group.fields.length + '</span>' +
          '</div>' +
          '<div class="settings-body">' + body + '</div>' +
        '</div>' +
      '</div>');
  });

  markPoolFormClean();
  refreshAdvancedToggle();
  if (typeof syncFieldVisibility === 'function') syncFieldVisibility();
  if (typeof scheduleStickySync === 'function') scheduleStickySync();
  if (typeof initFieldTips === 'function') initFieldTips();
}

$(document).on('click', '#pool-settings-nav .settings-nav-item', function () {
  showSettingsGroup('#pool-settings-nav', $(this).data('group'));
  refreshAdvancedToggle();
});

var POOL_TRUE_WORDS = ['1', 'true', 'yes', 'on'];


function renderPoolField(field, value) {
  var key = escapeHtml(field.key);
  var wide = '';
  var control;

  if (field.type === 'bool') {
    var checked = POOL_TRUE_WORDS.indexOf(String(value).toLowerCase()) >= 0 ? ' checked' : '';
    control = '<label class="chk-inline switch"><input type="checkbox" data-pool-key="' +
              key + '"' + checked + '></label>';
  } else if (field.type === 'int' || field.type === 'float') {
    var step = field.type === 'float' ? ' step="0.1"' : ' step="1"';
    var low = typeof field.low === 'number' ? field.low : 0;
    var bounds = ' min="' + low + '"';
    if (typeof field.high === 'number') {
      bounds += ' max="' + field.high + '"';
    }
    var numberInput = '<input class="fg-input" type="number"' + step + bounds +
              ' data-pool-key="' + key + '" value="' + escapeHtml(value) + '">';
    control = field.unit
      ? '<div class="fg-control">' + numberInput +
        '<span class="fg-unit">' + escapeHtml(field.unit) + '</span></div>'
      : numberInput;
  } else {
    control = '<input class="fg-input" data-pool-key="' + key + '" value="' + escapeHtml(value) + '">';
  }

  var doc = field.doc ? plainDoc(field.doc) : '';
  var visibleWhen = field.visible_when
    ? ' data-visible-when="' + escapeHtml(field.visible_when) + '"' : '';
  return '<div class="fg' + wide + '"' + visibleWhen + '>' +
           '<div class="fg-label-row">' +
             '<span class="fg-label">' + escapeHtml(field.title || field.key) + '</span>' +
             (doc ? '<i class="fa fa-info-circle fg-tip" title="' +
                    escapeHtml(doc) + '" aria-hidden="true"></i>' : '') +
           '</div>' +
           control +
           (field.hint ? '<div class="fg-hint">' + escapeHtml(field.hint) + '</div>' : '') +
         '</div>';
}

function collectPoolConfig() {
  var updates = {};
  $('#pool-form').find('[data-pool-key]').each(function () {
    var key = $(this).data('pool-key');
    var value = this.type === 'checkbox' ? (this.checked ? 'true' : 'false') : $(this).val();
    updates[key] = value;
  });
  return updates;
}

function poolConfigChanges() {
  var current = collectPoolConfig();
  var changes = {};
  for (var key in current) {
    if (String(current[key]) !== String(_poolFormBaseline ? _poolFormBaseline[key] : undefined)) {
      changes[key] = current[key];
    }
  }
  return changes;
}

function savePoolConfig() {
  var updates = poolConfigChanges();
  if (!Object.keys(updates).length) { toast(T().no_changes, 'error'); return; }
  submitConfig({ pool: updates }, $('#btn-save-pool-config'), markPoolFormClean);
  loadHostIp();
}


function openImportModal() {
  $('#import-text').val('');
  updateImportCount();
  openModal('import-modal');
}

function updateImportCount() {
  var n = $('#import-text').val().split('\n').filter(function (line) {
    return line.trim();
  }).length;
  $('#import-count').text(n ? fillTemplate(T().import_count, n) : '');
  $('#btn-import-submit').prop('disabled', !n);
}

$(document).on('input', '#import-text', updateImportCount);

function closeImportModal() { closeModal('import-modal'); }

function submitImport() {
  var lines = $('#import-text').val().split('\n')
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return s; });

  if (!lines.length) { toast(T().import_empty, 'error'); return; }

  var btn = $('#btn-import-submit');
  btnLoad(btn, true);

  poolRequest('POST', 'import', { proxies: lines }, function (r) {
    closeImportModal();
    toast(r.message, r.success === false ? 'error' : 'success');
    if (r.task_id) trackTask(r.task_id, T().task_import);
    else loadProxies();
  }).always(function () {
    btnLoad(btn, false);
  });
}

function openExportModal() {
  $('#export-count').text(totalCount ? fillTemplate(T().export_scope_count, totalCount) : '');
  openModal('export-modal');
}
function closeExportModal() { closeModal('export-modal'); }

function doExport(format) {
  closeExportModal();
  var params = $.extend({ format: format }, collectFilterParams());
  var query = $.param(params);
  window.location.href = appendToken('/api/pool/export?' + query);
  toast(T().log_export_started, 'success');
}

function copyPoolApiLink() {
  var params = $.extend({ format: 'text' }, collectFilterParams());
  var link = appendToken(location.origin + '/api/pool/random?' + $.param(params));

  copyToClipboard(link, function () {
    toast(T().api_link_copied, 'success');
  });
}

$(document).on('click', '#task-area [data-act="task-cancel"]', function () {
  cancelTask($(this).attr('data-id'), this);
});

$(document).on('click', '#plugin-tbody [data-act]', function () {
  var $el = $(this);
  var name = $el.closest('tr').attr('data-plugin');

  switch ($el.attr('data-act')) {
    case 'plugin-toggle':
      togglePlugin(name, this.checked, this);
      break;
    case 'plugin-interval':
      setPluginInterval(name, parseInt($el.attr('data-minutes'), 10));
      break;
    case 'plugin-test-url':
      setPluginTestUrl(name, $el.attr('data-url') || '');
      break;
    case 'plugin-validation':
      openPluginSettingsModal(name, _pluginRows[name] || {});
      break;
    case 'plugin-run':
      runPlugin(name, $el);
      break;
    case 'plugin-reload':
      reloadPlugin(name, $el);
      break;
  }
});


function loadDbMaintain() {
  onLangRender(loadDbMaintain);
  poolRequest('GET', 'database/stats', null, function (d) {
    renderDbStats(d.stats || {});
  }, { silent: true }).fail(function () { renderDbStats({}); });

  $('#db-backup-list').html(skeletonBlock(3));
  $.get(appendToken('/api/pool/backups'), function (d) {
    renderBackups(d.backups || []);
  }).fail(function () {
    $('#db-backup-list').empty().append(
      '<div class="empty-hint">' + escapeHtml(T().pool_unavailable_hint) + '</div>');
  });
}

function renderDbStats(s) {
  var items = [
    { key: 'db_stat_total',   val: s.total_proxies,   cls: '' },
    { key: 'db_stat_valid',   val: s.valid_proxies,   cls: 'ok' },
    { key: 'db_stat_invalid', val: s.invalid_proxies, cls: 'bad' },
    { key: 'db_stat_size',    val: s.db_size_mb, unit: 'MB', cls: '', digits: 1 }
  ];
  var box = $('#db-stats-text').empty();
  items.forEach(function (it) {
    var missing = it.val === undefined || it.val === null;
    var shown = missing ? '--'
      : (it.digits !== undefined ? Number(it.val).toFixed(it.digits) : it.val);
    box.append(
      '<div class="metric ' + it.cls + '">' +
        '<span class="metric-val">' + escapeHtml(shown) +
          (it.unit ? '<span class="metric-unit">' + escapeHtml(it.unit) + '</span>' : '') +
        '</span>' +
        '<span class="metric-lbl">' + escapeHtml(T()[it.key]) + '</span>' +
      '</div>');
  });
}

function renderBackups(backups) {
  var box = $('#db-backup-list');
  box.empty();
  if (!backups.length) {
    box.append('<div class="empty-hint">' + escapeHtml(T().db_no_backups) + '</div>');
    return;
  }

  var table = $('<table class="tbl-clean tbl-plugin"></table>');
  var head = $('<thead><tr></tr></thead>');
  head.find('tr')
    .append('<th>' + escapeHtml(T().db_backup_file) +
            ' <span class="col-badge">' + backups.length + '</span></th>')
    .append('<th>' + escapeHtml(T().db_backup_time) + '</th>')
    .append('<th class="cell-num">' + escapeHtml(T().db_backup_size) + '</th>')
    .append('<th></th>');
  table.append(head);

  var tbody = $('<tbody></tbody>');
  backups.forEach(function (b, index) {
    var sizeMb = (b.size / 1024 / 1024).toFixed(1);
    var row = $('<tr></tr>');
    row.append('<td class="cell-mono">' + escapeHtml(b.filename) +
               (index === 0 ? ' <span class="badge badge-latest">' +
                              escapeHtml(T().db_backup_latest) + '</span>' : '') + '</td>');
    row.append('<td class="cell-mono">' + escapeHtml(b.created_at) + '</td>');
    row.append('<td class="cell-num cell-mono">' + sizeMb + ' MB</td>');
    var btn = $('<button class="btn ghost bad sm">' + escapeHtml(T().db_restore_btn) + '</button>');
    btn.on('click', function () { restoreBackup(b.filename); });
    row.append($('<td></td>').append(btn));
    tbody.append(row);
  });
  table.append(tbody);
  box.append(table);
}

function restoreBackup(filename) {
  showConfirm(T().db_restore_confirm_title, T().db_restore_confirm_body, function (ok) {
    if (!ok) return;

    var perform = function () {
      poolRequest('POST', 'backups/restore', { filename: filename }, function (r) {
        toast(r.message || T().db_restore_success, 'success');
        loadDbMaintain();
        if (_poolRunning) controlPool('start');
        else updatePoolStatus();
      });
    };

    if (_poolRunning) {
      toast(T().db_restore_stopping, 'success');
      poolRequest('POST', 'stop', null, function () { perform(); });
    } else {
      perform();
    }
  }, { danger: true });
}

function optimizeDatabase() {
  showConfirm(T().db_optimize_btn, T().db_optimize_confirm_body, function (ok) {
    if (!ok) return;
    btnLoad($('#btn-db-optimize'), true);
    poolRequest('POST', 'database/optimize', null, function (r) {
      toast(r.message || (T().db_optimize_btn + ' ✓'), 'success');
      loadDbMaintain();
    }).always(function () { btnLoad($('#btn-db-optimize'), false); });
  });
}


var _geoPending = null;

var _geoTask = null;
var _geoSubmitPending = false;

function loadGeoStatus() {
  onLangRender(loadGeoStatus);
  poolRequest('GET', 'geo/status', null, renderGeoStatus, { silent: true })
    .fail(renderGeoStatusUnavailable);
}

function renderGeoStatus(d) {
  _geoPending = d.pending_recompute || 0;

  var pending = _geoPending > 0
    ? fillTemplate(T().geo_pending, _geoPending)
    : T().geo_pending_zero;
  var head = d.available ? T().geo_available : T().geo_unavailable;
  $('#geo-status-text').text(head + ' · ' + pending);

  renderGeoFiles(d.files || []);
  syncGeoControls();
}

function renderGeoStatusUnavailable() {
  _geoPending = null;
  $('#geo-status-text').text(T().geo_pool_down);
  syncGeoControls();
}

function renderGeoFiles(files) {
  var box = $('#geo-file-list');
  box.empty();
  if (!files.length) {
    box.append('<div class="empty-hint">' + escapeHtml(T().no_data) + '</div>');
    return;
  }

  var table = $('<table class="tbl-clean tbl-plugin"></table>');
  var head = $('<thead><tr></tr></thead>');
  head.find('tr')
    .append('<th>' + escapeHtml(T().geo_file_list_title) + '</th>')
    .append('<th class="cell-num">' + escapeHtml(T().geo_file_size) + '</th>')
    .append('<th>' + escapeHtml(T().geo_file_time) + '</th>');
  table.append(head);

  var tbody = $('<tbody></tbody>');
  files.forEach(function (f) {
    var row = $('<tr></tr>');
    row.append('<td class="cell-mono">' + escapeHtml(f.filename) + '</td>');
    row.append(f.exists
      ? '<td class="cell-num cell-mono">' + escapeHtml(fmtLogSize(f.size)) + '</td>'
      : '<td class="cell-num warn-text">' + escapeHtml(T().geo_file_missing) + '</td>');
    row.append('<td class="cell-mono">' + escapeHtml(f.modified_at || '--') + '</td>');
    tbody.append(row);
  });
  table.append(tbody);
  box.append(table);
}

function syncGeoControls() {
  var ready = poolReady();
  var busy = !!_geoTask;
  $('#btn-geo-update').prop('disabled', !ready || busy);
  $('#btn-geo-recompute').prop('disabled', !ready || busy || _geoPending === 0);
}

function startGeoUpdate() {
  submitGeoTask('geo/update');
}

function startGeoRecompute() {
  submitGeoTask('geo/recompute');
}

function submitGeoTask(path) {
  if (_geoTask || _geoSubmitPending) return;
  _geoSubmitPending = true;

  var btn = $(path.indexOf('recompute') >= 0 ? '#btn-geo-recompute' : '#btn-geo-update');
  btnLoad(btn, true);
  poolRequest('POST', path, null, function (r) {
    toast(r.message, 'success');
    if (!r.task_id) return;
    _geoTask = { id: r.task_id };
    renderGeoTask(T().geo_task_queued, 'fa-spinner fa-spin');
    syncGeoControls();
    startGeoPolling();
  }).always(function () {
    _geoSubmitPending = false;
    btnLoad(btn, false);
    syncGeoControls();
  });
}

function startGeoPolling() {
  if (isPolling('geo')) return;
  startPolling('geo', pollGeoTask, POOL_TASK_POLL_MS);
  pollGeoTask();
}

function stopGeoPolling() {
  stopPolling('geo');
}

function pollGeoTask() {
  if (!_geoTask) { stopGeoPolling(); return; }
  $.get(appendToken('/api/pool/tasks/' + _geoTask.id))
    .done(onGeoTaskUpdate)
    .fail(function () { finishGeoTask(T().geo_task_lost, false); });
}

function onGeoTaskUpdate(task) {
  if (task.status === 'running' || task.status === 'queued') {
    renderGeoTask(task.message || T().geo_task_running, 'fa-spinner fa-spin');
    return;
  }
  var done = task.status === 'completed';
  finishGeoTask(task.message || (done ? T().task_completed : T().task_failed), done);
}

function finishGeoTask(message, ok) {
  stopGeoPolling();
  _geoTask = null;
  renderGeoTask(message, ok ? 'fa-check-circle' : 'fa-exclamation-circle');
  toast(message, ok ? 'success' : 'error');
  syncGeoControls();
  loadGeoStatus();
}

function renderGeoTask(message, iconClass) {
  $('#geo-progress-icon').attr('class', 'fa ' + iconClass);
  $('#geo-progress-msg').text(message || '');
  $('#geo-progress-text').attr('title', message || '').show();
}


var POOL_VIEW_STORAGE_KEY = 'proxycat-pool-view';

function switchPoolView(viewId) {
  if (!$('#' + viewId).length) return;
  $('.pool-view').removeClass('show');
  $('#' + viewId).addClass('show');
  safeSetItem(POOL_VIEW_STORAGE_KEY, viewId);
  if (viewId === 'pool-view-db') { loadDbMaintain(); loadGeoStatus(); }
  if (viewId === 'pool-view-settings') refreshAdvancedToggle();
  if (typeof scheduleStickySync === 'function') scheduleStickySync();
  syncSidebarActive('tab-pool', viewId);
  renderViewHead();
  writeHash();
}
