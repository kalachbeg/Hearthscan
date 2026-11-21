// The Hearthscan window: start a check, follow it, read the result.
//
// Names, models, banners, descriptions and evidence come from devices on the
// network. They only ever reach the page through textContent, so nothing a
// device calls itself can turn into markup.

'use strict';

(function () {
  const token = new URLSearchParams(window.location.search).get('token') || '';

  // Each language is named in its own language, whatever the page shows.
  const LANGUAGE_NAMES = { en: 'English', tr: 'T\u00fcrk\u00e7e' };
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const COUNTED = ['critical', 'high', 'medium', 'low'];
  const STAGES = ['discover', 'ports', 'probes', 'router', 'checks'];
  const BANDS = [[90, 'good'], [70, 'fair'], [40, 'poor'], [0, 'bad']];
  const VIEWS = ['loading', 'fatal', 'start', 'scan', 'result'];
  const PLACEHOLDER = /\{(\w+)\}/g;
  // As in report.py: control characters become spaces and text direction
  // marks go, so a name cannot turn the text around it backwards.
  const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
  const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
  const DOT = ' \u00b7 ';

  const state = {
    info: null,
    texts: {},
    language: 'en',
    view: 'loading',
    shownView: null,
    progress: null, // {stage, done, total}
    shownStage: undefined,
    notes: [],
    result: null,
    probed: null, // false when the check behind the result skipped the service probes
    probe: true, // what the last check started from this page asked for
    noNetwork: false,
    stopping: false,
    message: null, // {key, params, tone}
    save: null, // {key, params, tone, copy, box}
    pending: null, // {text, name} of the last download, for copying instead
    deviceRows: [],
    lost: false,
    lostTimer: 0,
  };

  // Texts

  function has(key) {
    return Object.prototype.hasOwnProperty.call(state.texts, key);
  }

  function t(key, params) {
    const text = has(key) ? state.texts[key] : key;
    if (!params) return text;
    // One pass, so braces inside the values are never read as placeholders.
    return text.replace(PLACEHOLDER, function (match, name) {
      return Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match;
    });
  }

  function applyStaticTexts() {
    document.documentElement.lang = state.language;
    document.querySelectorAll('[data-t]').forEach(function (node) {
      node.textContent = t(node.getAttribute('data-t'));
    });
    document.querySelectorAll('[data-t-placeholder]').forEach(function (node) {
      node.placeholder = t(node.getAttribute('data-t-placeholder'));
    });
    document.querySelectorAll('[data-t-label]').forEach(function (node) {
      node.setAttribute('aria-label', t(node.getAttribute('data-t-label')));
    });
  }

  function useTexts(data) {
    state.texts = data && data.texts ? data.texts : {};
    state.language = (data && data.language) || 'en';
    applyStaticTexts();
  }

  // DOM

  function $(id) {
    return document.getElementById(id);
  }

  function clean(value) {
    return String(value).replace(CONTROL, ' ').replace(BIDI, '');
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = clean(text);
    return node;
  }

  function setText(node, text) {
    node.textContent = clean(text);
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function show(node, visible) {
    node.hidden = !visible;
  }

  function isVisible(node) {
    return !!(node.offsetWidth || node.offsetHeight || node.getClientRects().length);
  }

  // Server

  function request(path, method, body) {
    const options = {
      method: method || 'GET',
      headers: { 'X-Hearthscan-Token': token },
      cache: 'no-store',
    };
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    return fetch(path, options);
  }

  function httpError(response) {
    const error = new Error('HTTP ' + response.status);
    error.status = response.status;
    return error;
  }

  async function getJSON(path) {
    const response = await request(path);
    if (!response.ok) throw httpError(response);
    return response.json();
  }

  // A wrong token or host name: no retry can help, only the address Hearthscan opened.
  function refused(error) {
    return error && (error.status === 401 || error.status === 403 || error.status === 421);
  }

  // The parts of a result

  function list(value) {
    return Array.isArray(value) ? value : [];
  }

  function severityOf(finding) {
    return SEVERITIES.indexOf(finding.severity) >= 0 ? finding.severity : 'info';
  }

  function clampScore(value) {
    const score = Math.round(Number(value));
    return isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
  }

  function bandOf(score) {
    for (let i = 0; i < BANDS.length; i += 1) {
      if (score >= BANDS[i][0]) return BANDS[i][1];
    }
    return 'bad';
  }

  function kindText(kind) {
    return has('kind.' + kind) ? t('kind.' + kind) : t('kind.unknown');
  }

  // The same labels as render.device_label and render.maker.
  function deviceLabel(device, ip) {
    if (!device) return ip;
    const kind = kindText(device.kind);
    if (!device.name) return kind + ' (' + ip + ')';
    if (device.is_gateway) return device.name + ', ' + kind + ' (' + ip + ')';
    return device.name + ' (' + ip + ')';
  }

  function maker(device) {
    const vendor = device.vendor || '';
    const model = device.model || '';
    if (vendor && model.toLowerCase().indexOf(vendor.toLowerCase()) === 0) return model;
    return [vendor, model].filter(Boolean).join(' ');
  }

  function where(finding, device) {
    const label = deviceLabel(device, finding.ip);
    return finding.port ? t('ui.finding.where', { device: label, port: finding.port }) : label;
  }

  function devicesByIp(devices) {
    // The first device with an address wins, as in ScanResult.device().
    const found = new Map();
    devices.forEach(function (device) {
      if (device && !found.has(device.ip)) found.set(device.ip, device);
    });
    return found;
  }

  function parseTime(iso) {
    if (typeof iso !== 'string') return null;
    // Python writes microseconds; not every engine reads more than milliseconds.
    const moment = new Date(iso.replace(/(\.\d{3})\d+/, '$1'));
    return isNaN(moment.getTime()) ? null : moment;
  }

  function pad(number, width) {
    return String(number).padStart(width || 2, '0');
  }

  function formatTime(iso) {
    const moment = parseTime(iso);
    if (!moment) return String(iso || '');
    return t('report.datetime', {
      year: pad(moment.getFullYear(), 4),
      month: pad(moment.getMonth() + 1),
      day: pad(moment.getDate()),
      hour: pad(moment.getHours()),
      minute: pad(moment.getMinutes()),
    });
  }

  function duration(started, finished) {
    const start = parseTime(started);
    const end = parseTime(finished);
    if (!start || !end) return null;
    const seconds = (end - start) / 1000;
    return seconds >= 0 ? seconds : null;
  }

  function uptime(seconds) {
    return t('ui.router.uptime_value', {
      days: Math.floor(seconds / 86400),
      hours: Math.floor((seconds % 86400) / 3600),
    });
  }

  // Folds case and accents so "iphone" finds "iPhone" and "IPHONE" in either language.
  function fold(text) {
    return String(text)
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/\u0131/g, 'i');
  }

  // Rendering

  function render() {
    renderHeader();
    renderMessage();
    renderBanner();
    if (state.view === 'start') renderStart();
    if (state.view === 'scan') renderScan(true);
    if (state.view === 'result') renderResult();
    showView(state.view);
  }

  function go(view) {
    state.view = view;
    render();
  }

  function showView(name) {
    const previous = state.shownView;
    state.shownView = name;
    VIEWS.forEach(function (view) {
      show($('view-' + view), view === name);
    });
    if (!previous || previous === name) return;
    window.scrollTo(0, 0);
    // Keyboard focus would be lost on a button that just went away.
    const active = document.activeElement;
    if (!active || active === document.body || !isVisible(active)) {
      const heading = $('view-' + name).querySelector('h1');
      if (heading) heading.focus();
    }
  }

  function renderHeader() {
    const info = state.info;
    setText($('version'), info && info.version ? info.version : '');
    const network = info && info.network;
    show($('netline'), !!network);
    if (network) {
      setText(
        $('netline'),
        t('ui.banner.network', {
          network: network.scan_network || network.network,
          via: network.interface,
        })
      );
    }
    const box = $('lang');
    show(box, !!info);
    const codes = info && Array.isArray(info.languages) ? info.languages : [];
    // Built once, so keyboard focus on a language button survives a re-render.
    if (box.childElementCount !== codes.length) {
      clear(box);
      codes.forEach(function (code) {
        const button = el('button', null, LANGUAGE_NAMES[code] || code);
        button.type = 'button';
        button.lang = code;
        button.setAttribute('data-code', code);
        button.addEventListener('click', function () {
          switchLanguage(code);
        });
        box.appendChild(button);
      });
    }
    box.querySelectorAll('button').forEach(function (button) {
      button.setAttribute('aria-pressed', String(button.getAttribute('data-code') === state.language));
    });
  }

  function renderMessage() {
    const node = $('message');
    const message = state.message;
    node.className = 'message' + (message ? ' tone-' + message.tone : '');
    setText(node, message ? t(message.key, message.params) : '');
  }

  function setMessage(key, params, tone) {
    state.message = key ? { key: key, params: params || null, tone: tone || 'info' } : null;
    renderMessage();
  }

  function renderBanner() {
    setText($('banner'), state.lost ? t('gui.connection.lost') : '');
  }

  function addFacts(dl, rows) {
    clear(dl);
    rows.forEach(function (row) {
      dl.appendChild(el('dt', null, row[0]));
      dl.appendChild(el('dd', null, row[1]));
    });
  }

  function renderStart() {
    const info = state.info || {};
    const sandbox = info.sandbox === 'wsl' || info.sandbox === 'container' ? info.sandbox : null;
    show($('sandbox'), !!sandbox);
    if (sandbox) setText($('sandbox'), t('ui.sandbox.' + sandbox));

    const network = info.network;
    const offline = !network || state.noNetwork;
    show($('nonet'), offline);
    show($('start-actions'), !offline);

    show($('netcard'), !!network);
    if (network) {
      const rows = [
        [t('ui.network.interface'), network.interface],
        [t('ui.network.address'), network.address],
        [t('ui.network.network'), network.network],
        [t('ui.network.gateway'), network.gateway || '-'],
      ];
      if (network.scan_network && network.scan_network !== network.network) {
        rows.push([
          t('ui.network.scanning'),
          t('ui.network.narrowed', { network: network.scan_network }),
        ]);
      }
      addFacts($('netfacts'), rows);
    }
  }

  function stageLabel(stage) {
    if (stage === 'done') return t('gui.scan.finishing');
    if (STAGES.indexOf(stage) >= 0) return t('ui.stage.' + stage);
    return t('gui.scan.waiting');
  }

  function renderScan(full) {
    const progress = state.progress;
    const stage = progress ? progress.stage : null;
    if (full || stage !== state.shownStage) {
      // Only when the stage changes: the stage line is a live region.
      state.shownStage = stage;
      setText($('stage'), stageLabel(stage));
      renderSteps(stage);
    }
    if (full) renderScanNotes();

    const total = progress && progress.total > 0 ? progress.total : 0;
    let percent = null; // none: the stage has no count
    if (total) {
      const done = Math.min(Math.max(Number(progress.done) || 0, 0), total);
      percent = Math.floor((done * 100) / total);
    } else if (stage === 'done') {
      percent = 100;
    }
    const bar = $('bar');
    bar.classList.toggle('busy', percent === null);
    if (percent === null) bar.removeAttribute('aria-valuenow');
    else bar.setAttribute('aria-valuenow', String(percent));
    $('bar-fill').style.width = (percent === null ? 0 : percent) + '%';
    setText($('percent'), total ? t('gui.scan.percent', { percent: percent }) : '');

    const stop = $('stop');
    stop.disabled = state.stopping;
    setText(stop, state.stopping ? t('gui.stopping') : t('gui.stop'));
  }

  function renderSteps(stage) {
    const steps = $('steps');
    clear(steps);
    const stages =
      state.probe === false && stage !== 'probes'
        ? STAGES.filter(function (name) {
            return name !== 'probes';
          })
        : STAGES;
    const current = stage === 'done' ? stages.length : stages.indexOf(stage);
    stages.forEach(function (name, index) {
      const item = el('li', 'step', t('ui.stage.' + name));
      if (index < current) {
        item.classList.add('done');
        item.appendChild(el('span', 'sr-only', ' (' + t('gui.scan.step_done') + ')'));
      } else if (index === current) {
        item.classList.add('active');
        item.setAttribute('aria-current', 'step');
      }
      steps.appendChild(item);
    });
  }

  function noteLine(note) {
    return el('li', null, t('ui.note') + ': ' + (note.message || ''));
  }

  function renderScanNotes() {
    const notes = $('scan-notes');
    clear(notes);
    state.notes.forEach(function (note) {
      notes.appendChild(noteLine(note));
    });
  }

  function renderResult() {
    const result = state.result;
    if (!result) return;
    const findings = list(result.findings).filter(Boolean);
    const devices = list(result.devices).filter(Boolean);
    const byIp = devicesByIp(devices);
    renderScore(result, findings, devices);
    renderFindings(findings, byIp);
    renderRouter(result.router, byIp);
    renderDevices(devices);
    renderNotes(list(result.notes));
    const version = result.version || (state.info && state.info.version) || '';
    setText(
      $('foot-made'),
      'Hearthscan ' + version + DOT + t('report.started', { time: formatTime(result.started) })
    );
    renderSave();
  }

  function renderScore(result, findings, devices) {
    const score = clampScore(result.score);
    const band = bandOf(score);
    $('score').className = 'card score band-' + band;
    setText($('score-number'), String(score));
    setText($('band-title'), t('band.' + band + '.title'));
    setText($('band-summary'), t('band.' + band + '.summary'));
    // A CSSOM property, which the page's style policy allows; a style attribute it would not.
    $('meter-fill').style.width = score + '%';

    const counts = {};
    SEVERITIES.forEach(function (severity) {
      counts[severity] = 0;
    });
    findings.forEach(function (finding) {
      if (Object.prototype.hasOwnProperty.call(counts, finding.severity)) {
        counts[finding.severity] += 1;
      }
    });
    show($('urgent'), counts.critical > 0 || counts.high > 0);
    show($('unprobed'), state.probed === false);

    const found = COUNTED.filter(function (severity) {
      return counts[severity] > 0;
    }).map(function (severity) {
      return t('ui.count.' + severity, { count: counts[severity] });
    });
    const facts = [
      result.network,
      t('ui.summary.devices', { count: devices.length }),
      found.length ? found.join(', ') : t('ui.summary.clean'),
    ];
    const took = duration(result.started, result.finished);
    if (took !== null) facts.push(t('ui.summary.took', { seconds: took.toFixed(0) }));
    setText($('facts'), facts.join(DOT));

    const tiles = $('tiles');
    clear(tiles);
    COUNTED.forEach(function (severity) {
      const tile = el('li', 'tile sev-' + severity + (counts[severity] ? '' : ' zero'));
      tile.appendChild(el('span', 'tile-count', String(counts[severity])));
      tile.appendChild(el('span', 'tile-label', t('severity.' + severity)));
      tiles.appendChild(tile);
    });
  }

  function explain(finding) {
    const params = finding.params && typeof finding.params === 'object' ? finding.params : {};
    const dl = el('dl', 'explain');
    dl.appendChild(el('dt', null, t('ui.finding.why')));
    dl.appendChild(el('dd', null, t('rule.' + finding.rule + '.why', params)));
    dl.appendChild(el('dt', null, t('ui.finding.fix')));
    dl.appendChild(el('dd', null, t('rule.' + finding.rule + '.fix', params)));
    return dl;
  }

  function evidence(text) {
    const box = el('details', 'evidence');
    box.appendChild(el('summary', null, t('report.evidence')));
    const pre = el('pre');
    pre.appendChild(el('code', null, text));
    box.appendChild(pre);
    return box;
  }

  function findingCard(finding, device) {
    const severity = severityOf(finding);
    const card = el('article', 'card finding sev-' + severity);
    const head = el('header', 'finding-head');
    head.appendChild(el('span', 'badge sev-' + severity, t('severity.' + severity)));
    head.appendChild(el('h3', null, t('rule.' + finding.rule + '.title')));
    card.appendChild(head);
    card.appendChild(el('p', 'where', where(finding, device)));
    card.appendChild(explain(finding));
    if (finding.evidence) card.appendChild(evidence(finding.evidence));
    return card;
  }

  function fyiItem(finding, device) {
    const item = el('li');
    const box = el('details');
    const summary = el('summary');
    const text = el('span', 'fyi-text');
    text.appendChild(el('span', 'fyi-title', t('rule.' + finding.rule + '.title')));
    text.appendChild(el('span', 'where', where(finding, device)));
    summary.appendChild(text);
    box.appendChild(summary);
    const body = el('div', 'fyi-body');
    body.appendChild(explain(finding));
    if (finding.evidence) body.appendChild(evidence(finding.evidence));
    box.appendChild(body);
    item.appendChild(box);
    return item;
  }

  function renderFindings(findings, byIp) {
    const serious = findings.filter(function (finding) {
      return finding.severity !== 'info';
    });
    const fyi = findings.filter(function (finding) {
      return finding.severity === 'info';
    });
    const cards = $('finding-list');
    clear(cards);
    serious.forEach(function (finding) {
      cards.appendChild(findingCard(finding, byIp.get(finding.ip)));
    });
    show($('findings-none'), serious.length === 0);

    const items = $('fyi-list');
    clear(items);
    fyi.forEach(function (finding) {
      items.appendChild(fyiItem(finding, byIp.get(finding.ip)));
    });
    show($('fyi'), fyi.length > 0);
  }

  // A table that turns into labelled blocks on a phone. Cells are text or nodes.
  function table(headers, rows) {
    const node = el('table', 'stack');
    const head = el('thead');
    const headRow = el('tr');
    headers.forEach(function (header) {
      const th = el('th', null, header);
      th.scope = 'col';
      headRow.appendChild(th);
    });
    head.appendChild(headRow);
    node.appendChild(head);
    const body = el('tbody');
    rows.forEach(function (row) {
      const tr = el('tr', row.off ? 'off' : null);
      row.cells.forEach(function (cell, index) {
        const td = el('td', index === 0 ? 'first' : null);
        if (cell !== '' && cell !== null && cell !== undefined) {
          td.setAttribute('data-label', headers[index]);
          const inner = el('div');
          if (typeof cell === 'string' || typeof cell === 'number') setText(inner, cell);
          else inner.appendChild(cell);
          td.appendChild(inner);
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
      row.node = tr;
    });
    node.appendChild(body);
    return node;
  }

  function renderRouter(router, byIp) {
    show($('router'), !!router);
    if (!router) return;
    const rows = [];
    if (router.external_ip) rows.push([t('ui.router.external_ip'), router.external_ip]);
    if (router.connection) rows.push([t('ui.router.connection'), router.connection]);
    if (router.status) rows.push([t('ui.router.status'), router.status]);
    if (typeof router.uptime === 'number') rows.push([t('ui.router.uptime'), uptime(router.uptime)]);
    addFacts($('router-facts'), rows);
    show($('router-facts'), rows.length > 0);

    const box = $('mappings');
    clear(box);
    const mappings = list(router.mappings).filter(Boolean);
    if (mappings.length) {
      const headers = [
        t('ui.col.external'),
        t('ui.col.protocol'),
        t('ui.col.forwards_to'),
        t('ui.col.description'),
      ];
      const rowsOut = mappings.map(function (mapping) {
        const device = byIp.get(mapping.internal_client);
        const target = device
          ? t('ui.finding.where', {
              device: deviceLabel(device, mapping.internal_client),
              port: mapping.internal_port,
            })
          : mapping.internal_client + ':' + mapping.internal_port;
        const off = mapping.enabled === false;
        let description = mapping.description || '';
        if (off) {
          description = document.createDocumentFragment();
          if (mapping.description) {
            description.appendChild(document.createTextNode(clean(mapping.description) + ' '));
          }
          description.appendChild(el('span', 'tag', t('report.forward.off')));
        }
        return {
          cells: [String(mapping.external_port), mapping.protocol || '', target, description],
          off: off,
        };
      });
      const wrap = el('div', 'card table');
      wrap.appendChild(table(headers, rowsOut));
      box.appendChild(wrap);
    } else if (router.mappings_complete !== false) {
      box.appendChild(el('p', 'ok', t('ui.router.none')));
    }
    if (router.mappings_complete === false) {
      box.appendChild(el('p', 'warn', t('ui.router.incomplete')));
    }
  }

  function nameCell(device) {
    const tags = [];
    if (device.is_gateway) tags.push(t('ui.tag.gateway'));
    if (device.is_self) tags.push(t('ui.tag.self'));
    if (!device.confirmed) tags.push(t('ui.tag.recent'));
    if (!device.name && !tags.length) return '';
    const cell = document.createDocumentFragment();
    if (device.name) cell.appendChild(el('span', 'name', device.name));
    tags.forEach(function (tag) {
      cell.appendChild(el('span', 'tag', tag));
    });
    return cell;
  }

  function portsCell(device) {
    const services = list(device.services)
      .filter(Boolean)
      .slice()
      .sort(function (a, b) {
        return a.port - b.port;
      });
    if (!services.length) return '';
    const cell = document.createDocumentFragment();
    services.forEach(function (service) {
      const chip = el('span', 'port', String(service.port));
      if (service.name) {
        chip.appendChild(document.createTextNode(' '));
        chip.appendChild(el('span', 'port-name', service.name));
      }
      cell.appendChild(chip);
    });
    return cell;
  }

  function renderDevices(devices) {
    setText($('device-count'), String(devices.length));
    show($('search-box'), devices.length > 0);
    const box = $('device-table');
    clear(box);
    state.deviceRows = [];
    if (!devices.length) {
      box.appendChild(el('p', 'empty-note', t('report.devices.none')));
      filterDevices();
      return;
    }
    const headers = [
      t('ui.col.address'),
      t('ui.col.name'),
      t('ui.col.kind'),
      t('ui.col.maker'),
      t('ui.col.ports'),
    ];
    const rows = devices.map(function (device) {
      const made = maker(device);
      const kind = kindText(device.kind);
      const words = [device.ip, device.mac, device.name, made, kind, device.kind];
      return {
        cells: [device.ip, nameCell(device), kind, made, portsCell(device)],
        haystack: fold(words.filter(Boolean).join(' ')),
      };
    });
    box.appendChild(table(headers, rows));
    state.deviceRows = rows;
    filterDevices();
  }

  function filterDevices() {
    const words = fold($('search').value).split(/\s+/).filter(Boolean);
    let shown = 0;
    state.deviceRows.forEach(function (row) {
      const match = words.every(function (word) {
        return row.haystack.indexOf(word) >= 0;
      });
      row.node.hidden = !match;
      if (match) shown += 1;
    });
    const total = state.deviceRows.length;
    show($('no-match'), total > 0 && shown === 0);
    show($('device-table'), total === 0 || shown > 0);
    setText(
      $('device-shown'),
      words.length && total ? t('gui.devices.shown', { shown: shown, total: total }) : ''
    );
  }

  function renderNotes(notes) {
    show($('notes'), notes.length > 0);
    setText($('notes-title'), t('report.notes') + ' (' + notes.length + ')');
    const items = $('notes-list');
    clear(items);
    notes.forEach(function (note) {
      items.appendChild(el('li', null, (note && note.message) || ''));
    });
  }

  // Saving

  // The server names its downloads; this is the same name for when it does not say.
  function fileName(kind, response) {
    const given = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '');
    if (given) return given[1];
    const moment = (state.result && parseTime(state.result.started)) || new Date();
    const stamp =
      pad(moment.getFullYear(), 4) +
      pad(moment.getMonth() + 1) +
      pad(moment.getDate()) +
      '-' +
      pad(moment.getHours()) +
      pad(moment.getMinutes());
    return kind === 'report' ? 'hearthscan-report-' + stamp + '.html' : 'hearthscan-' + stamp + '.json';
  }

  function setSave(key, params, options) {
    const extra = options || {};
    state.save = key
      ? { key: key, params: params || null, tone: extra.tone || '', copy: !!extra.copy, box: !!extra.box }
      : null;
    renderSave();
  }

  function renderSave() {
    const save = state.save;
    const message = $('save-message');
    message.className = 'save-message' + (save && save.tone ? ' tone-' + save.tone : '');
    setText(message, save ? t(save.key, save.params) : '');
    show($('copy'), !!(save && save.copy));
    const box = !!(save && save.box && state.pending);
    show($('copy-box'), box);
    $('copy-text').value = box ? state.pending.text : '';
  }

  // Downloads need the token header, so the file comes as a blob and is saved
  // through a temporary link. Not every window engine saves those, hence the copy offer.
  async function save(kind) {
    setSave(null);
    let text;
    let name;
    try {
      const path =
        kind === 'report' ? '/api/report?lang=' + encodeURIComponent(state.language) : '/api/result.json';
      const response = await request(path);
      if (!response.ok) throw httpError(response);
      text = await response.text();
      name = fileName(kind, response);
    } catch (error) {
      setSave('gui.save.failed', { reason: error.message }, { tone: 'error' });
      return;
    }
    state.pending = { text: text, name: name };
    const type = kind === 'report' ? 'text/html' : 'application/json';
    const url = URL.createObjectURL(new Blob([text], { type: type + ';charset=utf-8' }));
    const link = el('a');
    link.href = url;
    link.download = name;
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 60000);
    // There is no telling whether the download went through, so copying stays on offer.
    setSave('gui.save.started', { name: name }, { copy: true });
  }

  function copyByHand(text) {
    const area = el('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.className = 'sr-only';
    document.body.appendChild(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (error) {
      copied = false;
    }
    area.remove();
    return copied;
  }

  async function copyPending() {
    const pending = state.pending;
    if (!pending) return;
    let copied = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(pending.text);
        copied = true;
      } catch (error) {
        copied = false;
      }
    }
    if (!copied) copied = copyByHand(pending.text);
    if (copied) {
      setSave('gui.save.copied', { name: pending.name });
      return;
    }
    setSave('gui.save.copy_failed', { name: pending.name }, { box: true });
    const area = $('copy-text');
    area.focus();
    area.select();
  }

  // Actions

  function backToRest() {
    state.stopping = false;
    go(state.result ? 'result' : 'start');
  }

  function failRequest(error) {
    if (refused(error)) {
      go('fatal');
      return;
    }
    setMessage('gui.error.request', { reason: error.message }, 'error');
    backToRest();
  }

  async function refreshInfo() {
    state.info = await getJSON('/api/info');
    state.noNetwork = !state.info.network;
  }

  async function startScan(probe) {
    state.probe = probe;
    state.probed = null;
    state.progress = null;
    state.notes = [];
    state.stopping = false;
    state.noNetwork = false;
    setMessage(null);
    setSave(null);
    go('scan');
    let response;
    try {
      response = await request('/api/scan', 'POST', { probe: probe });
    } catch (error) {
      failRequest(error);
      return;
    }
    // 409: a check is already running, and its events take over this page.
    if (response.status === 202 || response.status === 409) return;
    if (response.status === 503) {
      try {
        await refreshInfo();
      } catch (error) {
        // The start screen says there is no network either way.
      }
      state.noNetwork = true;
      if (state.result) setMessage('ui.no_network', null, 'warn');
      backToRest();
      return;
    }
    failRequest(httpError(response));
  }

  async function stopScan() {
    state.stopping = true;
    renderScan(false);
    try {
      const response = await request('/api/stop', 'POST');
      if (!response.ok) throw httpError(response);
      const data = await response.json();
      // When something was stopped, the "stopped" event moves the page on.
      if (!data.stopped) backToRest();
    } catch (error) {
      failRequest(error);
    }
  }

  async function retry() {
    try {
      await refreshInfo();
    } catch (error) {
      failRequest(error);
      return;
    }
    setMessage(null);
    go('start');
  }

  async function switchLanguage(code) {
    if (code === state.language) return;
    const hadFocus = $('lang').contains(document.activeElement);
    try {
      const response = await request('/api/language', 'POST', { language: code });
      if (!response.ok) throw httpError(response);
      useTexts(await getJSON('/api/texts?lang=' + encodeURIComponent(code)));
    } catch (error) {
      if (refused(error)) go('fatal');
      else setMessage('gui.error.request', { reason: error.message }, 'error');
      return;
    }
    render();
    if (hadFocus && !$('lang').contains(document.activeElement)) {
      const pressed = $('lang').querySelector('[aria-pressed="true"]');
      if (pressed) pressed.focus();
    }
  }

  // Events from the server

  function onProgress(data) {
    state.progress = {
      stage: String(data.stage || ''),
      done: Number(data.done) || 0,
      total: Number(data.total) || 0,
    };
    if (state.view === 'scan') {
      renderScan(false);
      return;
    }
    // A check started somewhere else, in another window or tab.
    state.notes = [];
    state.stopping = false;
    go('scan');
  }

  function onNote(data) {
    const note = { source: data.source, message: data.message };
    state.notes.push(note);
    if (state.view === 'scan') $('scan-notes').appendChild(noteLine(note));
  }

  function sameResult(a, b) {
    return !!(a && b && a.started === b.started && a.finished === b.finished);
  }

  function onResult(data) {
    if (!data.result || typeof data.result !== 'object') return;
    // A reconnect replays the last result; keep the page as it is then.
    if (state.view === 'result' && sameResult(state.result, data.result)) return;
    state.result = data.result;
    // The server may say whether the probes ran; otherwise only a check
    // started from this page tells.
    if (typeof data.probed === 'boolean') state.probed = data.probed;
    else if (state.view === 'scan') state.probed = state.probe;
    state.stopping = false;
    state.pending = null;
    state.save = null;
    go('result');
  }

  function onError(data) {
    setMessage('gui.error.scan', { message: data.message || '' }, 'error');
    backToRest();
  }

  function onStopped() {
    setMessage('ui.stopped', null, 'info');
    backToRest();
  }

  function onIdle() {
    if (state.view === 'loading') go('start');
  }

  function setLost(lost) {
    clearTimeout(state.lostTimer);
    if (lost) {
      // A reconnect usually takes a moment; only say so when it does not.
      state.lostTimer = setTimeout(function () {
        state.lost = true;
        renderBanner();
      }, 1500);
    } else if (state.lost) {
      state.lost = false;
      renderBanner();
    }
  }

  function connect() {
    const source = new EventSource('/api/events?token=' + encodeURIComponent(token));
    // The server's "error" event shares its name with the stream's own
    // connection errors. Only the server's carries data.
    function on(name, handler) {
      source.addEventListener(name, function (event) {
        if (typeof event.data !== 'string') return;
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (error) {
          return;
        }
        handler(data && typeof data === 'object' ? data : {});
      });
    }
    source.addEventListener('open', function () {
      setLost(false);
    });
    source.addEventListener('error', function (event) {
      if (typeof event.data === 'string') return;
      setLost(true);
      // A refused or broken stream is not retried by the browser.
      if (source.readyState === EventSource.CLOSED) {
        source.close();
        setTimeout(connect, 3000);
      }
    });
    on('progress', onProgress);
    on('note', onNote);
    on('result', onResult);
    on('error', onError);
    on('stopped', onStopped);
    on('idle', onIdle);
  }

  // Start

  function wire() {
    $('scan').addEventListener('click', function () {
      startScan(true);
    });
    $('scan-ports').addEventListener('click', function () {
      startScan(false);
    });
    $('again').addEventListener('click', function () {
      startScan(true);
    });
    $('stop').addEventListener('click', stopScan);
    $('retry').addEventListener('click', retry);
    $('save-report').addEventListener('click', function () {
      save('report');
    });
    $('save-json').addEventListener('click', function () {
      save('json');
    });
    $('copy').addEventListener('click', copyPending);
    $('search').addEventListener('input', filterDevices);
  }

  async function boot() {
    // Anything but visible ASCII cannot go in a header, and fetch would refuse every request.
    if (!/^[\x21-\x7e]+$/.test(token)) {
      go('fatal');
      return;
    }
    try {
      const info = await getJSON('/api/info');
      useTexts(await getJSON('/api/texts?lang=' + encodeURIComponent(info.language || 'en')));
      state.info = info;
      state.noNetwork = !info.network;
    } catch (error) {
      if (refused(error)) {
        go('fatal');
        return;
      }
      // Most likely the server is still starting up.
      setTimeout(boot, 2000);
      return;
    }
    // The event stream replays a running check or the last result as soon as
    // it connects. The result is also fetched, so it shows even when the stream is slow.
    if (state.info.scanning) {
      go('scan');
    } else if (state.info.has_result) {
      go('loading');
      getJSON('/api/result')
        .then(function (result) {
          if (state.view === 'loading') onResult({ result: result });
        })
        .catch(function () {
          // The stream brings it, or says what happened instead.
        });
    } else {
      go('start');
    }
    connect();
  }

  wire();
  boot();
})();
