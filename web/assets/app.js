/* ============================================================================
   Qorǵau — общий каркас  (app.js)  ·  глобальный объект  window.Qorgau
   Ноль внешних ресурсов. Все данные из API рендерятся через textContent/createElement.

   ──────────────────────────────────────────────────────────────────────────
   ПОДКЛЮЧЕНИЕ (на любой странице):
     <link rel="stylesheet" href="assets/app.css"/>
     <script src="assets/app.js" defer></script>
     <script defer>
       addEventListener('DOMContentLoaded', () => {
         Qorgau.mountNav('#nav', 'check');     // верхняя навигация + подсветка
         Qorgau.i18n.apply();                  // проставить [data-i18n]
       });
     </script>

   ──────────────────────────────────────────────────────────────────────────
   ПУБЛИЧНЫЙ API  (Qorgau.*)
     API                       — базовый origin ('' same-origin | http://localhost:8080 для file://)
     fetchJSON(path, opts)     — fetch + JSON, бросает {kind:'rate'|'bad'|'net', ...}
     i18n.t(key)               — перевод по текущему языку (фолбэк на ru → key)
     i18n.lang                 — 'ru' | 'kz'
     i18n.setLang('ru'|'kz')   — сменить язык (пишет localStorage, обновляет подписчиков)
     i18n.extend({ru:{…}, kz:{…}})  — ДОБАВИТЬ свои ключи (страницы регистрируют словарь)
     i18n.onChange(cb)         — подписка на смену языка; сразу вызывает cb(lang)
     i18n.apply(root=document) — проставить textContent для [data-i18n] и
                                 placeholder для [data-i18n-ph], title для [data-i18n-title]
     icon(name)                — <svg> line-иконка (Element). Набор: shield, phone, scan,
                                 link, message, card, alert, shield-check, graduation,
                                 scales, map-pin, radar, user-plus, eye, check, x, chevron
     iconHTML(name)            — та же иконка строкой (для статичных шаблонов)
     NAV_ITEMS                 — массив пунктов навигации (id, href, i18n, icon)
     nav(items, current)       — вернуть <header.qg-nav> (items=null → NAV_ITEMS)
     mountNav(target, current) — смонтировать навигацию в target (селектор|Element)
     Gauge(el, score, level)   — фирменный спидометр 0..100 (анимация дуги/стрелки/счётчика,
                                 плавная смена цвета дуги/числа при обновлении)
     renderVerdict(el, data)   — единый рендер ответа /analyze-совместимой формы
     toast(msg, kind)          — 'info'|'success'|'error'|'warn'
     skeleton.show(el)/hide(el)/fill(el,n,arc)/line(n) — состояние загрузки

   ──────────────────────────────────────────────────────────────────────────
   НОВОЕ в v2 (motion-утилиты, все с reduced-motion guard):
     reduced()                 — true, если пользователь просит меньше движения
     countUp(el, to, opts)     — плавный счётчик. opts:{from,duration,decimals,
                                 prefix,suffix,locale,group:bool}. Пример:
                                   Qorgau.countUp(node, 1240, {group:true, suffix:'+'})
     reveal(target?)           — staggered-reveal через IntersectionObserver.
                                 target: селектор | Element | NodeList (по умолч.
                                 '[data-reveal]'). Разметка: <div data-reveal>…,
                                 data-reveal="left|right|scale" — направление,
                                 data-reveal-delay="120" — доп. задержка (мс).
     shieldRadar(canvas, opts) — СИГНАТУРНЫЙ фон «щит + радар-скан» на Canvas
                                 (метафора защитной сети). Возвращает {stop,start}.
                                 Лёгкий, 60fps, стоп при reduced-motion/скрытой вкладке.
     magnetic(el, opts?)       — «магнитная» кнопка (тянется к курсору). Авто на .btn.magnetic.
     tilt(el, opts?)           — лёгкий 3D-наклон карточки. Авто на .card.tilt.
     scanLoader(host?)         — «сканирование» вместо спиннера. Возвращает узел
                                 с методом .stop() (удаляет себя). Без host — detached.
     tabs(el)                  — плавный скользящий индикатор для .tabs[data-ink].
                                 Авто-инициализация на всех .tabs[data-ink].

   Авто-инициализация на DOMContentLoaded (идемпотентно):
     .btn.magnetic → magnetic · .card.tilt → tilt · [data-reveal] → reveal ·
     .tabs[data-ink] → tabs. Всё уважает prefers-reduced-motion.

   Контракт data для renderVerdict (docs/API.md §POST /analyze):
     { risk_score, risk_level:'low|medium|high', scheme_title, impersonated_brand,
       flags:[str], explanation, recommended_actions:[str],
       iocs:[{type,value_masked}], degraded:bool }
   ========================================================================== */
(function (window, document) {
  'use strict';

  // Прогрессивное улучшение: помечаем документ, что JS активен (для reveal-скрытия).
  document.documentElement.classList.add('has-js');

  /* ------------------------------ motion guard ------------------------- */
  var _rmq = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  function reduced() { return !!(_rmq && _rmq.matches); }

  /* ------------------------------ API ---------------------------------- */
  var API = location.protocol === 'file:' ? 'http://localhost:8080' : '';

  async function fetchJSON(path, opts) {
    var r;
    try {
      r = await fetch(API + path, opts);
    } catch (_) {
      throw { kind: 'net' };
    }
    if (r.status === 429) {
      var wait = 0;
      try { wait = (await r.json()).retry_after_sec || 0; } catch (_) {}
      throw { kind: 'rate', wait: wait };
    }
    if (r.status === 400) throw { kind: 'bad' };
    if (!r.ok) throw { kind: 'net', status: r.status };
    if (r.status === 204) return null;
    try { return await r.json(); } catch (_) { throw { kind: 'bad' }; }
  }

  /* ------------------------------ i18n --------------------------------- */
  var DICT = {
    ru: {
      brand: 'Qorǵau',
      navCheck: 'Проверить', navTrainer: 'Тренажёр', navGuard: 'Под защитой',
      navHelp: 'Помощь', navShield: 'Shield', navRadar: 'Радар',
      lvlLow: 'Низкий риск', lvlMedium: 'Средний риск', lvlHigh: 'Высокий риск',
      vActions: 'Что делать', vIocs: 'Индикаторы (обезличены)', vBrand: 'Выдают себя за:',
      vOf: '/ 100',
      degraded: 'Базовый режим: ИИ временно недоступен, вердикт вынесен по правилам.',
      errNet: 'Не удалось связаться с сервисом. Проверьте соединение и попробуйте ещё раз.',
      errRate: 'Слишком много запросов. Подождите немного и повторите.',
      errBad: 'Не получилось разобрать данные. Попробуйте ещё раз.'
    },
    kz: {
      brand: 'Qorǵau',
      navCheck: 'Тексеру', navTrainer: 'Жаттықтырғыш', navGuard: 'Қорғауда',
      navHelp: 'Көмек', navShield: 'Shield', navRadar: 'Радар',
      lvlLow: 'Төмен қауіп', lvlMedium: 'Орташа қауіп', lvlHigh: 'Жоғары қауіп',
      vActions: 'Не істеу керек', vIocs: 'Индикаторлар (иесіздендірілген)',
      vBrand: 'Өздерін былай таныстырады:', vOf: '/ 100',
      degraded: 'Базалық режим: ЖИ уақытша қолжетімсіз, шешім ережелер бойынша шығарылды.',
      errNet: 'Сервиспен байланыс орнатылмады. Қосылымды тексеріп, қайталап көріңіз.',
      errRate: 'Сұраныс тым көп. Сәл күтіп, қайталаңыз.',
      errBad: 'Деректерді талдау мүмкін болмады. Қайталап көріңіз.'
    }
  };

  var _lang = localStorage.getItem('qorgau_lang') || 'ru';
  if (!DICT[_lang]) _lang = 'ru';
  var _subs = [];

  var i18n = {
    get lang() { return _lang; },
    t: function (key) {
      var d = DICT[_lang] || DICT.ru;
      return (key in d) ? d[key] : (key in DICT.ru ? DICT.ru[key] : key);
    },
    setLang: function (l) {
      if (!DICT[l] || l === _lang) { if (DICT[l]) _lang = l; else return; }
      _lang = l;
      try { localStorage.setItem('qorgau_lang', l); } catch (_) {}
      document.documentElement.lang = l === 'kz' ? 'kk' : 'ru';
      i18n.apply();
      for (var i = 0; i < _subs.length; i++) { try { _subs[i](l); } catch (_) {} }
    },
    extend: function (add) {
      if (!add) return;
      ['ru', 'kz'].forEach(function (lng) {
        if (add[lng]) for (var k in add[lng]) if (Object.prototype.hasOwnProperty.call(add[lng], k)) DICT[lng][k] = add[lng][k];
      });
      i18n.apply();
    },
    onChange: function (cb) { if (typeof cb === 'function') { _subs.push(cb); try { cb(_lang); } catch (_) {} } },
    apply: function (root) {
      root = root || document;
      root.querySelectorAll('[data-i18n]').forEach(function (el) {
        el.textContent = i18n.t(el.getAttribute('data-i18n'));
      });
      root.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
        el.setAttribute('placeholder', i18n.t(el.getAttribute('data-i18n-ph')));
      });
      root.querySelectorAll('[data-i18n-title]').forEach(function (el) {
        var v = i18n.t(el.getAttribute('data-i18n-title'));
        el.setAttribute('title', v); if (el === document.querySelector('title')) document.title = v;
      });
    }
  };

  /* ------------------------------ icons -------------------------------- */
  // 24-сетка, stroke:currentColor, stroke-width 1.75, round. Внутренняя разметка статична.
  var ICONS = {
    shield: '<path d="M12 22s8-4 8-10V5.2l-8-3-8 3V12c0 6 8 10 8 10Z"/>',
    'shield-check': '<path d="M12 22s8-4 8-10V5.2l-8-3-8 3V12c0 6 8 10 8 10Z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
    phone: '<path d="M6.5 3.5H9l1.6 4-2 1.4a11 11 0 0 0 5 5l1.4-2 4 1.6V19a2 2 0 0 1-2.2 2A16.5 16.5 0 0 1 4.5 5.7 2 2 0 0 1 6.5 3.5Z"/>',
    scan: '<path d="M4 8.5V6a2 2 0 0 1 2-2h2.5M15.5 4H18a2 2 0 0 1 2 2v2.5M20 15.5V18a2 2 0 0 1-2 2h-2.5M8.5 20H6a2 2 0 0 1-2-2v-2.5"/><path d="M4 12h16"/>',
    link: '<path d="M10.5 13.5a4 4 0 0 0 5.7 0l2.3-2.3a4 4 0 0 0-5.7-5.7l-1.2 1.2"/><path d="M13.5 10.5a4 4 0 0 0-5.7 0l-2.3 2.3a4 4 0 0 0 5.7 5.7l1.2-1.2"/>',
    message: '<path d="M20.5 12a8 8 0 0 1-11.6 7.1L4 20.5l1.4-4.9A8 8 0 1 1 20.5 12Z"/>',
    card: '<rect x="3" y="5.5" width="18" height="13" rx="2.4"/><path d="M3 9.5h18"/><path d="M6.5 14.5h3"/>',
    alert: '<path d="M12 3.5 2.7 20h18.6L12 3.5Z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
    graduation: '<path d="M12 4.2 2.5 9 12 13.8 21.5 9 12 4.2Z"/><path d="M6 11v4.2c0 1 2.7 2.8 6 2.8s6-1.8 6-2.8V11"/>',
    scales: '<path d="M12 4v16"/><path d="M7 20.5h10"/><path d="M4.5 7.2h15"/><path d="M4.5 7.2 2 13.2a3 3 0 0 0 5 0L4.5 7.2Z"/><path d="M19.5 7.2 17 13.2a3 3 0 0 0 5 0l-2.5-6Z"/>',
    'map-pin': '<path d="M12 21.5c4-4.2 7-7.4 7-11a7 7 0 0 0-14 0c0 3.6 3 6.8 7 11Z"/><circle cx="12" cy="10.3" r="2.6"/>',
    radar: '<path d="M12 12 18.5 5.5"/><path d="M20.5 12a8.5 8.5 0 1 1-8.5-8.5"/><path d="M16.5 12a4.5 4.5 0 1 1-4.5-4.5"/>',
    'user-plus': '<circle cx="9.5" cy="8" r="3.4"/><path d="M3.5 20a6 6 0 0 1 12 0"/><path d="M18.5 7.5v6"/><path d="M15.5 10.5h6"/>',
    eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
    check: '<path d="M4.5 12.5l4.5 4.5L19.5 6.5"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    chevron: '<path d="M9 6l6 6-6 6"/>'
  };

  function iconHTML(name) {
    var body = ICONS[name] || ICONS.alert;
    return '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      body + '</svg>';
  }
  function icon(name) {
    var tpl = document.createElement('template');
    tpl.innerHTML = iconHTML(name).trim();
    return tpl.content.firstChild;
  }

  /* ------------------------------ tiny DOM helper ---------------------- */
  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt != null) n.textContent = txt;
    return n;
  }

  /* ------------------------------ navigation --------------------------- */
  var NAV_ITEMS = [
    { id: 'check', href: 'check.html', i18n: 'navCheck', icon: 'scan' },
    { id: 'trainer', href: 'trainer.html', i18n: 'navTrainer', icon: 'graduation' },
    { id: 'guard', href: 'guard.html', i18n: 'navGuard', icon: 'user-plus' },
    { id: 'help', href: 'help.html', i18n: 'navHelp', icon: 'scales' },
    { id: 'shield', href: 'shield.html', i18n: 'navShield', icon: 'shield' },
    { id: 'radar', href: 'radar.html', i18n: 'navRadar', icon: 'radar' }
  ];

  function nav(items, current) {
    items = items || NAV_ITEMS;
    var header = el('header', 'qg-nav');
    header.setAttribute('role', 'navigation');
    var inner = el('div', 'qg-nav-in');

    // brand → на лендинг
    var brand = document.createElement('a');
    brand.className = 'qg-brand'; brand.href = 'index.html';
    var mark = icon('shield-check'); mark.classList.remove('ic'); mark.classList.add('mark');
    brand.appendChild(mark);
    brand.appendChild(el('span', null, i18n.t('brand')));
    inner.appendChild(brand);

    // links
    var links = el('div', 'qg-links');
    items.forEach(function (it) {
      var a = document.createElement('a');
      a.className = 'qg-link' + (it.id === current ? ' on' : '');
      a.href = it.href;
      if (it.id === current) a.setAttribute('aria-current', 'page');
      a.appendChild(icon(it.icon));
      var lbl = el('span', null, i18n.t(it.i18n));
      lbl.setAttribute('data-i18n', it.i18n);
      a.appendChild(lbl);
      links.appendChild(a);
    });
    inner.appendChild(links);

    // language switch
    var lang = el('div', 'qg-lang');
    lang.setAttribute('role', 'group');
    lang.setAttribute('aria-label', 'Language');
    [['ru', 'RU'], ['kz', 'QZ']].forEach(function (pair) {
      var b = document.createElement('button');
      b.type = 'button'; b.textContent = pair[1];
      b.className = (_lang === pair[0] ? 'on' : '');
      b.addEventListener('click', function () { i18n.setLang(pair[0]); });
      lang.appendChild(b);
    });
    inner.appendChild(lang);

    // держим активную кнопку языка в синхроне
    i18n.onChange(function (l) {
      var bs = lang.querySelectorAll('button');
      bs[0].className = (l === 'ru' ? 'on' : '');
      bs[1].className = (l === 'kz' ? 'on' : '');
      i18n.apply(header);
    });

    header.appendChild(inner);
    return header;
  }

  function mountNav(target, current) {
    var host = typeof target === 'string' ? document.querySelector(target) : target;
    if (!host) return null;
    var n = nav(NAV_ITEMS, current);
    host.textContent = '';
    host.appendChild(n);
    return n;
  }

  /* ------------------------------ Gauge -------------------------------- */
  var ARC_LEN = Math.PI * 86; // ~270.18
  var LEVEL_VAR = { low: 'var(--risk-low)', medium: 'var(--risk-med)', high: 'var(--risk-high)' };

  // Gauge(el, score, level) — строит/обновляет спидометр внутри el.
  function Gauge(host, score, level) {
    if (!host) return;
    score = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
    level = LEVEL_VAR[level] ? level : 'low';
    var color = LEVEL_VAR[level];
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (!host.classList.contains('gauge')) {
      host.className = (host.className ? host.className + ' ' : '') + 'gauge';
      host.innerHTML =
        '<svg viewBox="0 0 220 120" aria-hidden="true">' +
        '<path class="g-track" d="M 24 104 A 86 86 0 0 1 196 104"/>' +
        '<path class="g-arc" d="M 24 104 A 86 86 0 0 1 196 104" ' +
        'stroke-dasharray="' + ARC_LEN.toFixed(2) + '" stroke-dashoffset="' + ARC_LEN.toFixed(2) + '"/>' +
        '<g class="g-needle" style="transform:rotate(-90deg)">' +
        '<path d="M 110 38 L 113.5 100 A 6 6 0 1 1 106.5 100 Z"/>' +
        '<circle cx="110" cy="104" r="3.2" fill="var(--bg)"/></g>' +
        '</svg>' +
        '<div class="g-readout"><span class="g-num">0</span> <span class="g-of">/ 100</span></div>';
    }
    host.setAttribute('data-level', level);
    var arc = host.querySelector('.g-arc');
    var needle = host.querySelector('.g-needle');
    var needlePath = needle.querySelector('path');
    var num = host.querySelector('.g-num');
    arc.style.stroke = color;
    needlePath.style.fill = color;

    var targetOffset = ARC_LEN * (1 - score / 100);
    var targetRot = score * 1.8 - 90;

    if (reduce) {
      arc.style.transition = 'none';
      needle.style.transition = 'none';
      arc.setAttribute('stroke-dashoffset', String(targetOffset));
      needle.style.transform = 'rotate(' + targetRot + 'deg)';
      num.textContent = String(score);
      return;
    }

    // сброс к нулю, затем анимация (дуга/стрелка через CSS-transition)
    arc.style.transition = 'none';
    needle.style.transition = 'none';
    arc.setAttribute('stroke-dashoffset', String(ARC_LEN));
    needle.style.transform = 'rotate(-90deg)';
    void arc.getBoundingClientRect(); // reflow
    arc.style.transition = '';
    needle.style.transition = '';
    arc.setAttribute('stroke-dashoffset', String(targetOffset));
    needle.style.transform = 'rotate(' + targetRot + 'deg)';

    // счётчик числа: rAF + easeOutCubic
    var token = (host.__gaugeToken = (host.__gaugeToken || 0) + 1);
    var t0 = performance.now(), dur = 950;
    (function tick(now) {
      if (host.__gaugeToken !== token) return;
      var p = Math.min(1, (now - t0) / dur);
      num.textContent = String(Math.round(score * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }

  /* ------------------------------ renderVerdict ------------------------ */
  var LVL_META = {
    low: { cls: 'low', ic: 'shield-check', key: 'lvlLow' },
    medium: { cls: 'med', ic: 'alert', key: 'lvlMedium' },
    high: { cls: 'high', ic: 'alert', key: 'lvlHigh' }
  };

  // renderVerdict(el, data) — единый рендер вердикта. ВСЕ данные через textContent.
  function renderVerdict(host, d) {
    if (!host) return;
    d = d || {};
    var level = LVL_META[d.risk_level] ? d.risk_level : 'low';
    var meta = LVL_META[level];
    var score = Math.max(0, Math.min(100, Number(d.risk_score) || 0));
    var calm = level === 'low';

    host.textContent = '';
    var base = host.className.replace(/\bverdict\b/g, '').replace(/\breveal\b/g, '')
      .replace(/\bis-high\b/g, '').replace(/\s+/g, ' ').trim();
    host.className = (base + ' verdict reveal' + (level === 'high' ? ' is-high' : '')).trim();

    // gauge
    var g = el('div');
    host.appendChild(g);
    Gauge(g, score, level);

    // level badge
    var badgeRow = el('div', 'v-badge-row');
    var badge = el('span', 'badge ' + meta.cls);
    badge.appendChild(icon(meta.ic));
    badge.appendChild(el('span', null, i18n.t(meta.key)));
    badgeRow.appendChild(badge);
    host.appendChild(badgeRow);

    // scheme title
    if (d.scheme_title) host.appendChild(el('div', 'v-scheme', d.scheme_title));

    // impersonated brand
    if (d.impersonated_brand) {
      var brand = el('div', 'v-brand');
      brand.appendChild(el('span', null, i18n.t('vBrand') + ' '));
      var strong = document.createElement('strong'); strong.textContent = d.impersonated_brand;
      brand.appendChild(strong);
      host.appendChild(brand);
    }

    // flags
    var flags = Array.isArray(d.flags) ? d.flags : [];
    if (flags.length) {
      var fl = el('div', 'v-flags');
      flags.forEach(function (f) {
        var chip = el('span', 'v-flag' + (calm ? ' calm' : ''));
        chip.appendChild(icon(calm ? 'check' : 'alert'));
        chip.appendChild(el('span', null, String(f)));
        fl.appendChild(chip);
      });
      host.appendChild(fl);
    }

    // explanation
    if (d.explanation) host.appendChild(el('p', 'v-expl', d.explanation));

    // recommended actions
    var acts = Array.isArray(d.recommended_actions) ? d.recommended_actions : [];
    if (acts.length) {
      var box = el('div', 'v-actions');
      box.appendChild(el('div', 'v-h', i18n.t('vActions')));
      var ul = document.createElement('ul');
      acts.forEach(function (a) {
        var li = document.createElement('li');
        li.appendChild(icon('check'));
        li.appendChild(el('span', null, String(a)));
        ul.appendChild(li);
      });
      box.appendChild(ul);
      host.appendChild(box);
    }

    // iocs
    var iocs = Array.isArray(d.iocs) ? d.iocs : [];
    if (iocs.length) {
      var iw = el('div', 'v-iocs');
      iw.appendChild(el('div', 'v-h', i18n.t('vIocs')));
      var list = el('div');
      iocs.forEach(function (i) {
        var chip = el('span', 'v-ioc');
        chip.appendChild(el('span', 'v-ioc-t', (i.type || '') + ':'));
        chip.appendChild(el('span', null, ' ' + (i.value_masked || '')));
        list.appendChild(chip);
      });
      iw.appendChild(list);
      host.appendChild(iw);
    }

    // degraded
    if (d.degraded) {
      var dg = el('div', 'v-degraded');
      var db = el('span', 'badge degraded');
      db.appendChild(icon('alert'));
      db.appendChild(el('span', null, i18n.t('degraded')));
      dg.appendChild(db);
      host.appendChild(dg);
    }
    return host;
  }

  /* ------------------------------ toast -------------------------------- */
  var _toastHost = null;
  function toastHost() {
    if (!_toastHost) {
      _toastHost = el('div', 'qg-toasts');
      _toastHost.setAttribute('aria-live', 'polite');
      document.body.appendChild(_toastHost);
    }
    return _toastHost;
  }
  var TOAST_IC = { success: 'check', error: 'alert', warn: 'alert', info: 'eye' };
  function toast(msg, kind) {
    kind = kind || 'info';
    var host = toastHost();
    var t = el('div', 'qg-toast ' + kind);
    t.appendChild(icon(TOAST_IC[kind] || 'eye'));
    t.appendChild(el('span', null, String(msg)));
    host.appendChild(t);
    var life = setTimeout(remove, 4200);
    t.addEventListener('click', remove);
    function remove() {
      clearTimeout(life);
      if (!t.parentNode) return;
      t.classList.add('leaving');
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 320);
    }
    return t;
  }

  /* ------------------------------ skeleton ----------------------------- */
  var skeleton = {
    show: function (host) { if (host) host.classList.remove('hidden'); },
    hide: function (host) { if (host) host.classList.add('hidden'); },
    // построить n строк-заглушек внутри host (плюс опц. дугу спидометра)
    fill: function (host, n, withArc) {
      if (!host) return;
      host.textContent = '';
      if (withArc) host.appendChild(el('div', 'skeleton arc'));
      host.appendChild(el('div', 'skeleton title'));
      for (var i = 0; i < (n || 3); i++) {
        var l = el('div', 'skeleton line');
        l.style.width = (92 - i * 10) + '%';
        host.appendChild(l);
      }
    },
    line: function (n) {
      var frag = document.createDocumentFragment();
      for (var i = 0; i < (n || 1); i++) frag.appendChild(el('div', 'skeleton line'));
      return frag;
    }
  };

  /* ============================================================================
     v2 MOTION-УТИЛИТЫ (сигнатурный язык). Все с reduced-motion guard.
     ========================================================================== */

  /* ------------------------------ countUp ------------------------------ */
  function countUp(node, to, opts) {
    if (!node) return;
    opts = opts || {};
    to = Number(to) || 0;
    var from = Number(opts.from) || 0;
    var dur = opts.duration != null ? opts.duration : 1200;
    var dec = opts.decimals != null ? opts.decimals : 0;
    var pre = opts.prefix || '', suf = opts.suffix || '';
    var group = opts.group !== false;
    var locale = opts.locale || 'ru-RU';
    function fmt(v) {
      var s;
      try {
        s = group
          ? v.toLocaleString(locale, { minimumFractionDigits: dec, maximumFractionDigits: dec })
          : v.toFixed(dec);
      } catch (_) { s = v.toFixed(dec); }
      return pre + s + suf;
    }
    if (reduced() || dur <= 0) { node.textContent = fmt(to); return; }
    var token = (node.__cuToken = (node.__cuToken || 0) + 1);
    var t0 = performance.now();
    (function tick(now) {
      if (node.__cuToken !== token) return;
      var p = Math.min(1, (now - t0) / dur);
      var eased = 1 - Math.pow(1 - p, 3);            // easeOutCubic
      node.textContent = fmt(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(tick);
      else node.textContent = fmt(to);
    })(t0);
  }

  /* ------------------------------ reveal ------------------------------- */
  var _revealIO = null, _revealSeen = new WeakSet();
  function _resolveNodes(target) {
    if (!target) return document.querySelectorAll('[data-reveal]');
    if (typeof target === 'string') return document.querySelectorAll(target);
    if (target.nodeType === 1) return [target];
    if (target.length != null) return target;          // NodeList / Array
    return [];
  }
  function reveal(target) {
    var nodes = _resolveNodes(target);
    if (!nodes || !nodes.length) return;
    if (reduced() || !('IntersectionObserver' in window)) {
      Array.prototype.forEach.call(nodes, function (n) { n.classList.add('is-in'); });
      return;
    }
    if (!_revealIO) {
      _revealIO = new IntersectionObserver(function (entries, obs) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          var n = e.target;
          // stagger: индекс среди соседей с [data-reveal] в общем родителе
          var extra = parseInt(n.getAttribute('data-reveal-delay') || '0', 10) || 0;
          var idx = 0, sib = n;
          while ((sib = sib.previousElementSibling)) if (sib.hasAttribute('data-reveal')) idx++;
          n.style.transitionDelay = (Math.min(idx, 6) * 70 + extra) + 'ms';
          n.classList.add('is-in');
          obs.unobserve(n);
        });
      }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    }
    Array.prototype.forEach.call(nodes, function (n) {
      if (_revealSeen.has(n)) return;
      _revealSeen.add(n);
      _revealIO.observe(n);
    });
  }

  /* ------------------------------ shieldRadar -------------------------- */
  // Сигнатурный фон: концентрические кольца + вращающийся радар-скан + блипы,
  // вписанные в контур щита. Приглушённо. 60fps. Стоп при reduced-motion.
  function shieldRadar(canvas, opts) {
    if (!canvas || !canvas.getContext) return { stop: function () {}, start: function () {} };
    opts = opts || {};
    var ctx = canvas.getContext('2d');
    var c1 = opts.color1 || '59,130,246';     // blue
    var c2 = opts.color2 || '34,211,238';     // cyan
    var speed = opts.speed || 1;
    var raf = 0, running = false, w = 0, h = 0, dpr = 1, angle = 0;
    var blips = [];

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      var r = canvas.getBoundingClientRect();
      w = Math.max(1, r.width); h = Math.max(1, r.height);
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    function seed() {
      blips = [];
      for (var i = 0; i < 5; i++) {
        blips.push({ a: Math.random() * Math.PI * 2, r: 0.28 + Math.random() * 0.66, lit: 0 });
      }
    }
    function shieldPath(cx, cy, s) {
      // контур щита (нормализованный, s = радиус)
      ctx.beginPath();
      ctx.moveTo(cx, cy - s);
      ctx.bezierCurveTo(cx + s * 0.62, cy - s * 0.82, cx + s * 0.92, cy - s * 0.66, cx + s * 0.92, cy - s * 0.34);
      ctx.bezierCurveTo(cx + s * 0.92, cy + s * 0.4, cx + s * 0.5, cy + s * 0.86, cx, cy + s);
      ctx.bezierCurveTo(cx - s * 0.5, cy + s * 0.86, cx - s * 0.92, cy + s * 0.4, cx - s * 0.92, cy - s * 0.34);
      ctx.bezierCurveTo(cx - s * 0.92, cy - s * 0.66, cx - s * 0.62, cy - s * 0.82, cx, cy - s);
      ctx.closePath();
    }
    function frame() {
      if (!running) return;
      var cx = w * 0.5, cy = h * 0.5;
      var s = Math.min(w, h) * 0.42;
      ctx.clearRect(0, 0, w, h);
      ctx.save();
      shieldPath(cx, cy, s); ctx.clip();      // всё рисуем внутри щита

      // концентрические кольца
      for (var i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(cx, cy, s * (i / 4), 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(' + c1 + ',' + (0.05 + (4 - i) * 0.012) + ')';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      // крестовина
      ctx.strokeStyle = 'rgba(' + c1 + ',0.05)'; ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(cx - s, cy); ctx.lineTo(cx + s, cy);
      ctx.moveTo(cx, cy - s); ctx.lineTo(cx, cy + s); ctx.stroke();

      // радар-скан (сектор-градиент)
      var grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, s);
      grad.addColorStop(0, 'rgba(' + c2 + ',0.16)');
      grad.addColorStop(1, 'rgba(' + c2 + ',0)');
      ctx.save();
      ctx.translate(cx, cy); ctx.rotate(angle);
      ctx.beginPath(); ctx.moveTo(0, 0);
      ctx.arc(0, 0, s, -0.42, 0); ctx.closePath();
      ctx.fillStyle = grad; ctx.fill();
      // передний луч
      ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(s, 0);
      ctx.strokeStyle = 'rgba(' + c2 + ',0.5)'; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.restore();

      // блипы — загораются, когда луч проходит
      blips.forEach(function (b) {
        var beam = ((angle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
        var ba = ((b.a % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
        var d = Math.abs(beam - ba);
        if (d < 0.12 || d > Math.PI * 2 - 0.12) b.lit = 1;
        b.lit *= 0.965;
        var bx = cx + Math.cos(b.a) * s * b.r, by = cy + Math.sin(b.a) * s * b.r;
        ctx.beginPath(); ctx.arc(bx, by, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(' + c2 + ',' + (0.15 + b.lit * 0.7) + ')'; ctx.fill();
      });
      ctx.restore();

      // контур щита поверх
      shieldPath(cx, cy, s);
      ctx.strokeStyle = 'rgba(' + c1 + ',0.28)'; ctx.lineWidth = 1.5; ctx.stroke();

      angle += 0.012 * speed;
      raf = requestAnimationFrame(frame);
    }
    function staticFrame() {   // один кадр для reduced-motion
      running = true; angle = -0.6; frame(); running = false; cancelAnimationFrame(raf);
    }
    function start() {
      if (running) return;
      if (reduced()) { resize(); seed(); staticFrame(); return; }
      running = true; raf = requestAnimationFrame(frame);
    }
    function stop() { running = false; cancelAnimationFrame(raf); }

    resize(); seed();
    var onResize = function () { resize(); };
    window.addEventListener('resize', onResize, { passive: true });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop(); else start();
    });
    start();
    return {
      start: start, stop: stop,
      destroy: function () { stop(); window.removeEventListener('resize', onResize); }
    };
  }

  /* ------------------------------ magnetic ----------------------------- */
  function magnetic(node, opts) {
    if (!node || node.__magnetic) return;
    node.__magnetic = true;
    opts = opts || {};
    var strength = opts.strength != null ? opts.strength : 0.35;
    var max = opts.max != null ? opts.max : 10;
    if (reduced()) return;
    function move(e) {
      var r = node.getBoundingClientRect();
      var x = (e.clientX - (r.left + r.width / 2)) * strength;
      var y = (e.clientY - (r.top + r.height / 2)) * strength;
      x = Math.max(-max, Math.min(max, x));
      y = Math.max(-max, Math.min(max, y));
      node.style.transform = 'translate(' + x.toFixed(1) + 'px,' + y.toFixed(1) + 'px)';
    }
    function leave() { node.style.transform = ''; }
    node.addEventListener('pointermove', move);
    node.addEventListener('pointerleave', leave);
    node.addEventListener('pointercancel', leave);
  }

  /* ------------------------------ tilt --------------------------------- */
  function tilt(node, opts) {
    if (!node || node.__tilt) return;
    node.__tilt = true;
    opts = opts || {};
    var max = opts.max != null ? opts.max : 7;
    if (reduced()) return;
    function move(e) {
      var r = node.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      node.style.transform = 'perspective(800px) rotateX(' + (-py * max).toFixed(2) +
        'deg) rotateY(' + (px * max).toFixed(2) + 'deg)';
    }
    function leave() { node.style.transform = ''; }
    node.addEventListener('pointermove', move);
    node.addEventListener('pointerleave', leave);
    node.addEventListener('pointercancel', leave);
  }

  /* ------------------------------ scanLoader --------------------------- */
  function scanLoader(host) {
    var bar = el('div', 'qg-scan');
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-label', 'Сканирование');
    bar.stop = function () { if (bar.parentNode) bar.parentNode.removeChild(bar); };
    if (host) {
      var h = typeof host === 'string' ? document.querySelector(host) : host;
      if (h) h.appendChild(bar);
    }
    return bar;
  }

  /* ------------------------------ tabs (ink) --------------------------- */
  // Плавный скользящий индикатор для .tabs[data-ink]. Синхронизируется с .on.
  function tabs(container) {
    if (!container || container.__tabsInk) return;
    container.__tabsInk = true;
    var ink = container.querySelector('.tab-ink');
    if (!ink) { ink = el('span', 'tab-ink'); container.insertBefore(ink, container.firstChild); }
    function position() {
      var active = container.querySelector('button.on');
      if (!active) { ink.style.opacity = '0'; return; }
      ink.style.opacity = '1';
      ink.style.width = active.offsetWidth + 'px';
      ink.style.transform = 'translateX(' + (active.offsetLeft - 4) + 'px)';
    }
    container.addEventListener('click', function (e) {
      if (e.target.closest('button')) requestAnimationFrame(position);
    });
    // класс .on может меняться программно — следим
    var mo = new MutationObserver(function () { position(); });
    container.querySelectorAll('button').forEach(function (b) {
      mo.observe(b, { attributes: true, attributeFilter: ['class'] });
    });
    window.addEventListener('resize', function () { position(); }, { passive: true });
    i18n.onChange(function () { requestAnimationFrame(position); });
    requestAnimationFrame(position);
  }

  /* ------------------------------ export ------------------------------- */
  window.Qorgau = {
    API: API,
    fetchJSON: fetchJSON,
    i18n: i18n,
    icon: icon,
    iconHTML: iconHTML,
    el: el,
    NAV_ITEMS: NAV_ITEMS,
    nav: nav,
    mountNav: mountNav,
    Gauge: Gauge,
    renderVerdict: renderVerdict,
    toast: toast,
    skeleton: skeleton,
    // — v2 motion-утилиты —
    reduced: reduced,
    countUp: countUp,
    reveal: reveal,
    shieldRadar: shieldRadar,
    magnetic: magnetic,
    tilt: tilt,
    scanLoader: scanLoader,
    tabs: tabs
  };

  // применить язык к статике сразу, как только DOM готов
  document.documentElement.lang = _lang === 'kz' ? 'kk' : 'ru';

  /* ------------------------------ авто-инициализация ------------------- */
  // Идемпотентно навешиваем поведение на opt-in классы/атрибуты. Не трогает
  // страницы, которые ими не пользуются. Всё уважает prefers-reduced-motion.
  function autoInit(root) {
    root = root || document;
    root.querySelectorAll('.btn.magnetic').forEach(function (n) { magnetic(n); });
    root.querySelectorAll('.card.tilt').forEach(function (n) { tilt(n); });
    root.querySelectorAll('.tabs[data-ink]').forEach(function (n) { tabs(n); });
    if (root.querySelector('[data-reveal]')) reveal('[data-reveal]');
  }
  Qorgau.autoInit = autoInit;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { autoInit(document); });
  } else {
    autoInit(document);
  }
})(window, document);
