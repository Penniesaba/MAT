/* ============================================================
   mcp-sec-audit v6.0 — WebUI 前端逻辑
   覆盖：导航态 · 日夜主题 · 监控页（真实 WS 契约）· 日志弹窗
        配置页（结构化表单 ↔ 后端 TOML）· 仓库管理页（本地占位）
   ============================================================ */
(function () {
  "use strict";

  /* ==================== 小工具 ==================== */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const pad = (n) => String(n).padStart(2, "0");
  const nowTime = () => {
    const d = new Date();
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  };

  function toast(msg) {
    let wrap = $(".toast-wrap");
    if (!wrap) {
      wrap = document.createElement("div");
      wrap.className = "toast-wrap";
      document.body.appendChild(wrap);
    }
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = msg;
    wrap.appendChild(el);
    requestAnimationFrame(() => el.classList.add("is-visible"));
    setTimeout(() => {
      el.classList.remove("is-visible");
      setTimeout(() => el.remove(), 300);
    }, 3000);
  }

  /* ==================== 导航态 ==================== */
  function initNav() {
    const page = document.body.dataset.page;
    $$(".mainnav a").forEach((a) => {
      if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    });
  }

  /* ==================== 日夜主题 ==================== */
  function initTheme() {
    const btn = $("#theme-toggle");
    if (!btn) return;
    const root = document.documentElement;
    const label = () => {
      const cur = root.dataset.theme || "dark";
      const next = cur === "dark" ? "切换到白天模式" : "切换到黑夜模式";
      btn.setAttribute("aria-label", next);
      btn.setAttribute("title", next);
    };
    label();
    btn.addEventListener("click", () => {
      const next = (root.dataset.theme || "dark") === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try { localStorage.setItem("theme", next); } catch (e) { /* 忽略隐私模式 */ }
      label();
    });
  }

  /* ==================== 状态徽标 ==================== */
  const STATUS_LABEL = {
    queued: "排队", running: "运行中", ok: "完成", failed: "失败", cancelled: "已取消",
  };
  function statusBadge(status) {
    return '<span class="badge badge-' + esc(status) + '">' +
      '<span class="dot"></span>' + (STATUS_LABEL[status] || status) + "</span>";
  }

  /* =================================================================
     监控页 —— 真实 WebSocket 契约
     ================================================================= */
  const Monitor = {
    repos: {},
    logs: {},
    batchId: null,
    running: false,
    finished: false,
    startedAt: null,
    follow: true,
    activeRepo: null,
    ws: null,
    _reconnect: null,

    init() {
      if (!$("#repo-list")) return;
      this.connect();
      this.bindControls();
      this.bindModal();
    },

    connect() {
      try {
        const proto = location.protocol === "https:" ? "wss" : "ws";
        const ws = new WebSocket(proto + "://" + location.host + "/ws/events");
        this.ws = ws;
        ws.onopen = () => this.setLive("live");
        ws.onmessage = (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch (e) { return; }
          if (msg.type === "snapshot") this.applySnapshot(msg.data);
          else if (msg.type === "event") this.applyEvent(msg.data);
        };
        ws.onclose = () => {
          this.setLive(null);
          // 运行结束后服务端会关闭连接；断线则 1s 重试，重连后以快照全量重建。
          if (this._reconnect) return;
          this._reconnect = setTimeout(() => {
            this._reconnect = null;
            this.connect();
          }, 1000);
        };
        ws.onerror = () => {};
        return true;
      } catch (e) {
        return false;
      }
    },

    applySnapshot(data) {
      this.repos = {};
      this.logs = {};
      this.batchId = data.batch_id;
      Object.entries(data.repos || {}).forEach(([name, p]) => {
        this.repos[name] = {
          status: p.status || "running",   // status null = 进行中
          stage: p.stage,
          percent: p.percent || 0,
          risk: p.risk_level,
          findings: p.finding_count,
          error: p.error,
        };
      });
      Object.entries(data.logs || {}).forEach(([name, lines]) => {
        this.logs[name] = lines.map(([lv, line]) => ({ t: nowTime(), lv, line }));
      });
      this.running = Object.values(this.repos).some((r) => r.status === "running");
      this.finished = !this.running && Object.keys(this.repos).length > 0;
      this.renderAll();
    },

    applyEvent(ev) {
      const key = Object.keys(ev)[0];
      const d = ev[key];
      if (key === "BatchStarted") {
        this.batchId = d.batch_id; this.running = true; this.finished = false;
        this.startedAt = Date.now();
      }
      if (key === "BatchFinished") { this.finished = true; this.running = false; this.showSummary(d.summary); }
      if (key === "RepoStarted") { this.ensureRepo(d.repo).status = "running"; this.ensureLogs(d.repo); }
      if (key === "RepoFinished") {
        const r = this.ensureRepo(d.repo);
        r.status = d.status; r.risk = d.risk_level; r.findings = d.fused_finding_count; r.error = d.error;
        r.percent = d.status === "ok" ? 100 : r.percent;
      }
      if (key === "StageProgress") {
        const r = this.ensureRepo(d.repo);
        r.stage = d.stage; r.percent = d.percent;
        this.ensureLogs(d.repo);
      }
      if (key === "Log") {
        this.pushLog(d.repo, d.level || "info", d.line);
      }
      this.renderAll();
    },

    ensureRepo(name) {
      if (!this.repos[name]) this.repos[name] = { status: "queued", stage: null, percent: 0, risk: null, findings: null, error: null };
      return this.repos[name];
    },
    ensureLogs(name) { if (!this.logs[name]) this.logs[name] = []; return this.logs[name]; },

    /* —— 渲染 —— */
    renderAll() {
      const list = $("#repo-list");
      if (!list) return;
      const names = Object.keys(this.repos);
      if (names.length === 0) {
        list.innerHTML = '<div class="empty"><div class="empty-title">暂无运行</div>在配置页启动分析后，这里会实时显示各仓库进度。<br><span class="demo-note">去「配置」页填写或导入 TOML，然后点击「启动运行」。</span></div>';
        return;
      }
      list.innerHTML = names.map((n) => this.rowHTML(n)).join("");
      this.renderRunbar();
    },

    rowHTML(name) {
      const r = this.repos[name];
      const status = r.status || "queued";
      const pct = Math.round(r.percent || 0);
      const stage = r.stage ? '<span class="repo-stage">' + esc(this.stageLabel(r.stage)) + "</span>" : "";
      let meta = "";
      if (status === "ok") meta = '<span class="repo-meta">风险 ' + esc(r.risk || "-") + " · " + (r.findings == null ? "-" : r.findings) + " 项</span>";
      else if (status === "failed") meta = '<span class="repo-meta">' + esc(r.error || "失败") + "</span>";
      else if (status === "cancelled") meta = '<span class="repo-meta">已取消</span>';
      return (
        '<div class="repo-row" role="button" tabindex="0" data-repo="' + esc(name) + '">' +
          '<div class="repo-head">' +
            '<span class="repo-name">' + esc(name) + "</span>" + stage +
          "</div>" +
          '<div class="repo-side">' + statusBadge(status) +
            '<span class="repo-percent">' + pct + "%</span>" +
          "</div>" +
          '<div class="pbar is-' + esc(status) + '"><div class="pbar-fill" style="width:' + pct + '%"></div></div>' +
          meta +
        "</div>"
      );
    },

    // 把嵌套的 Stage（externally tagged）压成人类可读的 "Phase1::Codeql::Analyze"。
    stageLabel(stage) {
      if (stage == null) return "";
      if (typeof stage === "string") return stage;
      if (Array.isArray(stage)) return stage.join("::");
      const key = Object.keys(stage)[0];
      if (key === undefined) return JSON.stringify(stage);
      const inner = this.stageLabel(stage[key]);
      return inner ? key + "::" + inner : key;
    },

    renderRunbar() {
      const el = $("#runbar");
      if (!el) return;
      const total = Object.keys(this.repos).length;
      const running = Object.keys(this.repos).filter((n) => this.repos[n].status === "running").length;
      const done = Object.keys(this.repos).filter((n) => ["ok", "failed", "cancelled"].includes(this.repos[n].status)).length;
      const live = $("#runbar-live");
      if (live) live.textContent = this.finished ? "已完成" : this.running ? running + " 运行中 / " + total + " 总计" : "空闲";
      const btnRun = $("#btn-run"); const btnCancel = $("#btn-cancel");
      if (btnRun) btnRun.hidden = this.running;
      if (btnCancel) btnCancel.disabled = !this.running;
      const doneEl = $("#runbar-done");
      if (doneEl) doneEl.textContent = done + " / " + total;
      const batch = $("#runbar-batch");
      if (batch) batch.textContent = this.batchId || "无";
    },

    showSummary(s) {
      const el = $("#batch-summary");
      if (!el) return;
      el.classList.add("is-visible");
      el.innerHTML =
        '<h2>批次汇总</h2>' +
        '<div class="summary-grid">' +
          '<div class="summary-cell"><div class="k">成功</div><div class="v">' + (s.succeeded || 0) + "</div></div>" +
          '<div class="summary-cell"><div class="k">失败</div><div class="v">' + (s.failed || 0) + "</div></div>" +
          '<div class="summary-cell"><div class="k">取消</div><div class="v">' + (s.cancelled || 0) + "</div></div>" +
          '<div class="summary-cell"><div class="k">Fused findings</div><div class="v">' + (s.total_fused_findings || 0) + "</div></div>" +
          '<div class="summary-cell"><div class="k">跨仓库学习</div><div class="v">' + (s.cross_repo_learned ? s.cross_repo_learned.length : 0) + '<small>项</small></div></div>' +
        "</div>" +
        (s.cross_repo_learned && s.cross_repo_learned.length
          ? '<div class="mono" style="margin-top:14px;font-size:12px;color:var(--muted)">' + s.cross_repo_learned.map(esc).join(", ") + "</div>"
          : "");
    },

    pushLog(repo, lv, line) {
      if (!repo) return;
      this.ensureLogs(repo).push({ t: nowTime(), lv, line });
      if (this.logs[repo].length > 500) this.logs[repo].shift();
      if (this.activeRepo === repo) this.renderLog(repo);
    },

    setLive(mode) {
      const dot = $("#status-dot"), label = $("#status-label");
      if (!dot) return;
      dot.classList.toggle("is-live", mode === "live");
      dot.classList.toggle("is-demo", mode === "demo");
      if (label) label.textContent = mode === "live" ? "已连接" : mode === "demo" ? "演示模式" : "未连接";
    },

    /* —— 弹窗 —— */
    bindModal() {
      const list = $("#repo-list");
      if (!list) return;
      list.addEventListener("click", (e) => {
        const row = e.target.closest(".repo-row");
        if (row) this.openModal(row.dataset.repo);
      });
      list.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          const row = e.target.closest(".repo-row");
          if (row) { e.preventDefault(); this.openModal(row.dataset.repo); }
        }
      });
      const bd = $("#modal-backdrop");
      bd.addEventListener("click", (e) => { if (e.target === bd) this.closeModal(); });
      $("#modal-close").addEventListener("click", () => this.closeModal());
      document.addEventListener("keydown", (e) => { if (e.key === "Escape") this.closeModal(); });
      $("#modal-follow").addEventListener("click", (e) => {
        this.follow = !this.follow;
        e.currentTarget.classList.toggle("is-on", this.follow);
        e.currentTarget.textContent = this.follow ? "跟随" : "暂停";
        if (this.follow && this.activeRepo) this.scrollLogBottom();
      });
      const body = $("#modal-body");
      body.addEventListener("scroll", () => {
        const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 4;
        if (!atBottom && this.follow) {
          this.follow = false;
          $("#modal-follow").classList.remove("is-on");
          $("#modal-follow").textContent = "暂停";
        } else if (atBottom && !this.follow) {
          this.follow = true;
          $("#modal-follow").classList.add("is-on");
          $("#modal-follow").textContent = "跟随";
        }
      });
    },

    openModal(name) {
      this.activeRepo = name;
      const r = this.repos[name] || { status: "queued", stage: null, percent: 0 };
      $("#modal-title").textContent = name;
      $("#modal-backdrop").classList.add("is-open");
      $("#modal-backdrop").setAttribute("aria-hidden", "false");
      this.follow = true;
      const ft = $("#modal-follow");
      ft.classList.add("is-on"); ft.textContent = "跟随";
      this.renderLog(name);
    },

    closeModal() {
      this.activeRepo = null;
      $("#modal-backdrop").classList.remove("is-open");
      $("#modal-backdrop").setAttribute("aria-hidden", "true");
    },

    renderLog(name) {
      const body = $("#modal-body");
      const logs = this.logs[name] || [];
      const r = this.repos[name] || { status: "queued", percent: 0, stage: null };
      $("#modal-stage").textContent = (this.stageLabel(r.stage) || "等待中") + " · " + Math.round(r.percent || 0) + "%";
      const pbar = $("#modal-pbar");
      if (pbar) {
        pbar.className = "pbar is-" + (r.status || "queued");
        pbar.querySelector(".pbar-fill").style.width = Math.round(r.percent || 0) + "%";
      }
      body.innerHTML = logs.length
        ? logs.map((l) => this.logLineHTML(l)).join("")
        : '<div class="log-line"><span class="log-text">（暂无日志）</span></div>';
      this.scrollLogBottom();
    },

    logLineHTML(l) {
      const cls = "lv-" + (l.lv === "error" ? "error" : l.lv === "warn" ? "warn" : l.lv === "debug" ? "debug" : l.lv === "trace" ? "trace" : "info");
      return (
        '<div class="log-line ' + cls + '">' +
          '<span class="log-time">' + esc(l.t) + "</span>" +
          '<span class="log-level">' + esc((l.lv || "info").toUpperCase()) + "</span>" +
          '<span class="log-text">' + esc(l.line) + "</span>" +
        "</div>"
      );
    },

    scrollLogBottom() {
      const body = $("#modal-body");
      body.scrollTop = body.scrollHeight;
    },

    /* —— 控制 —— */
    bindControls() {
      const btnRun = $("#btn-run");
      if (btnRun) btnRun.addEventListener("click", () => this.startRun());
      const btnCancel = $("#btn-cancel");
      if (btnCancel) btnCancel.addEventListener("click", () => this.cancelRun());
    },

    async startRun() {
      const btn = $("#btn-run");
      if (btn) btn.disabled = true;
      try {
        const r = await fetch("/api/run", { method: "POST" });
        const text = await r.text();
        if (!r.ok) toast(text || "启动失败");
        else toast("已启动分析");
      } catch (e) {
        toast("请求失败：" + e.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    },

    async cancelRun() {
      try {
        const r = await fetch("/api/run/cancel", { method: "POST" });
        if (r.ok) toast("已请求取消运行");
        else toast(await r.text());
      } catch (e) {
        toast("请求失败：" + e.message);
      }
    },
  };

  /* =================================================================
     配置页 —— 结构化表单 ↔ 后端
     ================================================================= */
  const CONFIG_SCHEMA = [
    {
      id: "scan", title: "扫描", key: "scan",
      desc: "分析目标、排除项与语言集合。",
      fields: [
        { path: "scan.targets", label: "目标", key: "targets", type: "array", default: ["."], hint: "扫描的目录或文件路径，可多个。" },
        { path: "scan.exclude", label: "排除", key: "exclude", type: "array", default: ["node_modules", "target", ".venv", "dist"] },
        { path: "scan.languages", label: "语言", key: "languages", type: "array", default: ["python", "javascript", "typescript", "rust"] },
      ],
    },
    {
      id: "static", title: "静态分析", key: "static",
      desc: "事实提取、规则 / 污点 / Agent / CodeQL 四条线的总开关。",
      fields: [
        { path: "static.enabled", label: "启用静态分析", key: "enabled", type: "bool", default: true },
        { path: "static.save_facts", label: "保存事实库", key: "save_facts", type: "bool", default: true },
        { path: "static.models_dir", label: "模型目录", key: "models_dir", type: "string", default: null, optional: true },
        { path: "static.learned_dir", label: "学习目录", key: "learned_dir", type: "string", default: null, optional: true },
      ],
    },
    {
      id: "rule", title: "规则引擎", key: "static.rule",
      desc: "确定性规则匹配。",
      fields: [
        { path: "static.rule.enabled", label: "启用规则引擎", key: "enabled", type: "bool", default: true },
        { path: "static.rule.rule_paths", label: "规则路径", key: "rule_paths", type: "array", default: ["rules/mcp", "rules/languages"] },
      ],
    },
    {
      id: "taint", title: "污点分析", key: "static.taint",
      desc: "轻量污点传播，默认关闭。",
      fields: [
        { path: "static.taint.enabled", label: "启用污点分析", key: "enabled", type: "bool", default: false },
        { path: "static.taint.forward", label: "前向传播", key: "forward", type: "bool", default: true },
        { path: "static.taint.backward", label: "反向传播", key: "backward", type: "bool", default: true },
        { path: "static.taint.max_depth", label: "最大深度", key: "max_depth", type: "number", default: 8 },
        { path: "static.taint.entrypoint_required", label: "要求入口点", key: "entrypoint_required", type: "bool", default: true },
      ],
    },
    {
      id: "agent", title: "Agent（LLM 语义分析）", key: "static.agent",
      desc: "默认关闭；开启后每个候选 finding 走一轮 LLM 复核。",
      fields: [
        { path: "static.agent.enabled", label: "启用 Agent", key: "enabled", type: "bool", default: false },
        { path: "static.agent.provider", label: "提供方", key: "provider", type: "select", default: "claude", options: ["claude", "openai", "ollama"] },
        { path: "static.agent.prompt_template_path", label: "提示词模板路径", key: "prompt_template_path", type: "string", default: null, optional: true },
        { path: "static.agent.max_turns", label: "最大轮次", key: "max_turns", type: "number", default: 30 },
        { path: "static.agent.timeout_seconds", label: "超时（秒）", key: "timeout_seconds", type: "number", default: 600 },
        { path: "static.agent.extra_args", label: "额外参数", key: "extra_args", type: "array", default: [] },
      ],
    },
    {
      id: "codeql", title: "CodeQL", key: "static.codeql",
      desc: "默认关闭；需要本机可用的 codeql 二进制。",
      fields: [
        { path: "static.codeql.enabled", label: "启用 CodeQL", key: "enabled", type: "bool", default: false },
        { path: "static.codeql.query_pack_path", label: "查询包路径", key: "query_pack_path", type: "string", default: null, optional: true },
        { path: "static.codeql.binary", label: "二进制", key: "binary", type: "string", default: "codeql" },
        { path: "static.codeql.timeout_seconds", label: "超时（秒）", key: "timeout_seconds", type: "number", default: 1200 },
        { path: "static.codeql.extra_args", label: "额外参数", key: "extra_args", type: "array", default: [] },
      ],
    },
    {
      id: "dynamic", title: "动态分析", key: "dynamic",
      desc: "Docker 沙箱 + eBPF 系统调用监控，v6 仅沿用开关。",
      fields: [
        { path: "dynamic.enabled", label: "启用动态分析", key: "enabled", type: "bool", default: false },
        { path: "dynamic.sandbox", label: "沙箱", key: "sandbox", type: "select", default: "existing_python_runtime", options: ["existing_python_runtime", "docker"] },
        { path: "dynamic.timeout_seconds", label: "超时（秒）", key: "timeout_seconds", type: "number", default: 120 },
      ],
    },
    {
      id: "fusion", title: "相关性融合", key: "fusion",
      desc: "四线结果融合打分与裁决。",
      fields: [
        { path: "fusion.enabled", label: "启用融合", key: "enabled", type: "bool", default: true },
        { path: "fusion.require_confirmed_by", label: "需确认线数", key: "require_confirmed_by", type: "number", default: 1 },
        { path: "fusion.boost_when_multiple_lines_agree", label: "多线一致加权", key: "boost_when_multiple_lines_agree", type: "bool", default: true },
        { path: "fusion.agent_only_as_advisory", label: "Agent 仅作参考", key: "agent_only_as_advisory", type: "bool", default: true },
        { path: "fusion.line_proximity", label: "行邻近度", key: "line_proximity", type: "number", default: 5 },
        { path: "fusion.rule_weight", label: "规则权重", key: "rule_weight", type: "number", default: 3 },
        { path: "fusion.taint_weight", label: "污点权重", key: "taint_weight", type: "number", default: 2 },
        { path: "fusion.agent_weight", label: "Agent 权重", key: "agent_weight", type: "number", default: 1 },
        { path: "fusion.codeql_weight", label: "CodeQL 权重", key: "codeql_weight", type: "number", default: 4 },
      ],
    },
    {
      id: "report", title: "报告", key: "report",
      desc: "报告输出格式与内容。",
      fields: [
        { path: "report.formats", label: "格式", key: "formats", type: "array", default: ["json", "markdown"] },
        { path: "report.output", label: "输出目录", key: "output", type: "string", default: "docs/result/<timestamp>/<repo>" },
        { path: "report.include_fused_results", label: "含融合结果", key: "include_fused_results", type: "bool", default: true },
        { path: "report.include_raw_rule_results", label: "含原始规则结果", key: "include_raw_rule_results", type: "bool", default: true },
        { path: "report.include_raw_taint_results", label: "含原始污点结果", key: "include_raw_taint_results", type: "bool", default: true },
        { path: "report.include_raw_agent_results", label: "含原始 Agent 结果", key: "include_raw_agent_results", type: "bool", default: true },
        { path: "report.include_raw_codeql_results", label: "含原始 CodeQL 结果", key: "include_raw_codeql_results", type: "bool", default: true },
        { path: "report.include_facts", label: "含事实库", key: "include_facts", type: "bool", default: false },
      ],
    },
    {
      id: "logging", title: "日志", key: "logging",
      desc: "运行日志输出。",
      fields: [
        { path: "logging.level", label: "级别", key: "level", type: "select", default: "info", options: ["trace", "debug", "info", "warn", "error"] },
        { path: "logging.format", label: "格式", key: "format", type: "select", default: "compact", options: ["full", "compact", "pretty", "json"] },
        { path: "logging.ansi", label: "ANSI 颜色", key: "ansi", type: "bool", default: true },
        { path: "logging.show_timestamps", label: "显示时间戳", key: "show_timestamps", type: "bool", default: true },
        { path: "logging.show_progress", label: "显示进度", key: "show_progress", type: "bool", default: true },
        { path: "logging.log_file", label: "日志文件", key: "log_file", type: "string", default: null, optional: true },
      ],
    },
    {
      id: "batch", title: "批量运行", key: "batch",
      desc: "多仓库并行的调度配置与仓库清单。",
      fields: [
        { path: "batch.max_parallel", label: "并行度", key: "max_parallel", type: "number", default: 4 },
        { path: "batch.learning_bus", label: "学习总线", key: "learning_bus", type: "bool", default: true },
        { path: "batch.fail_fast", label: "快速失败", key: "fail_fast", type: "bool", default: false },
        { path: "batch.limits.codeql", label: "CodeQL 并发上限", key: "codeql", type: "number", default: 1 },
        { path: "batch.limits.agent", label: "Agent 并发上限", key: "agent", type: "number", default: 1 },
        { path: "batch.limits.cpu", label: "CPU 上限", key: "cpu", type: "number", default: 4 },
      ],
      repoList: true,
    },
  ];

  const Config = {
    values: {},
    repos: [],

    init() {
      if (!$("#config-form")) return;
      this.buildForm();
      this.applyDefaults();
      this.bind();
      this.loadFromBackend();
    },

    buildForm() {
      const form = $("#config-form");
      form.innerHTML = CONFIG_SCHEMA.map((sec) => {
        let repoListHTML = "";
        if (sec.repoList) {
          repoListHTML =
            '<div class="field field-full">' +
              "<label>仓库清单 <span class=\"key\">[[batch.repo]]</span></label>" +
              '<div class="repo-config-list" id="repo-config-list"></div>' +
              '<div class="repo-config-item" style="border-top:1px solid var(--border)">' +
                '<input class="input" id="rc-name" placeholder="name，如 fastapi" aria-label="仓库名">' +
                '<input class="input" id="rc-path" placeholder="path，如 /path/to/repo" aria-label="仓库路径">' +
                '<button type="button" class="btn btn-secondary btn-sm" id="rc-add">添加</button>' +
              "</div>" +
            "</div>";
        }
        const fields = sec.fields.map((f) => this.fieldHTML(f)).join("");
        return (
          '<section class="config-section">' +
            '<div class="config-section-head"><h2>' + esc(sec.title) + '</h2><span class="key">[' + esc(sec.key) + "]</span></div>" +
            '<p class="config-section-desc">' + esc(sec.desc) + "</p>" +
            '<div class="form-grid">' + fields + repoListHTML + "</div>" +
          "</section>"
        );
      }).join("");
    },

    fieldHTML(f) {
      const id = "f-" + f.path.replace(/\./g, "-");
      const defaultNote = f.default !== null && f.default !== undefined
        ? '<span class="default-note">默认 ' + (Array.isArray(f.default) ? JSON.stringify(f.default) : f.default) + "</span>"
        : "";
      let control = "";
      if (f.type === "bool") {
        control =
          '<label class="switch">' +
            '<input type="checkbox" id="' + id + '" data-path="' + f.path + '">' +
            '<span class="track"></span>' +
            '<span class="sw-label">' + (f.default ? "开启" : "关闭") + "</span>" +
          "</label>";
      } else if (f.type === "select") {
        control =
          '<select class="select" id="' + id + '" data-path="' + f.path + '">' +
            f.options.map((o) => '<option value="' + esc(o) + '"' + (o === f.default ? " selected" : "") + ">" + esc(o) + "</option>").join("") +
          "</select>";
      } else if (f.type === "array") {
        control =
          '<div class="chips" id="' + id + '" data-path="' + f.path + '" role="textbox" tabindex="0">' +
            '<input type="text" placeholder="输入后回车添加">' +
          "</div>";
      } else if (f.type === "number") {
        control = '<input class="input" type="number" id="' + id + '" data-path="' + f.path + '" value="' + f.default + '">';
      } else {
        control = '<input class="input" type="text" id="' + id + '" data-path="' + f.path + '" value="' + (f.default == null ? "" : esc(f.default)) + '"' + (f.optional ? ' placeholder="可选"' : "") + ">";
      }
      return (
        '<div class="field" data-field="' + esc(f.path) + '">' +
          "<label for=\"" + id + "\">" + esc(f.label) + ' <span class="key">' + esc(f.key) + "</span></label>" +
          (f.hint ? '<span class="hint">' + esc(f.hint) + "</span>" : "") +
          control + defaultNote +
          '<div class="field-error">配置错误</div>' +
        "</div>"
      );
    },

    applyDefaults() {
      this.values = {};
      CONFIG_SCHEMA.forEach((sec) => sec.fields.forEach((f) => {
        this.values[f.path] = Array.isArray(f.default) ? f.default.slice() : f.default;
      }));
      this.repos = [];
      this.populateForm();
      this.renderRepoList();
    },

    populateForm() {
      CONFIG_SCHEMA.forEach((sec) => sec.fields.forEach((f) => {
        const el = $("#f-" + f.path.replace(/\./g, "-"));
        if (!el) return;
        const v = this.values[f.path];
        if (f.type === "bool") {
          el.checked = !!v;
          el.closest(".switch").querySelector(".sw-label").textContent = v ? "开启" : "关闭";
        } else if (f.type === "array") {
          this.renderChips(el, v || []);
        } else if (f.type === "select") {
          el.value = v == null ? f.default : v;
        } else {
          el.value = v == null ? "" : v;
        }
      }));
    },

    renderChips(wrap, arr) {
      const input = wrap.querySelector("input");
      wrap.querySelectorAll(".chip").forEach((c) => c.remove());
      (arr || []).forEach((val) => {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.innerHTML = esc(val) + '<button type="button" aria-label="移除">×</button>';
        chip.querySelector("button").addEventListener("click", () => {
          chip.remove();
          this.collect();
        });
        wrap.insertBefore(chip, input);
      });
    },

    renderRepoList() {
      const list = $("#repo-config-list");
      if (!list) return;
      if (!this.repos.length) {
        list.innerHTML = '<div class="repo-config-empty">暂无仓库，使用下方输入添加。</div>';
        return;
      }
      list.innerHTML = this.repos.map((r, i) =>
        '<div class="repo-config-item">' +
          '<span class="rc-name">' + esc(r.name) + "</span>" +
          '<span class="rc-path">' + esc(r.path) + "</span>" +
          '<button type="button" class="btn btn-ghost btn-sm" data-rc-del="' + i + '">移除</button>' +
        "</div>"
      ).join("");
      list.querySelectorAll("[data-rc-del]").forEach((b) => {
        b.addEventListener("click", () => {
          this.repos.splice(Number(b.dataset.rcDel), 1);
          this.renderRepoList();
          this.syncTOML();
        });
      });
    },

    bind() {
      $$("#config-view button").forEach((btn) => {
        btn.addEventListener("click", () => {
          $$("#config-view button").forEach((b) => b.setAttribute("aria-selected", "false"));
          btn.setAttribute("aria-selected", "true");
          const mode = btn.dataset.view;
          $("#view-form").hidden = mode !== "form";
          $("#view-toml").hidden = mode !== "toml";
          if (mode === "toml") this.syncTOML();
        });
      });
      document.addEventListener("keydown", (e) => {
        const wrap = e.target.closest ? e.target.closest(".chips") : null;
        if (!wrap) return;
        const input = wrap.querySelector("input");
        if ((e.key === "Enter" || e.key === ",") && input.value.trim()) {
          e.preventDefault();
          const path = wrap.dataset.path;
          this.values[path] = this.values[path] || [];
          this.values[path].push(input.value.trim());
          input.value = "";
          this.renderChips(wrap, this.values[path]);
        }
      });
      document.addEventListener("change", (e) => {
        const el = e.target;
        if (el && el.dataset && el.dataset.path) this.collect();
      });
      $("#config-form").addEventListener("submit", (e) => e.preventDefault());
      $("#rc-add").addEventListener("click", () => this.addRepo());
      $("#btn-export").addEventListener("click", () => { this.syncTOML(); $("#view-toml").hidden = false; $("#view-form").hidden = true; toast("已导出到 TOML 编辑器"); });
      $("#btn-import").addEventListener("click", () => this.importFromBackend());
      $("#btn-reset").addEventListener("click", () => { this.applyDefaults(); this.syncTOML(); toast("已恢复默认配置"); });
      $("#btn-save").addEventListener("click", () => this.save());
      $("#btn-start").addEventListener("click", () => this.startRun());
    },

    addRepo() {
      const name = $("#rc-name"), path = $("#rc-path");
      if (!name.value.trim() || !path.value.trim()) {
        toast("请填写仓库名与路径");
        return;
      }
      this.repos.push({ name: name.value.trim(), path: path.value.trim() });
      name.value = ""; path.value = "";
      this.renderRepoList();
      this.syncTOML();
    },

    collect() {
      CONFIG_SCHEMA.forEach((sec) => sec.fields.forEach((f) => {
        const el = $("#f-" + f.path.replace(/\./g, "-"));
        if (!el) return;
        if (f.type === "bool") {
          this.values[f.path] = el.checked;
          el.closest(".switch").querySelector(".sw-label").textContent = el.checked ? "开启" : "关闭";
        } else if (f.type === "array") {
          this.values[f.path] = Array.from(el.querySelectorAll(".chip")).map((c) => c.textContent.replace("×", "").trim());
        } else if (f.type === "number") {
          this.values[f.path] = el.value === "" ? f.default : Number(el.value);
        } else {
          this.values[f.path] = el.value;
        }
      }));
    },

    validate() {
      let ok = true;
      $$(".field.has-error").forEach((f) => f.classList.remove("has-error"));
      const err = (path, msg) => {
        ok = false;
        const f = $('[data-field="' + path + '"]');
        if (f) {
          f.classList.add("has-error");
          f.querySelector(".field-error").textContent = msg;
        }
      };
      if (!this.values["scan.targets"] || !this.values["scan.targets"].length) err("scan.targets", "至少需要一个扫描目标");
      if (this.values["scan.targets"] && this.values["scan.targets"].some((t) => t.includes(" "))) err("scan.targets", "目标路径不能包含空格");
      if (this.repos.length && this.repos.some((r) => !r.name || !r.path)) err("batch", "仓库清单中的 name / path 不能为空");
      return ok;
    },

    /* —— TOML 序列化（表单 → TOML） —— */
    toTOML() {
      const v = this.values;
      const L = [];
      const str = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
      const val = (x) => Array.isArray(x)
        ? "[" + x.map((e) => (typeof e === "number" ? e : str(e))).join(", ") + "]"
        : typeof x === "boolean" ? x
        : typeof x === "number" ? x
        : str(x);
      const write = (header, keys) => {
        const lines = keys.map(([path, key]) => {
          const x = v[path];
          if (x === null || x === undefined || x === "") return null;
          return key + " = " + val(x);
        }).filter(Boolean);
        if (!lines.length) return;
        L.push("[" + header + "]");
        lines.forEach((l) => L.push(l));
        L.push("");
      };
      write("scan", [["scan.targets", "targets"], ["scan.exclude", "exclude"], ["scan.languages", "languages"]]);
      write("static", [["static.enabled", "enabled"], ["static.save_facts", "save_facts"], ["static.models_dir", "models_dir"], ["static.learned_dir", "learned_dir"]]);
      write("static.rule", [["static.rule.enabled", "enabled"], ["static.rule.rule_paths", "rule_paths"]]);
      write("static.taint", [["static.taint.enabled", "enabled"], ["static.taint.forward", "forward"], ["static.taint.backward", "backward"], ["static.taint.max_depth", "max_depth"], ["static.taint.entrypoint_required", "entrypoint_required"]]);
      write("static.agent", [["static.agent.enabled", "enabled"], ["static.agent.provider", "provider"], ["static.agent.prompt_template_path", "prompt_template_path"], ["static.agent.max_turns", "max_turns"], ["static.agent.timeout_seconds", "timeout_seconds"], ["static.agent.extra_args", "extra_args"]]);
      write("static.codeql", [["static.codeql.enabled", "enabled"], ["static.codeql.query_pack_path", "query_pack_path"], ["static.codeql.binary", "binary"], ["static.codeql.timeout_seconds", "timeout_seconds"], ["static.codeql.extra_args", "extra_args"]]);
      write("dynamic", [["dynamic.enabled", "enabled"], ["dynamic.sandbox", "sandbox"], ["dynamic.timeout_seconds", "timeout_seconds"]]);
      write("fusion", [["fusion.enabled", "enabled"], ["fusion.require_confirmed_by", "require_confirmed_by"], ["fusion.boost_when_multiple_lines_agree", "boost_when_multiple_lines_agree"], ["fusion.agent_only_as_advisory", "agent_only_as_advisory"], ["fusion.line_proximity", "line_proximity"], ["fusion.rule_weight", "rule_weight"], ["fusion.taint_weight", "taint_weight"], ["fusion.agent_weight", "agent_weight"], ["fusion.codeql_weight", "codeql_weight"]]);
      write("report", [["report.formats", "formats"], ["report.output", "output"], ["report.include_fused_results", "include_fused_results"], ["report.include_raw_rule_results", "include_raw_rule_results"], ["report.include_raw_taint_results", "include_raw_taint_results"], ["report.include_raw_agent_results", "include_raw_agent_results"], ["report.include_raw_codeql_results", "include_raw_codeql_results"], ["report.include_facts", "include_facts"]]);
      write("logging", [["logging.level", "level"], ["logging.format", "format"], ["logging.ansi", "ansi"], ["logging.show_timestamps", "show_timestamps"], ["logging.show_progress", "show_progress"], ["logging.log_file", "log_file"]]);
      write("batch", [["batch.max_parallel", "max_parallel"], ["batch.learning_bus", "learning_bus"], ["batch.fail_fast", "fail_fast"]]);
      write("batch.limits", [["batch.limits.codeql", "codeql"], ["batch.limits.agent", "agent"], ["batch.limits.cpu", "cpu"]]);
      this.repos.forEach((r) => {
        L.push("[[batch.repo]]");
        L.push("name = " + str(r.name));
        L.push("path = " + str(r.path));
        L.push("");
      });
      return L.join("\n").replace(/\n+$/, "\n");
    },

    syncTOML() {
      this.collect();
      const editor = $("#toml-editor");
      if (editor) editor.value = this.toTOML();
    },

    /* —— 后端同步 —— */
    // 把后端 ConfigKind JSON（Single/Batch）压平为 form 的 path -> value。
    flattenInto(out, obj, prefix) {
      Object.entries(obj || {}).forEach(([k, val]) => {
        const path = prefix ? prefix + "." + k : k;
        if (val !== null && typeof val === "object" && !Array.isArray(val)) {
          this.flattenInto(out, val, path);
        } else {
          out[path] = val;
        }
      });
    },

    applyConfigJSON(cfg) {
      const inner = (cfg && (cfg.Single || cfg.Batch)) || null;
      if (!inner) return;
      const flat = {};
      this.flattenInto(flat, inner, "");
      CONFIG_SCHEMA.forEach((sec) => sec.fields.forEach((f) => {
        if (Object.prototype.hasOwnProperty.call(flat, f.path)) {
          const v = flat[f.path];
          if (v !== null && v !== undefined) {
            this.values[f.path] = Array.isArray(v) ? v.slice() : v;
          }
        }
      }));
      if (Array.isArray(flat["batch.repo"])) {
        this.repos = flat["batch.repo"]
          .filter((r) => r && r.name)
          .map((r) => ({ name: r.name, path: r.path || "" }));
      }
      this.populateForm();
      this.renderRepoList();
      this.syncTOML();
    },

    async loadFromBackend() {
      try {
        const r = await fetch("/api/config");
        const text = await r.text();
        if (!r.ok || text === "null") return; // 无配置：保持默认
        this.applyConfigJSON(JSON.parse(text));
      } catch (e) {
        /* 后端不可用则保持默认表单 */
      }
    },

    async importFromBackend() {
      const editor = $("#toml-editor");
      if (!editor || !editor.value.trim()) {
        toast("请先在 TOML 编辑器粘贴配置");
        return;
      }
      try {
        const r = await fetch("/api/import", { method: "POST", body: editor.value });
        const text = await r.text();
        if (!r.ok) {
          toast("配置校验失败：" + text);
          return;
        }
        // 规范化后的 TOML 回填编辑器，并从后端 JSON 重建表单。
        editor.value = text;
        await this.loadFromBackend();
        toast("已导入并校验配置");
      } catch (e) {
        toast("导入失败：" + e.message);
      }
    },

    async save() {
      if (!this.validate()) return;
      this.syncTOML();
      try {
        const r = await fetch("/api/config", { method: "PUT", body: $("#toml-editor").value });
        if (r.ok) toast("配置已保存");
        else toast("保存失败：" + await r.text());
      } catch (e) {
        toast("保存失败：" + e.message);
      }
    },

    async startRun() {
      if (!this.validate()) return;
      if (!this.repos.length) {
        toast("请先在「批量运行」添加至少一个仓库");
        return;
      }
      this.syncTOML();
      try {
        const put = await fetch("/api/config", { method: "PUT", body: $("#toml-editor").value });
        if (!put.ok) {
          toast("保存失败：" + await put.text());
          return;
        }
        const run = await fetch("/api/run", { method: "POST" });
        if (!run.ok) {
          toast("启动失败：" + await run.text());
          return;
        }
        location.href = "/";
      } catch (e) {
        toast("启动失败：" + e.message);
      }
    },
  };

  /* =================================================================
     仓库管理页 —— 本地占位（localStorage）
     ================================================================= */
  const SEED_REPOS = [
    ["fastapi", "~/repos/fastapi", "python"],
    ["requests", "~/repos/requests", "python"],
    ["pydantic", "~/repos/pydantic", "python"],
    ["httpx", "~/repos/httpx", "python"],
    ["aiohttp", "~/repos/aiohttp", "python"],
    ["flask", "~/repos/flask", "python"],
    ["django", "~/repos/django", "python"],
    ["celery", "~/repos/celery", "python"],
    ["sentry-python", "~/repos/sentry-python", "python"],
    ["uvicorn", "~/repos/uvicorn", "python"],
    ["starlette", "~/repos/starlette", "python"],
    ["sqlalchemy", "~/repos/sqlalchemy", "python"],
    ["alembic", "~/repos/alembic", "python"],
    ["gunicorn", "~/repos/gunicorn", "python"],
    ["typer", "~/repos/typer", "python"],
    ["rich", "~/repos/rich", "python"],
    ["click", "~/repos/click", "python"],
    ["structlog", "~/repos/structlog", "python"],
    ["mypy", "~/repos/mypy", "python"],
    ["express", "~/repos/express", "javascript"],
  ];

  const Repos = {
    KEY: "msa-repos-v6",
    init() {
      if (!$("#repo-table-body")) return;
      this.load();
      this.bind();
      this.render();
    },

    load() {
      try {
        const raw = localStorage.getItem(this.KEY);
        if (raw) { this.items = JSON.parse(raw); return; }
      } catch (e) {}
      this.items = SEED_REPOS.map(([name, path, lang]) => ({
        name, path, lang,
        status: "ok",
        risk: "Low",
      }));
    },

    save() {
      try { localStorage.setItem(this.KEY, JSON.stringify(this.items)); } catch (e) {}
    },

    render() {
      const tbody = $("#repo-table-body");
      $("#repo-count").textContent = this.items.length + " 个仓库";
      if (!this.items.length) {
        tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-title">暂无本地仓库</div>点击「添加仓库」登记一个本地路径。</div></td></tr>';
        return;
      }
      tbody.innerHTML = this.items.map((r, i) => {
        const st = r.status || "ok";
        return (
          '<tr>' +
            '<td class="t-name">' + esc(r.name) + "</td>" +
            '<td class="t-path">' + esc(r.path) + "</td>" +
            '<td class="t-lang">' + esc(r.lang || "-") + "</td>" +
            '<td>' + statusBadge(st) + (st === "ok" ? ' <span class="repo-meta" style="font-size:11px">风险 ' + esc(r.risk || "-") + "</span>" : "") + "</td>" +
            '<td class="t-actions">' +
              '<button class="btn btn-ghost btn-sm" data-act="pull" data-i="' + i + '">拉取</button>' +
              '<button class="btn btn-ghost btn-sm" data-act="scan" data-i="' + i + '">分析</button>' +
              '<button class="btn btn-ghost btn-sm" data-act="del" data-i="' + i + '">删除</button>' +
            "</td>" +
          "</tr>"
        );
      }).join("");
    },

    bind() {
      $("#btn-add-repo").addEventListener("click", () => {
        $("#add-repo-form").hidden = !$("#add-repo-form").hidden;
      });
      $("#add-repo-cancel").addEventListener("click", () => {
        $("#add-repo-form").hidden = true;
      });
      $("#add-repo-submit").addEventListener("click", () => {
        const name = $("#new-repo-name").value.trim();
        const path = $("#new-repo-path").value.trim();
        if (!name || !path) { toast("请填写仓库名与本地路径"); return; }
        this.items.unshift({ name, path, lang: "python", status: "ok", risk: "Low" });
        $("#new-repo-name").value = ""; $("#new-repo-path").value = "";
        $("#add-repo-form").hidden = true;
        this.save(); this.render();
        toast("已添加仓库 " + name);
      });
      $("#btn-pull-all").addEventListener("click", () => {
        toast("已发起拉取全部仓库");
        this.items.forEach((r) => { r.status = "running"; });
        this.render();
        setTimeout(() => {
          this.items.forEach((r) => { r.status = "ok"; });
          this.save(); this.render();
          toast("全部仓库拉取完成");
        }, 1600);
      });
      $("#repo-table-body").addEventListener("click", (e) => {
        const btn = e.target.closest("[data-act]");
        if (!btn) return;
        const i = Number(btn.dataset.i);
        const r = this.items[i];
        if (btn.dataset.act === "del") {
          this.items.splice(i, 1);
          this.save(); this.render();
          toast("已删除仓库 " + r.name);
        } else if (btn.dataset.act === "pull") {
          toast("正在拉取 " + r.name + " …");
          r.status = "running"; this.render();
          setTimeout(() => { r.status = "ok"; r.risk = "Low"; this.save(); this.render(); toast(r.name + " 拉取完成"); }, 1200);
        } else if (btn.dataset.act === "scan") {
          toast("已对 " + r.name + " 发起分析，前往日志页查看");
        }
      });
    },
  };

  /* ==================== 页面路由 ==================== */
  function boot() {
    initTheme();
    initNav();
    const page = document.body.dataset.page;
    if (page === "monitor") Monitor.init();
    else if (page === "config") Config.init();
    else if (page === "repos") Repos.init();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
