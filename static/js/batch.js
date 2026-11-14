/* 批量校验页：本地轮询队列状态并局部刷新，无框架、无外部请求。 */
(function () {
  "use strict";

  var queueBody = document.getElementById("queue-body");
  if (!queueBody) {
    return;
  }
  var recentBody = document.getElementById("recent-body");
  var queueEmpty = document.getElementById("queue-empty");
  var recentEmpty = document.getElementById("recent-empty");
  var queuedCount = document.getElementById("queued-count");
  var runningCount = document.getElementById("running-count");
  var inflightBytes = document.getElementById("inflight-bytes");

  var STATUS_LABELS = {
    queued: "排队中", running: "校验中", done: "通过",
    failed: "未通过", error: "执行异常", cancelled: "已取消"
  };
  var STATUS_PILLS = {
    queued: "queued", running: "running", done: "pass",
    failed: "fail", error: "fail", cancelled: "queued"
  };

  function fmtBytes(value) {
    var size = Number(value) || 0;
    if (size >= 1073741824) {
      return (size / 1073741824).toFixed(2) + " GiB";
    }
    if (size >= 1048576) {
      return (size / 1048576).toFixed(1) + " MiB";
    }
    return (size / 1024).toFixed(1) + " KiB";
  }

  function fmtTime(value) {
    return (value || "").replace("T", " ");
  }

  function cell(text, className) {
    var td = document.createElement("td");
    if (className) {
      td.className = className;
    }
    td.textContent = text;
    return td;
  }

  function packetCell(job) {
    var td = document.createElement("td");
    var name = document.createElement("strong");
    name.textContent = job.packet_name;
    td.appendChild(name);
    var meta = document.createElement("small");
    meta.className = "muted";
    meta.textContent = fmtBytes(job.packet_size);
    td.appendChild(meta);
    return td;
  }

  function pillCell(status) {
    var td = document.createElement("td");
    var pill = document.createElement("span");
    pill.className = "pill " + (STATUS_PILLS[status] || "queued");
    pill.textContent = STATUS_LABELS[status] || status;
    td.appendChild(pill);
    return td;
  }

  function detailCell(job) {
    if (job.status === "done" || job.status === "failed") {
      var td = document.createElement("td");
      var link = document.createElement("a");
      link.className = "text-link";
      link.href = "/tasks/" + encodeURIComponent(job.task_id);
      link.textContent = "详情";
      td.appendChild(link);
      return td;
    }
    return cell("—");
  }

  function buildRow(job, withError) {
    var tr = document.createElement("tr");
    tr.appendChild(cell(job.job_id, "mono"));
    var packet = packetCell(job);
    if (withError && job.error) {
      var error = document.createElement("small");
      error.className = "muted break";
      error.textContent = job.error;
      packet.appendChild(error);
    }
    tr.appendChild(packet);
    tr.appendChild(cell(job.priority_label || String(job.priority)));
    tr.appendChild(pillCell(job.status));
    tr.appendChild(cell(fmtTime(job.created_at), "nowrap"));
    tr.appendChild(detailCell(job));
    return tr;
  }

  function buildRecentRow(job) {
    var tr = document.createElement("tr");
    tr.appendChild(cell(job.job_id, "mono"));
    var packet = packetCell(job);
    if (job.error) {
      var error = document.createElement("small");
      error.className = "muted break";
      error.textContent = job.error;
      packet.appendChild(error);
    }
    tr.appendChild(packet);
    tr.appendChild(cell(job.priority_label || String(job.priority)));
    tr.appendChild(pillCell(job.status));
    tr.appendChild(cell(fmtTime(job.finished_at), "nowrap"));
    tr.appendChild(detailCell(job));
    return tr;
  }

  function render(data) {
    var active = (data.running || []).concat(data.queued || []);
    queueBody.textContent = "";
    active.forEach(function (job) {
      queueBody.appendChild(buildRow(job, false));
    });
    queueEmpty.hidden = active.length > 0;
    recentBody.textContent = "";
    (data.recent || []).forEach(function (job) {
      recentBody.appendChild(buildRecentRow(job));
    });
    recentEmpty.hidden = (data.recent || []).length > 0;
    queuedCount.textContent = String((data.queued || []).length);
    runningCount.textContent = String((data.running || []).length);
    inflightBytes.textContent = fmtBytes(data.inflight_bytes);
  }

  function tick() {
    window.fetch("/batch/api/status", {headers: {"Accept": "application/json"}})
      .then(function (response) { return response.json(); })
      .then(render)
      .catch(function () { /* 离线本地服务短暂不可达时忽略本轮 */ });
  }

  window.setInterval(tick, 3000);

  var form = document.getElementById("batch-form");
  var fileInput = document.querySelector('input[name="packets"]');
  var countHint = document.getElementById("packet-count");
  if (fileInput && countHint) {
    fileInput.addEventListener("change", function () {
      var total = fileInput.files ? fileInput.files.length : 0;
      countHint.textContent = total
        ? ("已选择 " + total + " 个数据包，提交后按优先级排队校验。")
        : "每个压缩包根目录必须包含 manifest.yaml。";
    });
  }
  if (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
        button.textContent = "提交中…";
      }
    });
  }
})();
