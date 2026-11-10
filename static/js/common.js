/* 数包闸检本地交互：无框架、无外部请求。 */
(function () {
  "use strict";

  document.querySelectorAll("form.js-confirm").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm") || "确认执行该操作？";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  var upload = document.querySelector('input[name="packet"]');
  var form = document.getElementById("upload-form");
  if (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
        button.textContent = "校验进行中…";
      }
    });
  }
  if (upload) {
    upload.addEventListener("change", function () {
      if (!upload.files || !upload.files.length) {
        return;
      }
      var file = upload.files[0];
      var sizeMb = (file.size / 1024 / 1024).toFixed(2);
      var hint = upload.parentElement.querySelector("small");
      if (hint) {
        hint.textContent = "已选择：" + file.name + "（" + sizeMb + " MB）";
      }
    });
  }

  window.setTimeout(function () {
    document.querySelectorAll(".flash").forEach(function (node) {
      node.style.transition = "opacity .4s";
      node.style.opacity = "0.72";
    });
  }, 6000);
})();
