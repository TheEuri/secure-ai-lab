(function () {
  "use strict";

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function renderMessageMatches(message, keyword) {
    var text = message.textContent || "";
    if (!keyword) {
      message.textContent = text;
      return;
    }

    var pattern = new RegExp(escapeRegExp(keyword), "gi");
    var cursor = 0;
    message.replaceChildren();
    text.replace(pattern, function (match, offset) {
      message.appendChild(document.createTextNode(text.slice(cursor, offset)));
      var mark = document.createElement("mark");
      mark.textContent = match;
      message.appendChild(mark);
      cursor = offset + match.length;
      return match;
    });
    message.appendChild(document.createTextNode(text.slice(cursor)));
  }

  var search = document.getElementById("chat-search");
  var searchForm = document.getElementById("searchForm");
  var chatList = document.getElementById("chat-messages");
  if (search && chatList) {
    search.addEventListener("input", function () {
      chatList.querySelectorAll(".message-text").forEach(function (message) {
        renderMessageMatches(message, search.value);
      });
    });
  }
  if (searchForm) {
    searchForm.addEventListener("submit", function (event) {
      event.preventDefault();
    });
  }

  document.querySelectorAll("[data-word-limit]").forEach(function (field) {
    var maxWords = Number.parseInt(field.dataset.wordLimit, 10);
    if (!Number.isInteger(maxWords) || maxWords < 1) {
      return;
    }
    field.addEventListener("input", function () {
      var words = field.value.split(/\s+/).filter(Boolean);
      if (words.length > maxWords) {
        field.value = words.slice(0, maxWords).join(" ");
      }
    });
  });

  document.querySelectorAll("[data-file-name-target]").forEach(function (input) {
    input.addEventListener("change", function () {
      var target = document.getElementById(input.dataset.fileNameTarget);
      if (!target) {
        return;
      }
      var fileName = input.files && input.files.length > 0
        ? input.files[0].name
        : "Nenhum arquivo selecionado";
      target.textContent = fileName;
    });
  });

  document.querySelectorAll("[data-confirm-message]").forEach(function (control) {
    control.addEventListener("click", function (event) {
      if (!window.confirm(control.dataset.confirmMessage)) {
        event.preventDefault();
      }
    });
  });
})();
