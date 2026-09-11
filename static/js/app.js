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

  var aiModerationForm = document.querySelector("[data-ai-moderation-form]");
  if (aiModerationForm) {
    var aiStatus = document.getElementById("ai-moderation-status");
    var aiResult = document.getElementById("ai-moderation-result");
    var aiSubmit = aiModerationForm.querySelector("button[type='submit']");
    var aiContent = document.getElementById("ai-moderation-content");
    var aiContentType = document.getElementById("ai-moderation-content-type");
    var aiCsrf = aiModerationForm.querySelector("input[name='csrf_token']");

    function setAiText(id, value) {
      var target = document.getElementById(id);
      if (target) {
        target.textContent = value;
      }
    }

    function aiErrorMessage(payload, status) {
      if (payload && typeof payload.error === "string" && payload.error) {
        return payload.error;
      }
      return "Não foi possível obter a recomendação (HTTP " + status + ").";
    }

    aiModerationForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!aiContent || !aiContentType || !aiCsrf) {
        return;
      }
      aiResult.hidden = true;
      aiStatus.textContent = "Solicitando recomendação consultiva...";
      if (aiSubmit) {
        aiSubmit.disabled = true;
      }

      fetch(aiModerationForm.action, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": aiCsrf.value
        },
        body: JSON.stringify({
          content: aiContent.value,
          content_type: aiContentType.value
        })
      })
        .then(function (response) {
          return response.json().catch(function () {
            return {};
          }).then(function (payload) {
            if (!response.ok) {
              throw new Error(aiErrorMessage(payload, response.status));
            }
            return payload;
          });
        })
        .then(function (result) {
          setAiText("ai-result-category", String(result.category));
          setAiText("ai-result-suspicious", result.suspicious ? "Sim" : "Não");
          setAiText(
            "ai-result-phishing",
            result.phishing_or_social_engineering ? "Sim" : "Não"
          );
          setAiText("ai-result-confidence", String(result.confidence));
          setAiText("ai-result-rationale", String(result.rationale));
          setAiText("ai-result-action", String(result.recommended_action));
          aiStatus.textContent = "Recomendação recebida; aguarde a revisão humana.";
          aiResult.hidden = false;
        })
        .catch(function (error) {
          aiStatus.textContent = error instanceof Error
            ? error.message
            : "Não foi possível obter a recomendação.";
        })
        .finally(function () {
          if (aiSubmit) {
            aiSubmit.disabled = false;
          }
        });
    });
  }
})();
