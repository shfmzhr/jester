// Jester content script — runs on Gmail pages
// Extracts the currently open email and sends it to the popup on request

function extractEmailFromGmail() {
  try {
    // Subject
    const subjectEl = document.querySelector('h2.hP');
    const subject = subjectEl ? subjectEl.innerText.trim() : '';

    // Sender name and email
    const senderEl = document.querySelector('span.gD');
    const sender = senderEl
      ? `${senderEl.innerText.trim()} <${senderEl.getAttribute('email') || ''}>`
      : '';

    // Reply-to (if visible)
    const replyToEl = document.querySelector('span[email].go');
    const replyTo = replyToEl ? replyToEl.getAttribute('email') : '';

    // Email body — try multiple selectors Gmail uses
    const bodyEl =
      document.querySelector('div.a3s.aiL') ||
      document.querySelector('div.a3s') ||
      document.querySelector('div[data-message-id] .ii.gt div');

    const body = bodyEl ? bodyEl.innerText.trim() : '';

    if (!body && !subject) {
      return { success: false, reason: 'No email open. Please open an email in Gmail first.' };
    }

    // Build RFC-style text
    const emailText = [
      sender    ? `From: ${sender}`    : '',
      replyTo   ? `Reply-To: ${replyTo}` : '',
      subject   ? `Subject: ${subject}` : '',
      '',
      body
    ].filter(Boolean).join('\n');

    return { success: true, emailText, subject };

  } catch (e) {
    return { success: false, reason: 'Could not extract email: ' + e.message };
  }
}

// Listen for message from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'extractEmail') {
    const result = extractEmailFromGmail();
    sendResponse(result);
  }
  return true; // keep channel open for async
});
