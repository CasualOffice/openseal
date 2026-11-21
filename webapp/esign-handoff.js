// RSP-02 (ADR-047 §3.1): the eSign hand-off page (`GET /s/{token}/remote-signing/esign`,
// served by the server with its own Content Security Policy) posts the ASP's signed
// request to the eSign Service Provider in a top-level navigation. Its button does the
// same without script; this submits once, at once.
const form = document.getElementById("esign");
if (form && !form.dataset.sent) {
  form.dataset.sent = "1";
  form.submit();
}
