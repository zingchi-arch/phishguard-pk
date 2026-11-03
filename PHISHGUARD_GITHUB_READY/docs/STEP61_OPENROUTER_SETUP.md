# PhishGuard-PK Step 61: OpenRouter fallback when Groq signup is blocked

## Summary

- Free hosted model inference via **OpenRouter Free Models Router** (`openrouter/free`). It chooses a currently available free model. This **does not guarantee Qwen, open-source licensing, stable model identity, or 99% fraud detection accuracy**.
- Previously installed Step 59 local ML, intent AI, OTP negation fixes, URL structural policy, logo, PDF/CSV, mobile input font fixes stay intact.
- Existing Groq key remains supported if configured, but OpenRouter takes priority when both keys are present.
- No key or remote API call is required for standard `/analyze`.
- `/analyze/deep` requires explicit consent. It sends best-effort redacted message text to the chosen external provider. **Do not submit real OTPs, passwords, personal or confidential material.** Redaction may miss personal details and provider policies vary.
- No candidate URL from the message is fetched. API endpoints are hardcoded. Remote errors and rate limits return the original local result.

## Upload (cumulative Step 60 + 61)

1. Extract `PhishGuard_Step61_OpenRouter_GitHub_Update.zip` on your computer.
2. In GitHub open `phishguard-pk/main/PHISHGUARD_GITHUB_READY`.
3. Upload the *contents* of the extracted `PHISHGUARD_GITHUB_READY/` folder into this **same** repository folder, preserving each path. Do not upload the ZIP or create an extra nested parent folder. Replace matching files and commit.
4. Wait until Vercel reports its deployment as Ready.
5. At [OpenRouter API Keys](https://openrouter.ai/settings/keys), create a free account/key if registration is available.
6. In Vercel Project → Settings → Environment Variables, add `OPENROUTER_API_KEY` for Production. **Never put this value in GitHub, screenshots, chats or other files.** Redeploy after saving.
7. Visit `https://phishguard-pk.vercel.app/health`. Verify:

```json
{
  "version": "2.3.0",
  "deep_ai_release_id": "step61-openrouter-free-hybrid-v1",
  "deep_ai_provider": "OpenRouter",
  "deep_ai_configured": true
}
```

This is a subset of `/health`, not the entire response.

8. On the website, tick **Use Deep AI (free hosted model)** and test the already-known artificial JazzCash warning and a mock scam, without personal details. Check the `deep_ai.status` in exported JSON: `complete` proves a real provider output was used. `local_fallback` means the external provider was not used. A configured status alone does **not** prove a successful remote call.

## Limitations

- As verified from OpenRouter's current pricing/docs on November 3, 2026, free models normally allow **50 API requests/day and 20/minute** on an account without qualifying credit purchases. Quotas and availability may change; the free router picks different models from time to time.
- A best-effort **per-process** cap (35 OpenRouter requests/day, 12/minute) is implemented; it is not a distributed/global limit across Vercel instances and not abuse-proof. Site owner should add provider/key restrictions and server-side shared throttling for a public service.
- Remote providers can fail, change models, respond in an unexpected format, or disagree with local ML. Fallback keeps standard functionality working. No independent real-world validation has been completed and no 99% guarantee is made.
- Groq sign-up `signup_blocked` is a provider-side registration restriction, not a PhishGuard model error. OpenRouter is a different provider; its own registration may have independent requirements.

Official references:
- https://openrouter.ai/pricing
- https://openrouter.ai/openrouter/free
- https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request
