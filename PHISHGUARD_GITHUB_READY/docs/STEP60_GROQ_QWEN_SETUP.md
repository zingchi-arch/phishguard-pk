# Step 60: Groq Qwen Deep AI (optional and external)

## Deployment (once)
1. Open https://console.groq.com/keys and create a **free-tier API key**.
2. Open **Vercel -> Project -> Settings -> Environment Variables**.
3. Add `GROQ_API_KEY` as a **server-side secret** for Production (and optionally Preview).
4. Redeploy the latest commit. DO NOT upload the key to GitHub, paste it into website forms, or share it in chat.
5. Open `/health`. Look for `deep_ai_release_id: step60-groq-qwen-hybrid-v1` and `deep_ai_configured: true`.
6. On the webpage, tick **Use Deep AI (Groq Qwen)** and click Analyze.

### How it works
- Unticked: the previous Step59 local AI + offline URL system runs; **no third-party message transmission**.
- Ticked: one opt-in external Groq Qwen 3.8 27B request provides a second opinion. Local model still runs; disagreements show **Suspicious** unless a high-risk local rule stays active.
- The server redacts obvious links, emails, phone numbers, IDs, account numbers and long digit sequences first. **This is best-effort only**: names and context could still identify someone, so **do not paste private messages**.
- `/analyze/batch`, `/analyze/explain`, and `/analyze` remain entirely local.
- The Groq key is never sent to the browser. The provider sees only redacted data if the user consents. The app never opens URLs, authenticates senders or guarantees protection.
- If the key is missing, Groq is down, quota is reached, or Groq returns malformed JSON: response says `local_fallback`, with its status. Do not describe it as a Qwen result.
- Limit Qwen input to 2,000 characters; normal local input limit remains 10,000.
- A conservative per-instance cap of 12 requests/minute and 150/day is included, but this resets on serverless instance restart and is **not a reliable global budget**. Shared free-tier provider quota also applies. **Public endpoints can exhaust the key's allowance.** For a public launch, configure platform-side bot protection/rate limiting and abuse controls; per-process counters are not reliable across Vercel instances.

### Why no 99% claim?
- Groq/Qwen is a generic reasoning model, not a tested Pakistan SMS fraud classifier.
- The integration tests mock the provider; no real provider call is made without the user's API key.
- Fine-grained Urdu/Roman Urdu mixed-language validation and verified independent genuine SMS data remain incomplete.

### Official references (checked 3 Nov 2026)
- https://console.groq.com/docs/models
- https://console.groq.com/docs/structured-outputs
- https://console.groq.com/docs/reasoning
- https://console.groq.com/docs/rate-limits
- https://console.groq.com/docs/openai
