# PhishGuard-PK: Free Public Website Setup

## GitHub par files upload
1. `PHISHGUARD_GITHUB_READY.zip` ko Windows par Extract All karo.
2. `https://github.com/zingchi-arch/phishguard-pk` kholo.
3. Empty repo mein `uploading an existing file` dabao.
4. Extracted folder KE ANDAR KI files/folders drag/drop karo. **ZIP file ko upload mat karo.**
5. `Commit changes` dabao. Check karo: `render.yaml`, `phishguard/`, `models/`, `requirements-deploy.txt` root mein nazar aayen.

## Render public site (separate step)
1. `https://dashboard.render.com/` par free account login.
2. `New +` -> `Blueprint` -> connect GitHub repo `zingchi-arch/phishguard-pk`.
3. `render.yaml` config se free web service deploy karo. Agar payment method ya paid plan maange, proceed mat karna.
4. Render ka real `.onrender.com` link open kar ke website check karo.

### Limitations
- Free Render web service 15 min idle par sleep karti hai, first visit slow ho sakta hai. No always-on instant hosting guarantee.
- Existing model is provisional and not validated for real-world fraud protection.
- Raw collected/user message datasets GitHub par **exclude** kiye hain.
- Data, 50-100 independent real tests, XLM-R GPU model, and real-label URL model still pending.
