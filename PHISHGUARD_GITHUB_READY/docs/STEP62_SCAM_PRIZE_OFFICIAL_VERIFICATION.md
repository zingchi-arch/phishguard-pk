# Step 62: Context-aware prize redirect and official contact source comparison

Status: **ready to deploy**, not deployed by this ZIP. Version `2.4.0`.

## Fixes

1. Analyzer UI displays only **Deep AI** beside the checkbox. Screen-reader privacy explanation remains; user consent is still required before any external AI request.
2. Jeeto Pakistan / Honda-bike prize approval with a WhatsApp/mobile/contact redirect now triggers the `PK_JEETO_CLAIM` high-risk indicator (92/100 floor). Other unexpected bike/gold/cash prizes directed to private mobiles have an 88/100 floor. Includes Roman Urdu / Urdu variants such as `manzoor`, `nikla`, `gari`, `motorcycle`.
3. Limited official source registry includes ARY Digital / Jeeto Pakistan, UBL, HBL, JazzCash, Bank Alfalah, Easypaisa and BISP. Exact known official contact references are matched without authenticating the sender. Official host comparisons avoid deceptive lookalike domains.
4. New `/verify/contact` POST endpoint performs best-effort ONLINE inspection of a **fixed allowlisted official HTTPS page only**. It never opens links that arrive inside a suspicious message. When the official page cannot be reached or a number isn't on that page, the status explicitly stays inconclusive.
5. Existing local model, OpenRouter optional Deep AI, mobile textbox, logo, PDF and batch UI are preserved.

## Important scientific and safety limits

- Not every real prize is fraudulent; a private WhatsApp redirect after an unsolicited award is a strong social-engineering risk indicator, **not legal proof of fraud**.
- Some legitimate companies have official WhatsApp contacts. For example JazzCash publishes 0325-4444786 on its contact page and UBL publishes WhatsApp banking through its official helpline. A published contact can be spoofed, and an unpublished contact can be legitimate. **No SMS sender is authenticated by this tool.**
- Only organizations in the named limited registry can be cross-checked. Results are not an internet-wide lookup of every business or contact.
- An external page may require JavaScript, redirect or not list every authorized number. Missing numbers or network failures must never be treated as conclusive proof of fraud.
- Real-world 99% accuracy is not independently established; the risk indicator is uncalibrated.
- The external language model is optional and still uses user opt-in. It cannot verify that an organizer really chose a winner.

## Verified official sources used to prepare limited registry (2026-11-03)

- ARY Digital Jeeto Pakistan: https://arydigital.tv/jeeto-pakistan/
- UBL contact: https://ubldigital.com/More/ContactUs
- UBL WhatsApp banking: https://ubldigital.com/About-UBL/Speak-to-UBL
- HBL: https://www.hbl.com/
- JazzCash: https://www.jazzcash.com.pk/contact-us/
- Bank Alfalah: https://www.bankalfalah.com/contact-us/
- Easypaisa: https://easypaisa.com.pk/
- BISP: https://bisp.gov.pk/
- SBP scam messaging warning: https://www.sbp.org.pk/press/2022/Pr-24-Sep-2022.pdf

## Quick verification after deployment

1. `/health` should include `version: 2.4.0` and `contact_check_release_id: step62-prize-and-official-sources-v1`.
2. Website checkbox should show only `Deep AI` (not a paragraph of provider/free-plan text).
3. Original sample `jeeto pakistan ki trf sy apko honda ki bike manzoor hoi ha humary watsapp pr rabta kry 032498230333` must return **Scam** with `PK_JEETO_CLAIM` in JSON.
4. `JazzCash support: WhatsApp 0325-4444786. Never share your OTP.` should **not** be marked Scam solely for WhatsApp and OTP safety advice.
5. In the results, the official-source check should provide the curated official page. Live lookup only runs for a recognised brand and an actionable contact/link, and may return `inconclusive`.

To upload: unpack Step 62 ZIP, navigate to repository `PHISHGUARD_GITHUB_READY/`, upload/overwrite the included `phishguard`, `tests`, `docs` paths preserving structure, commit on `main`, and check Vercel Production deployment Ready. **Do not upload the ZIP itself as one file.** No API key change is required.
