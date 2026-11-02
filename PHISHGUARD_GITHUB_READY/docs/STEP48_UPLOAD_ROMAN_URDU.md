# Step 48 GitHub upload: 4 folders only

1. `PhishGuard_Step48_GitHub_Patch.zip` extract karo.
2. GitHub `zingchi-arch/phishguard-pk` ke `PHISHGUARD_GITHUB_READY` folder mein jao.
3. ZIP ke `PHISHGUARD_GITHUB_READY` ke ANDAR se **docs**, **phishguard**, **scripts**, **tests** ko drag/drop karo.
4. Commit changes karo; Vercel Deployments mein latest `Ready` check karo.
5. Research-only RF model ya dataset ZIP GitHub par upload MAT karo. Website design unchanged rahega.

### Included code
- `phishguard/url_policy.py`: gov.pk aur hyphenated brand-hostname spoof corrections.
- `scripts/step48_url_benchmark.py`: 10k offline source-label comparisons and research RF, no suspicious link opened.
- `tests/test_step48_url_benchmark.py`: regression tests.
- `docs/STEP48_URL_COVERAGE_AND_RF_DECISION.md`: honest dataset result and limits.

Old structural URL heuristic covers only a very small share of source-labelled phishing URLs (104 / 5,000). This is a known research limitation. Supervised RF is NOT deployed because independently verified URL performance is still missing.
