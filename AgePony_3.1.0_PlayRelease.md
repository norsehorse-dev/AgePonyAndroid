# AgePony 3.1.0 — what is left before Google Play

Everything so far has been built and tested as the **foss** flavor. Play ships the **play**
flavor, which is a different artifact with an extra dependency in it, and that flavor has not
been built once during this work. That is the main gap.

## 1. Build and test the flavor you are actually shipping

```
cd ~/Apps/AgePonyAndroid
./gradlew :agepony-core:test :app:assemblePlayRelease :app:bundlePlayRelease
```

Outputs:

- APK for testing: `app/build/outputs/apk/play/release/app-play-release.apk`
- AAB for upload: `app/build/outputs/bundle/playRelease/app-play-release.aab`

| # | Check | Why |
| --- | --- | --- |
| 1.1 | `assemblePlayRelease` succeeds | The play flavor pulls in `libs.play.review`, which the foss builds never compile against. |
| 1.2 | Install the play APK and run the pre-release checks (sections B, C, D of the pre-release doc) | Same code, different dependency graph. The in-app review library is the only difference, but it is the only thing untested. |
| 1.3 | Use the app enough to trip the review nudge (`launchCount`, `reviewPromptShown`) | This code path exists only in the play flavor and cannot run in a foss build. |

## 2. Version code

**Check the Play Console before uploading.** `versionCode 8` must be strictly higher than the
highest code ever uploaded to any Play track, including internal testing and anything you rolled
back. F-Droid and Play share the same numbering here, so if a build was pushed to an internal
track that F-Droid never saw, 8 may already be taken. If so, bump both repos and re-tag before
anything goes out.

## 3. Store listing

| Item | Status |
| --- | --- |
| "What's new" text | `fastlane/metadata/android/en-US/changelogs/8.txt` works as-is: 498 characters against Play's 500 limit. |
| Full description | Updated to lead with 3.1.0. Note it still claims QR **sharing**; the code appears to only scan. Fix before it ships. |
| Screenshots | The four existing ones predate 3.1.0. Not required to update, but the new screens are the selling point: the multi-file chooser, the progress bar on a large file, and the inspector. |
| Privacy policy URL | Required for every app. Confirm the one on file still resolves. |

## 4. Play Console declarations

| Item | What applies here |
| --- | --- |
| Data safety | The app collects nothing and has no servers. Declare no data collected, no data shared. Be ready to explain `INTERNET`: it is used to fetch public keys from `github.com/<user>.keys`, nothing else. |
| Permissions | `INTERNET`, `CAMERA` (QR scanning), `NFC` (FIDO security keys). Each needs a plain-language justification if asked. |
| Export compliance | This is an encryption app, so the export-law questions in the Console apply. Standard cryptography using published algorithms, but answer it deliberately rather than clicking through. |
| Content rating | Unchanged from 3.0.2 if the questionnaire is already on file. |
| Target API level | `targetSdk 36` already meets Google's August 2026 deadline for API 36, so nothing to do. |

## 5. Rollout

1. Upload the AAB to **internal testing** first, not production.
2. Wait for the **pre-launch report**. Google runs it on real devices, and it catches crashes on
   hardware you do not own. Expect the crawler to stall at the biometric unlock; that is normal
   and not a failure.
3. Install from the internal track on your own phone and repeat check 1.2 against the
   Play-signed artifact. This is the only way to test what users will actually receive, since Play
   App Signing re-signs the upload.
4. Promote to production, staged rollout if you want the option to halt it.

## 6. Things that do not carry over from F-Droid

- The Play artifact is **not** the F-Droid artifact. Play App Signing re-signs it, so the two are
  different files with different signatures. That is expected, and it is why a user cannot switch
  between the F-Droid and Play builds without uninstalling.
- Reproducibility does not apply to the Play build. The guards stay in place because they are
  harmless and the foss build needs them.
- The fdroiddata MR is unaffected by anything in this document.
