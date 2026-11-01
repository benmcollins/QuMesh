# Packaging QuMesh

QuMesh ships as:

- a `.dmg` on macOS,
- an NSIS-based `.exe` installer on Windows,
- a `.deb` for Debian 13 and Ubuntu 26.04 on amd64 and arm64
  (four `.deb`s per release), distributed both as release assets
  and through a signed APT repo on GitHub Pages.

The macOS and Windows bundles are self-contained — Qt, the QML modules,
and OpenSSL are inlined so the app runs on a fresh OS install without
needing developer tooling. The Linux `.deb` instead `Depends:` on the
distro-provided Qt 6 + libssh + OpenSSL, which keeps the package small
and lets apt handle Qt-side upgrades for free.

## Cutting a release

1. Bump `PROJECT_VERSION` at the top of `CMakeLists.txt`.
2. Commit and push, then tag:
   ```
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. The `Release` GitHub Actions workflow builds both platforms, runs
   the test suite, packages with CPack, and publishes a draft GitHub
   Release with the two artifacts attached.

## Local packaging (smoke test)

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build
cpack -G DragNDrop      # macOS
cpack -G NSIS           # Windows
cpack -G DEB            # Linux
```

The output lands in `build/`. Note: Homebrew Qt installs everything
as symlinks back into `/opt/homebrew/Cellar`, so a locally built DMG
will reference those paths and won't run on another machine. Use the
CI artifact for actual distribution.

On Linux the `.deb` is built against whatever Qt/libssh/libssl are
installed in the local prefix — `dpkg-shlibdeps` resolves them at
packaging time. To ship a Debian-13-compatible .deb, build inside a
`debian:13` container (which is what CI does); building on Ubuntu
26.04 produces a Ubuntu-26.04-compatible .deb.

## Signing and notarization

Both platforms ship unsigned by default. The bundle still runs, but
users see the platform's standard "unverified publisher" warning on
first launch. Provisioning the secrets below activates signing and (on
macOS) notarization without any further code changes.

### macOS

| Secret                          | Source |
|---------------------------------|--------|
| `MAC_DEVELOPER_ID_P12_BASE64`   | Your Developer ID Application certificate + private key, exported from Keychain Access as a `.p12`, then base64-encoded (`base64 -i cert.p12 \| pbcopy`). The release workflow imports it into a fresh per-job keychain so codesign can find the identity. |
| `MAC_DEVELOPER_ID_P12_PASSWORD` | The export password you set when generating the `.p12`. |
| `MAC_SIGNING_IDENTITY`          | The Developer ID Application identity string, e.g. `Developer ID Application: Your Name (TEAMID)`. Run `security find-identity -v -p codesigning` on the build machine to list candidates. |
| `MAC_NOTARIZE_APPLE_ID`         | The Apple ID associated with your developer account. |
| `MAC_NOTARIZE_TEAM_ID`          | Your 10-character Apple Developer Team ID. |
| `MAC_NOTARIZE_PASSWORD`         | An app-specific password generated at <https://appleid.apple.com> (Sign-In and Security → App-Specific Passwords). |

Add them under **Settings → Secrets and variables → Actions** in this
repo. The workflow imports the cert with `security import` +
`set-key-partition-list`; the CMake install step then runs
`app/codesign-bundle.sh`, which signs Sparkle.framework's internal
helpers (XPCServices, Autoupdate, Updater.app) inner-out before
sealing the app shell with hardened-runtime entitlements from
`app/QuMesh.entitlements`. The release workflow follows up with
`notarytool submit --wait` and `stapler staple`.

If you also have an Apple Developer ID **Installer** certificate and
want a signed `.pkg` instead of a `.dmg`, switch CPack to the
`productbuild` generator in `CMakeLists.txt` and add
`MAC_INSTALLER_IDENTITY` plumbing — out of scope for v1.

### Windows

| Secret                  | Source |
|-------------------------|--------|
| `WIN_SIGN_THUMBPRINT`   | SHA-1 thumbprint of a code-signing certificate already installed in the GitHub-hosted runner's certificate store. Install the cert in a runner-setup step (or move to a self-hosted runner) and pass the thumbprint here. |

The CMake install step invokes `signtool sign /sha1 <thumbprint>` with
SHA-256 file digest and a DigiCert timestamp.

For EV certificates that require a USB token, the runner must be
self-hosted (the token can't be plugged into a GitHub-hosted VM).

## In-app auto-update (Sparkle)

QuMesh on macOS embeds [Sparkle](https://sparkle-project.org/) so users
get a "Check for updates…" UX backed by GitHub Releases. The release
workflow signs each `.dmg` with an EdDSA private key, generates an
`appcast.xml` that lists the new release plus the prior history, and
uploads it as a release asset. The bundled app's Info.plist points
`SUFeedURL` at `https://github.com/<owner>/<repo>/releases/latest/download/appcast.xml`,
which always resolves to the current latest release's asset.

### Generating the EdDSA keypair (one-time)

Use Sparkle's `generate_keys` tool — the easiest source is the same
tarball CMake fetches at build time:

```
curl -sLO https://github.com/sparkle-project/Sparkle/releases/download/2.6.4/Sparkle-2.6.4.tar.xz
tar -xf Sparkle-2.6.4.tar.xz
./bin/generate_keys
```

The tool prints a base64 public key to stdout and either stores the
private key in your macOS keychain (default) or to a file with
`-f private.pem`. For CI, write the private key to a file and copy its
contents into the `SPARKLE_ED_PRIVATE_KEY` repo secret.

The base64 public key goes into `app/sparkle_pub_ed_key` (just the
key, no headers, no whitespace) and is committed. CMake reads it at
configure time and substitutes it into the bundle Info.plist as
`SUPublicEDKey`. Without a key the build still produces a runnable
bundle — Sparkle just refuses to install any update because no
signature can validate.

### Required CI secret

| Secret                       | Source |
|------------------------------|--------|
| `SPARKLE_ED_PRIVATE_KEY`     | Base64 EdDSA private key (single-line, no headers). Used to sign both `.dmg` (via Sparkle's `sign_update`) and `.exe` (via WinSparkle's `winsparkle-tool sign`) — Sparkle and WinSparkle share key format, so one keypair covers both platforms. |

### Windows side (WinSparkle)

The Windows build uses [WinSparkle 0.9.2](https://github.com/vslavik/winsparkle).
WinSparkle 0.8+ adopted Sparkle's EdDSA key format exactly, so the
same `app/sparkle_pub_ed_key` (and the same `SPARKLE_ED_PRIVATE_KEY`
secret) drives both platforms. Nothing extra to provision once Sparkle
is set up.

The release workflow signs each `.exe` with `winsparkle-tool.exe sign
--private-key-file …` and merges the Windows `<item>` into the same
`appcast.xml` the macOS job produces. Each item carries `<sparkle:os>`
so Sparkle and WinSparkle each pick their own.

### Code signing on Windows

There's no equivalent to Apple's Developer ID baked into the workflow
yet — Windows code signing requires buying a certificate from a CA
(Sectigo via SSL.com is $80–200/yr; Azure Trusted Signing is ~$10/mo).
Without one, SmartScreen warns "Windows protected your PC" on first
launch but the installer still works, and WinSparkle's *update*
signature check is independent of Authenticode anyway. Wire this up
later when a cert is acquired.

### Linux side (appcast reader, no installer)

The Linux build has no in-app installer — apt owns upgrades there. The
"Updates" button still works: `app/src/updater_linux.cpp` fetches the
same `appcast.xml`, parses it, and pops a small dialog
(`qml/LinuxUpdateDialog.qml`) when a newer release is found. The
dialog shows the release notes and offers two actions:

- **Open Release Page** — Qt.openUrlExternally to the matching
  `releases/tag/v...` URL.
- **Copy `sudo apt update && sudo apt upgrade qumesh`** — the
  one-liner that works when the user has the QuMesh APT repo added.

No new keypair or signature work is needed here: TLS to github.com
gates the appcast fetch, and apt's own GPG check (against `apt-pub.asc`)
gates the actual upgrade. The Linux updater never installs anything.

### Disabling auto-update for a build

Pass `-DQUMESH_AUTOUPDATE=OFF` at configure time. The Updater QML
singleton then reports `available() === false`, so the in-app "Updates"
button hides itself.

## Linux APT repository (one-time setup)

The release-apt.yml workflow publishes a signed APT repo to the
`gh-pages` branch each time the `Release` workflow ships new `.deb`s.
Before it can sign anything the maintainer has to provision a GPG
keypair and a few repo settings:

1. **Generate the signing keypair** (one time, on a trusted box):

   ```
   gpg --batch --quick-generate-key \
       'QuMesh APT <ben@ironrocketsmc.org>' ed25519 sign 0
   gpg --list-keys
   ```

2. **Export the public key into the repo:**

   ```
   gpg --armor --export <fingerprint> > branding/apt-pub.asc
   ```

   Commit it (overwriting the placeholder); users `curl` it from the
   Pages site to populate `/etc/apt/keyrings/qumesh.asc`.

3. **Export the private key and stash it as a secret:**

   ```
   gpg --armor --export-secret-keys <fingerprint> | base64 -w0
   ```

   Paste the output into the repo's **Settings → Secrets and variables
   → Actions** → new secret named `APT_SIGNING_KEY`. The workflow
   base64-decodes and imports it into an ephemeral GPG home for the
   signing step, then exits.

4. **Enable GitHub Pages** — Settings → Pages → Source: **GitHub
   Actions**. No `gh-pages` branch needed; `release-apt.yml`
   uploads a full site artifact via `actions/upload-pages-artifact`
   and `actions/deploy-pages` swaps it in atomically. Each run is
   stateless — the workflow reconstructs the full `.deb` pool by
   listing every `v*` GitHub Release and downloading its assets,
   so a re-run can fix metadata without touching any persistent
   branch state.

Until step 3 is done the apt workflow is a no-op — it logs a
`::notice::` and skips. Releases continue to ship `.deb` assets on the
Release page either way; only the apt-update-via-repo path is gated
on the key. Replacing the keypair later requires bumping the
`apt-pub.asc` users have already added, which means they'll see a
`NO_PUBKEY` warning on the next `apt update` — pick a key length and
identity you're happy to commit to.

## Translations

User-facing strings are wrapped in `qsTr(...)` and extracted by
`lupdate` into `app/translations/qumesh_<locale>.ts`. The `app/`
CMake target calls `qt_add_translations()` to wire this up:

- `cmake --build build --target update_translations` runs `lupdate`
  to refresh the `.ts` files with any new strings. Edit the `.ts`
  files (manually or in Qt Linguist) to add translations.
- `cmake --build build --target release_translations` compiles the
  `.ts` files into `.qm` and embeds them under `qrc:/i18n/` in the
  app's QML resource module. The release target runs automatically
  as part of the normal build.
- At launch, `main.cpp` installs a `QTranslator` that loads
  `qumesh_<system locale>.qm` if present, falling back to the
  un-translated English source baked into the `qsTr()` calls.

To add a new language:

1. Append `translations/qumesh_<locale>.ts` to the `TS_FILES` list
   in `app/CMakeLists.txt`.
2. Run the `update_translations` target — it will create the file
   and seed it from the source strings.
3. Translate; rebuild.

## What the bundle contains

- `QuMesh.app/Contents/MacOS/QuMesh` (macOS), `QuMesh.exe` (Windows),
  or `/usr/bin/QuMesh-app` + a `/usr/bin/qumesh` symlink (Linux).
- The Qt frameworks linked at build time, copied by `macdeployqt` /
  `windeployqt` from the Qt install the build used. On Linux the
  `.deb` instead `Depends:` on the system Qt — no inlining.
- The QML modules QuMesh imports (`QtQuick`, `QtQuick.Controls.Basic`,
  `QtQuick.Layouts`, `QtQuick.Dialogs`, etc.), discovered via
  `qmlimportscanner`. (Linux: pulled in via Qt 6 declarative-dev.)
- `libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `legacy.dll` and
  `ssh.dll` on Windows (Qt's deploy tool doesn't follow non-Qt DLL
  dependencies).
- The bundled fonts (IBM Plex Sans, JetBrains Mono).
- `LICENSE.rtf` — Apache 2.0 license text, rendered from the
  repo-root `LICENSE.md`. Lives at `QuMesh.app/Contents/Resources/`
  inside the bundle and at the `.dmg` root next to the app. On
  Linux the same source ships as `/usr/share/doc/qumesh/copyright`
  per Debian policy.
- Linux also installs `qumesh.desktop` (apps menu) and
  `com.insynergy.QuMesh.metainfo.xml` (AppStream catalogue entry)
  plus the hicolor icon set at 16/24/32/48/64/96/128/256/512 px.

### Windows install layout

The Windows install is flat: `QuMesh.exe`, `qt.conf`, and every DLL it
loads (Qt, OpenSSL, libssh, WinSparkle) sit together in
`%ProgramFiles%\QuMesh\`, with `plugins\`, `qml\` and `translations\`
underneath. The Windows loader only searches the exe's own directory
and `PATH` for DLLs, so nothing the exe imports can live in a
subdirectory. Qt's deploy script defaults to putting the DLLs in
`bin\`, so `app/CMakeLists.txt` points it at the install root instead.
Through v1.4.1 it didn't, so no Windows release could start (#445).

`.github/scripts/verify-windows-install.sh <install-dir>` checks a
tree for that layout, walks every import table with `dumpbin`, then
launches the app with `PATH` and the Qt env vars stripped. CI runs it
on a `cmake --install` prefix on every PR, and `release.yml` runs it
after silently installing the real NSIS installer. To check a local
build from a Visual Studio developer shell in Git Bash:

```
cmake --install build --prefix /c/tmp/qumesh-install
.github/scripts/verify-windows-install.sh /c/tmp/qumesh-install
```

## DMG mount-window layout (macOS)

The `.dmg` opens to a 640×400 window with a branded slate-and-cyan
background and the two icons pre-positioned: `QuMesh.app` on the left,
the `Applications` symlink on the right, with a chevron pointing
between them.

- The background is rendered by `branding/build-icons.py` from
  `branding/svg/qumesh-dmg-bg.svg` into a multi-resolution TIFF
  (`branding/build/dmg-background.tiff`, embedding both 1× and 2×
  pages so retina displays stay crisp). Both PNG variants are also
  written and committed.
- The mount window's layout is set by
  `app/dmg-setup.applescript.in` — Finder runs it once when the
  staged DMG is mounted during `cpack` and the resulting `.DS_Store`
  is sealed into the final read-only image. The icon positions in
  the script match the glow centres in the background SVG; if you
  reposition one, move both.
- The volume itself uses a custom icon (the slate squircle + Q mark
  + cyan install-badge in `branding/svg/qumesh-dmg-volume.svg`,
  rendered to `branding/build/qumesh-dmg.icns`). The same AppleScript
  copies it onto the mounted volume as `.VolumeIcon.icns` and runs
  `SetFile -a C` to set the HasCustomIcon Finder flag — required for
  Finder to actually pick the file up. (CPack's DragNDrop generator
  drops dotfiles other than `.background/` and `.DS_Store` during
  its internal staging→DMG copy, so a normal `install(FILES)` of
  `.VolumeIcon.icns` doesn't survive.)

The `LICENSE.rtf` license-acceptance dialog that hdiutil presents
before mounting the DMG is generated at CMake configure time by
`branding/build-license.py` from `LICENSE.md`. The same RTF is what
CPack's NSIS generator shows in the Windows installer's license
page.
