# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

# The app is built as a STATIC backing library plus a thin executable
# that just owns main(). Splitting them out lets `app/tests/` link the
# QML module directly (see `test_qml_engine_loads`) without standing
# up a second `qt_add_qml_module` call that would silently drift from
# the production wiring. Note: `Updater` is intentionally NOT in the
# library — its implementation is platform-specific (Sparkle on macOS,
# WinSparkle on Windows, appcast-reader on Linux, no-op stub elsewhere)
# and each consumer of qumesh_appcore picks one at link time.
qt_add_library(qumesh_appcore STATIC
    src/configstore.cpp
    src/configstore.h
    src/secret_codec.cpp
    src/secret_codec.h
    src/keystore.cpp
    src/keystore.h
    src/ssh_tunnel_opener.cpp
    src/ssh_tunnel_opener.h
    src/sshtunnelhost.cpp
    src/sshtunnelhost.h
    src/computermodel.cpp
    src/computermodel.h
    src/machinedetailscontroller.cpp
    src/machinedetailscontroller.h
    src/migrationcontroller.cpp
    src/migrationcontroller.h
    src/solcontroller.cpp
    src/solcontroller.h
    src/idercontroller.cpp
    src/idercontroller.h
    src/kvmcontroller.cpp
    src/kvmcontroller.h
    src/kvmframebuffer.cpp
    src/kvmframebuffer.h
    src/kvmviewer.cpp
    src/kvmviewer.h
    src/asciicast_recorder.cpp
    src/asciicast_recorder.h
    src/mjpeg_mov_recorder.cpp
    src/mjpeg_mov_recorder.h
    src/filename_formatter.cpp
    src/filename_formatter.h
    src/appinfo.cpp
    src/appinfo.h
    src/certmodel.cpp
    src/certmodel.h
    src/scannercontroller.cpp
    src/scannercontroller.h
    src/setupbincontroller.cpp
    src/setupbincontroller.h
    src/batchrunner.cpp
    src/batchrunner.h
    src/batchcontroller.cpp
    src/batchcontroller.h
    src/backup_codec.cpp
    src/backup_codec.h
    src/backupcontroller.cpp
    src/backupcontroller.h
    src/qml_registration.cpp
    src/qml_registration.h
)

# `src/updater.h` is intentionally NOT listed in qumesh_appcore: AUTOMOC
# would generate Updater's moc data here AND in every consumer that adds
# the matching impl (qumesh: updater.mm/_win.cpp/_linux.cpp,
# test_qml_engine_loads: updater.cpp), producing duplicate-symbol link
# errors. AUTOMOC matches the header to the .cpp/.mm in the same target's
# source list, so each consumer gets the moc data exactly once.

qt_add_executable(qumesh
    src/main.cpp
    src/updater.h
)

# Build-time configuration header carrying PROJECT_VERSION and the
# ISO build date. Consumed by AppInfo for the "About" dialog (#246).
string(TIMESTAMP QUMESH_BUILD_DATE "%Y-%m-%d" UTC)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/appinfo_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/appinfo_config.h"
    @ONLY
)
target_include_directories(qumesh_appcore PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")

# Embed LICENSE.md as a Qt resource so the About dialog can display
# the full license without depending on a filesystem path that varies
# between dev runs, macOS bundles, and the Windows installer layout.
qt_add_resources(qumesh_appcore "qumesh_appdata"
    PREFIX "/QuMesh"
    BASE "${CMAKE_SOURCE_DIR}"
    FILES "${CMAKE_SOURCE_DIR}/LICENSE.md"
)

set_source_files_properties(
    qml/Theme/Colors.qml
    qml/Theme/Type.qml
    qml/Theme/Motion.qml
    qml/Theme/Spacing.qml
    qml/Theme/ThemePalette.qml
    qml/Theme/ActivityHeartbeat.qml
    qml/Paths.qml
    PROPERTIES QT_QML_SINGLETON_TYPE TRUE
)

qt_add_translations(qumesh_appcore
    TS_FILES
        translations/qumesh_en.ts
    QM_FILES_OUTPUT_VARIABLE qm_files
    LUPDATE_OPTIONS
        -no-obsolete
)

qt_add_qml_module(qumesh_appcore
    URI QuMesh
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/ComputerListView.qml
        qml/ComputerStatusPane.qml
        qml/EditComputerDialog.qml
        qml/ScanDialog.qml
        qml/HttpProxyDialog.qml
        qml/UserAccountDialog.qml
        qml/AdminPasswordDialog.qml
        qml/ConfirmDialog.qml
        qml/AboutDialog.qml
        qml/LinuxUpdateDialog.qml
        qml/AddCertificateDialog.qml
        qml/IssueCertificateDialog.qml
        qml/TlsModeDialog.qml
        qml/CertDetailsDialog.qml
        qml/WiFiProfileDialog.qml
        qml/EventSubscriptionDialog.qml
        qml/Hdr8021FilterDialog.qml
        qml/IpHeadersFilterDialog.qml
        qml/SystemDefensePolicyDialog.qml
        qml/WakeAlarmDialog.qml
        qml/WatchdogDialog.qml
        qml/WatchdogActionsDialog.qml
        qml/Wired8021xDialog.qml
        qml/EnvDetectionDialog.qml
        qml/UserInitiatedDialog.qml
        qml/MpsServerDialog.qml
        qml/CiraPolicyDialog.qml
        qml/LocalAmtPromptDialog.qml
        qml/MigrationBanner.qml
        qml/TitleBar.qml
        qml/StatusBar.qml
        qml/StatusLed.qml
        qml/Section.qml
        qml/SectionHeader.qml
        qml/Terminal.qml
        qml/IderPanel.qml
        qml/KvmPanel.qml
        qml/SessionWindow.qml
        qml/SolPanel.qml
        qml/MachineDetailsWindow.qml
        qml/CertificatesWindow.qml
        qml/CertTrustDialog.qml
        qml/SshHostKeyTrustDialog.qml
        qml/ResultBanner.qml
        qml/SetupBinWindow.qml
        qml/BatchProgressDialog.qml
        qml/BackupExportDialog.qml
        qml/BackupImportDialog.qml
        qml/AccentButton.qml
        qml/BootMenu.qml
        qml/AppMark.qml
        qml/AppWindow.qml
        qml/CertPinFlash.qml
        qml/FlatButton.qml
        qml/HttpsBootPrompt.qml
        qml/OcrPrompt.qml
        qml/Icon.qml
        qml/KvmSettingsDialog.qml
        qml/OptInPrompt.qml
        qml/Paths.qml
        qml/PlatformErasePrompt.qml
        qml/PowerPolicyDialog.qml
        qml/SecureErasePrompt.qml
        qml/MachineDetails/OverviewSection.qml
        qml/MachineDetails/TimeSection.qml
        qml/MachineDetails/HardwareSection.qml
        qml/MachineDetails/EventLogSection.qml
        qml/MachineDetails/AuditLogSection.qml
        qml/MachineDetails/WatchdogsSection.qml
        qml/MachineDetails/EventSubscriptionsSection.qml
        qml/MachineDetails/WakeAlarmsSection.qml
        qml/MachineDetails/ActiveSessionsSection.qml
        qml/MachineDetails/WsmanBrowserSection.qml
        qml/MachineDetails/SystemDefenseSection.qml
        qml/MachineDetails/RuleCard.qml
        qml/MachineDetails/UserAccountsSection.qml
        qml/MachineDetails/PinnedCertificatesSection.qml
        qml/MachineDetails/NetworkSection.qml
        qml/MachineDetails/DeviceCertStoreSection.qml
        qml/MachineDetails/WirelessSection.qml
        qml/MachineDetails/CiraSection.qml
        qml/MachineDetails/PowerSection.qml
        qml/MachineDetails/SessionLaunchersSection.qml
        qml/Theme/Colors.qml
        qml/Theme/Type.qml
        qml/Theme/Motion.qml
        qml/Theme/Spacing.qml
        qml/Theme/ThemePalette.qml
        qml/Theme/ActivityHeartbeat.qml
        qml/HeartbeatBar.qml
    RESOURCES
        qml/fonts/IBMPlexSans-Regular.ttf
        qml/fonts/IBMPlexSans-Medium.ttf
        qml/fonts/JetBrainsMono-Regular.ttf
)

target_include_directories(qumesh_appcore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(qumesh_appcore PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Network
    Qt6::Svg
    qumesh_migrate
    qumesh_redir
    qumesh_terminal
    qumesh_ider
    qumesh_kvm
    qumesh_certs
    qumesh_wsman
    qumesh_rmcp
    qumesh_ssh
    OpenSSL::Crypto
)

# Platform-specific KeyStore backend for the v3 SecretCodec envelope
# (#306). Each platform compiles exactly one impl into qumesh_appcore;
# the abstract interface lives in keystore.h.
if(APPLE)
    target_sources(qumesh_appcore PRIVATE src/keystore_mac.mm)
    set_source_files_properties(src/keystore_mac.mm
        PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
    target_link_libraries(qumesh_appcore PRIVATE
        ${SECURITY_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
elseif(WIN32)
    target_sources(qumesh_appcore PRIVATE src/keystore_win.cpp)
    target_link_libraries(qumesh_appcore PRIVATE crypt32)
else()
    target_sources(qumesh_appcore PRIVATE src/keystore_linux.cpp)
endif()

target_link_libraries(qumesh PRIVATE qumesh_appcore)

# qumesh_appcore is a STATIC backing target for the `QuMesh` QML module.
# qt_add_qml_module produces a static plugin (`qumesh_appcoreplugin`) and
# an OBJECT initialiser (`qumesh_appcoreplugin_init`) that registers it at
# startup via `Q_IMPORT_PLUGIN(QuMeshPlugin)`. qt_add_executable's
# qmlimportscanner only auto-imports plugins whose `import` statements it
# can find by scanning the executable's QML_FILES — `qumesh` has no QML
# files (Main.qml lives in qumesh_appcore), so the scan finds nothing and
# no plugin gets linked. The result is a build that succeeds but fails at
# runtime with "No module named 'QuMesh' found". Link them explicitly.
target_link_libraries(qumesh PRIVATE
    qumesh_appcoreplugin
    qumesh_appcoreplugin_init
)

# --- Branding -------------------------------------------------------
#
# The master SVGs in branding/svg/ use `currentColor` so they pick
# up the surrounding text colour in CSS — but Qt's SVG renderer
# resolves it to black. Bake two variants at configure time (slate
# for the light theme, near-white for the dark) and let `AppMark.qml`
# pick the right one based on the active palette.

set(_branding_dir "${CMAKE_SOURCE_DIR}/branding")
set(_baked_icons_dir "${CMAKE_CURRENT_BINARY_DIR}/icons")
file(MAKE_DIRECTORY "${_baked_icons_dir}")

# Same bake-on-configure pattern applies to the Lucide UI icon set
# (under branding/svg/lucide/) — the upstream SVGs are also authored
# with `stroke="currentColor"`. Keeping all the swaps in one block so
# branding + UI icons travel through the same pipeline; see #248.
set(_lucide_icons
    alarm-clock arrow-left-right badge-check bell clipboard-list
    clock cloud-cog cpu dog layout-dashboard lock monitor network
    power scroll-text shield terminal users wifi
)

set(_baked_icon_files "")
foreach(_svg_name IN ITEMS qumesh-mark qumesh-mark-small icon-sun icon-moon)
    file(READ "${_branding_dir}/svg/${_svg_name}.svg" _svg_src)
    string(REPLACE "currentColor" "#1e293b" _svg_slate "${_svg_src}")
    string(REPLACE "currentColor" "#E6EDF3" _svg_light "${_svg_src}")
    file(WRITE "${_baked_icons_dir}/${_svg_name}-slate.svg" "${_svg_slate}")
    file(WRITE "${_baked_icons_dir}/${_svg_name}-light.svg" "${_svg_light}")
    list(APPEND _baked_icon_files
        "${_baked_icons_dir}/${_svg_name}-slate.svg"
        "${_baked_icons_dir}/${_svg_name}-light.svg")
endforeach()

foreach(_svg_name IN LISTS _lucide_icons)
    file(READ "${_branding_dir}/svg/lucide/${_svg_name}.svg" _svg_src)
    string(REPLACE "currentColor" "#1e293b" _svg_slate "${_svg_src}")
    string(REPLACE "currentColor" "#E6EDF3" _svg_light "${_svg_src}")
    file(WRITE "${_baked_icons_dir}/${_svg_name}-slate.svg" "${_svg_slate}")
    file(WRITE "${_baked_icons_dir}/${_svg_name}-light.svg" "${_svg_light}")
    list(APPEND _baked_icon_files
        "${_baked_icons_dir}/${_svg_name}-slate.svg"
        "${_baked_icons_dir}/${_svg_name}-light.svg")
endforeach()

qt_add_resources(qumesh_appcore "qumesh_icons"
    PREFIX "/icons"
    BASE   "${_baked_icons_dir}"
    FILES  ${_baked_icon_files}
)

# Standalone tile asset (slate background + light Q) for the window
# icon — see main.cpp's QGuiApplication::setWindowIcon. Lives under
# branding/svg/ rather than the baked dir because it doesn't need a
# colour swap; the slate background and light-grey mark are baked in.
qt_add_resources(qumesh_appcore "qumesh_tile_icon"
    PREFIX "/icons"
    BASE   "${_branding_dir}/svg"
    FILES
        "${_branding_dir}/svg/qumesh-mark-tile.svg"
)

# Platform app icons (already pre-built under branding/build/).
if(APPLE)
    set(_macos_icns "${_branding_dir}/build/qumesh.icns")
    set_source_files_properties("${_macos_icns}"
        PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(qumesh PRIVATE "${_macos_icns}")

    # Bundle the rendered LICENSE.rtf next to qumesh.icns under
    # QuMesh.app/Contents/Resources/. Same POST_BUILD-copy pattern as
    # Sparkle.framework above — CMake's `MACOSX_PACKAGE_LOCATION` for
    # source files is unreliable for generated files (the COPY rule
    # only gets emitted for files that exist at configure time), so
    # we just stage the copy ourselves.
    add_dependencies(qumesh qumesh_license_rtf)
    add_custom_command(TARGET qumesh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QUMESH_LICENSE_RTF}"
            "$<TARGET_BUNDLE_DIR:qumesh>/Contents/Resources/LICENSE.rtf"
        VERBATIM
    )
endif()

# On Windows QuMesh.exe sits at the install root (`%ProgramFiles%\QuMesh\`)
# and every DLL it imports must sit beside it — the loader searches the
# exe's own directory and PATH, never a subdirectory. WinSparkle, the
# OpenSSL/libssh DLLs and the Qt deploy script all install here; see
# the comment above qt_generate_deploy_qml_app_script() below.
set(_qumesh_win_bindir ".")

# --- In-app auto-update ----------------------------------------------
#
# Two platform backends share the QML-facing `Updater` facade
# (src/updater.h): Sparkle on macOS and WinSparkle on Windows. Both
# binaries are pulled at configure time from their respective GitHub
# Releases (pinned URL + SHA256, no vendored binary in the repo). The
# bundle/install steps drop the framework / DLL next to the executable,
# and a checked-in public key in this directory (`sparkle_pub_ed_key`,
# `winsparkle_pub_ed_key`) is read in for the runtime signature check.
# Without a key set the build still produces a runnable artifact;
# Sparkle/WinSparkle simply refuse to install any update they can't
# verify.

option(QUMESH_AUTOUPDATE "Build with in-app auto-update (Sparkle/WinSparkle)" ON)

set(QUMESH_APPCAST_FEED_URL
    "https://github.com/benmcollins/QuMesh/releases/latest/download/appcast.xml"
    CACHE STRING "Sparkle/WinSparkle appcast.xml feed URL")

if(APPLE AND QUMESH_AUTOUPDATE)
    include(FetchContent)
    FetchContent_Declare(
        sparkle
        URL      https://github.com/sparkle-project/Sparkle/releases/download/2.6.4/Sparkle-2.6.4.tar.xz
        URL_HASH SHA256=50612a06038abc931f16011d7903b8326a362c1074dabccb718404ce8e585f0b
    )
    FetchContent_MakeAvailable(sparkle)

    set(_sparkle_framework "${sparkle_SOURCE_DIR}/Sparkle.framework")

    add_library(Sparkle::Sparkle SHARED IMPORTED)
    set_target_properties(Sparkle::Sparkle PROPERTIES
        FRAMEWORK TRUE
        IMPORTED_LOCATION             "${_sparkle_framework}/Sparkle"
        INTERFACE_INCLUDE_DIRECTORIES "${_sparkle_framework}/Headers"
    )

    target_sources(qumesh PRIVATE src/updater.mm)
    target_link_libraries(qumesh PRIVATE Sparkle::Sparkle "-framework AppKit")

    # Sparkle.framework lives next to the app inside Contents/Frameworks
    # at runtime; copy it in post-build so launch-from-build-tree also
    # works, and add the matching rpath.
    set_target_properties(qumesh PROPERTIES
        INSTALL_RPATH "@executable_path/../Frameworks"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    # Use `ditto` to copy the framework, not `cmake -E copy_directory`:
    # the CMake helper dereferences symlinks, which produces a malformed
    # Sparkle.framework (both Versions/Current/ and Versions/B/ end up as
    # full duplicate trees, and the top-level Sparkle/Headers/Resources
    # symlinks become real files). codesign then refuses with
    # "bundle format is ambiguous (could be app or framework)" and
    # notarization rejects every nested binary. `ditto` preserves the
    # symlink layout Sparkle expects. The `rm -rf` keeps re-builds clean,
    # since ditto merges into an existing target rather than replacing it.
    add_custom_command(TARGET qumesh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_BUNDLE_DIR:qumesh>/Contents/Frameworks"
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "$<TARGET_BUNDLE_DIR:qumesh>/Contents/Frameworks/Sparkle.framework"
        COMMAND ditto
            "${_sparkle_framework}"
            "$<TARGET_BUNDLE_DIR:qumesh>/Contents/Frameworks/Sparkle.framework"
        VERBATIM
    )

    # Custom Info.plist template so we can inject the Sparkle keys.
    # Read the EdDSA public key from a checked-in file; empty file is
    # fine for unsigned dev builds (Sparkle just refuses to install).
    set(_sparkle_pub_key_file "${CMAKE_CURRENT_SOURCE_DIR}/sparkle_pub_ed_key")
    if(EXISTS "${_sparkle_pub_key_file}")
        file(READ "${_sparkle_pub_key_file}" SPARKLE_PUBLIC_ED_KEY)
        string(STRIP "${SPARKLE_PUBLIC_ED_KEY}" SPARKLE_PUBLIC_ED_KEY)
    else()
        set(SPARKLE_PUBLIC_ED_KEY "")
    endif()
    set(SPARKLE_FEED_URL "${QUMESH_APPCAST_FEED_URL}")
    set_target_properties(qumesh PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
    )
elseif(WIN32 AND QUMESH_AUTOUPDATE)
    include(FetchContent)
    FetchContent_Declare(
        winsparkle
        URL      https://github.com/vslavik/winsparkle/releases/download/v0.9.2/WinSparkle-0.9.2.zip
        URL_HASH SHA256=2a5facf5a22056edf7afc4d0a4bf05620b7aa7cc1619c3078b281e374cdb9996
    )
    FetchContent_MakeAvailable(winsparkle)

    # The zip lays out per-arch subdirs under WinSparkle-0.9.2/. We
    # build x64 (Qt's win64_msvc2022_64) so pick that variant.
    set(_winsparkle_root "${winsparkle_SOURCE_DIR}")
    set(_winsparkle_dll  "${_winsparkle_root}/x64/Release/WinSparkle.dll")
    set(_winsparkle_lib  "${_winsparkle_root}/x64/Release/WinSparkle.lib")

    add_library(WinSparkle::WinSparkle SHARED IMPORTED)
    set_target_properties(WinSparkle::WinSparkle PROPERTIES
        IMPORTED_LOCATION             "${_winsparkle_dll}"
        IMPORTED_IMPLIB               "${_winsparkle_lib}"
        INTERFACE_INCLUDE_DIRECTORIES "${_winsparkle_root}/include"
    )

    target_sources(qumesh PRIVATE src/updater_win.cpp)
    target_link_libraries(qumesh PRIVATE WinSparkle::WinSparkle)

    # WinSparkle.dll must sit alongside QuMesh.exe at runtime. Copy
    # into the build dir post-build so launch-from-build-tree works,
    # and install it next to the exe so cpack picks it up.
    add_custom_command(TARGET qumesh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_winsparkle_dll}"
            "$<TARGET_FILE_DIR:qumesh>/WinSparkle.dll"
        VERBATIM
    )
    install(FILES "${_winsparkle_dll}" DESTINATION "${_qumesh_win_bindir}")

    # WinSparkle takes its appcast URL + EdDSA public key via C-API
    # calls at startup. Bake both into a generated header so the wiring
    # stays internal to the binary and we avoid MSVC/clang macro-quoting
    # differences that bite you with COMPILE_DEFINITIONS.
    #
    # Sparkle and WinSparkle both use Ed25519 with the same key format
    # (base64 single line, ~44 chars), so one keypair is reused across
    # macOS and Windows — there's only `sparkle_pub_ed_key`, no separate
    # winsparkle file.
    set(_appcast_pub_key_file "${CMAKE_CURRENT_SOURCE_DIR}/sparkle_pub_ed_key")
    if(EXISTS "${_appcast_pub_key_file}")
        file(READ "${_appcast_pub_key_file}" WINSPARKLE_PUBLIC_ED_KEY)
        string(STRIP "${WINSPARKLE_PUBLIC_ED_KEY}" WINSPARKLE_PUBLIC_ED_KEY)
    else()
        set(WINSPARKLE_PUBLIC_ED_KEY "")
    endif()
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/updater_win_config.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/updater_win_config.h"
        @ONLY
    )
    target_include_directories(qumesh PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
elseif(UNIX AND QUMESH_AUTOUPDATE)
    # Linux: appcast-reader-only — apt is the installer, so the
    # backend just parses the same feed Sparkle/WinSparkle consume,
    # compares versions, and emits signals for QML to render
    # LinuxUpdateDialog. The feed URL is baked in as a macro so the
    # same QUMESH_APPCAST_FEED_URL CACHE variable that drives Sparkle
    # also drives this — no duplication.
    target_sources(qumesh PRIVATE src/updater_linux.cpp)
    target_compile_definitions(qumesh PRIVATE
        QUMESH_APPCAST_FEED_URL=\"${QUMESH_APPCAST_FEED_URL}\")
else()
    # Stub implementation; declares Updater as available()==false so QML
    # can `import` it unconditionally and hide its UI.
    target_sources(qumesh PRIVATE src/updater.cpp)
endif()

if(WIN32)
    set(_win_ico "${_branding_dir}/build/qumesh.ico")
    file(TO_NATIVE_PATH "${_win_ico}" _win_ico_native)
    string(REPLACE "\\" "\\\\" _win_ico_native "${_win_ico_native}")
    set(_win_rc "${CMAKE_CURRENT_BINARY_DIR}/qumesh.rc")
    file(WRITE "${_win_rc}"
        "IDI_ICON1 ICON \"${_win_ico_native}\"\n")
    target_sources(qumesh PRIVATE "${_win_rc}")
endif()

# On macOS the output is `QuMesh.app/` (bundle) and on Windows it's
# `QuMesh.exe`, so the extension keeps them off the `QuMesh/` directory
# that `qt_add_qml_module(URI QuMesh …)` drops in the build tree. On
# Linux the executable would be a bare file at the same path — link
# fails with "cannot open output file QuMesh: Is a directory". Just
# lowercasing isn't enough: case-insensitive filesystems (APFS by
# default on macOS, NTFS, exFAT) still treat `qumesh` and `QuMesh/`
# as the same path, so a Linux build staged on one of those would
# regress. `QuMesh-app` is textually distinct under case folding.
if(APPLE OR WIN32)
    set(_qumesh_output_name "QuMesh")
else()
    set(_qumesh_output_name "QuMesh-app")
endif()

set_target_properties(qumesh PROPERTIES
    OUTPUT_NAME "${_qumesh_output_name}"
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_BUNDLE_NAME "QuMesh"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.insynergy.QuMesh"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_ICON_FILE "qumesh.icns"
    WIN32_EXECUTABLE TRUE
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# --- Install / deploy -------------------------------------------------
#
# Install the app + the Qt runtime + OpenSSL into the install prefix.
# CPack at the top level picks this up to produce a .dmg / .exe.

if(APPLE)
    install(TARGETS qumesh BUNDLE DESTINATION .)
elseif(WIN32)
    install(TARGETS qumesh RUNTIME DESTINATION "${_qumesh_win_bindir}")
else()
    install(TARGETS qumesh RUNTIME DESTINATION bin)
endif()

# Bundle openssl + libssh runtime DLLs next to QuMesh.exe on Windows.
# macdeployqt picks these up automatically on macOS once they live in
# the bundle; windeployqt only follows Qt deps, so we have to install
# them by hand. Glob from every CMake prefix that has a `bin/` tree —
# in CI that's the windeps tarball CMAKE_PREFIX_PATH points at; in a
# manual local build it might be a vcpkg install or a hand-rolled
# prefix. Globbing by specific filename rather than `*.dll` keeps us
# from accidentally bundling unrelated Qt/vcpkg DLLs that find their
# way into the search path. legacy.dll is OpenSSL 3's legacy provider
# — loaded at runtime by libcrypto for older algorithms, not a CMake
# target, so it needs the explicit pattern.
if(WIN32)
    set(_windeps_dll_patterns
        "libcrypto-*.dll"
        "libssl-*.dll"
        "legacy.dll"
        "ssh.dll"
    )
    # Build the search list from three sources because none alone is
    # reliable on CI:
    #   1. The CMake variable CMAKE_PREFIX_PATH (set via -D on the
    #      command line, e.g. local builds).
    #   2. $ENV{CMAKE_PREFIX_PATH} — find_package() reads this directly,
    #      but CMake does *not* always promote it to the CMake variable.
    #      Observed in the v1.1.0 release run: find_package(OpenSSL)
    #      resolved fine via the env var, while the foreach below saw
    #      an empty CMake variable and the glob found nothing, so the
    #      packaged QuMesh.exe shipped without libcrypto/libssl/ssh and
    #      failed to load.
    #   3. The directory two levels up from OPENSSL_CRYPTO_LIBRARY,
    #      which find_package(OpenSSL) sets to <prefix>/lib/libcrypto.lib.
    #      Authoritative since it's whatever find_package actually picked.
    set(_search_prefixes ${CMAKE_PREFIX_PATH})
    if(DEFINED ENV{CMAKE_PREFIX_PATH})
        list(APPEND _search_prefixes "$ENV{CMAKE_PREFIX_PATH}")
    endif()
    if(OPENSSL_CRYPTO_LIBRARY)
        get_filename_component(_p "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
        get_filename_component(_p "${_p}" DIRECTORY)
        list(APPEND _search_prefixes "${_p}")
    endif()
    if(_search_prefixes)
        list(REMOVE_DUPLICATES _search_prefixes)
    endif()

    set(_windeps_dlls)
    foreach(_prefix IN LISTS _search_prefixes)
        foreach(_pat IN LISTS _windeps_dll_patterns)
            file(GLOB _matches "${_prefix}/bin/${_pat}")
            list(APPEND _windeps_dlls ${_matches})
        endforeach()
    endforeach()
    if(_windeps_dlls)
        list(REMOVE_DUPLICATES _windeps_dlls)
        install(FILES ${_windeps_dlls} DESTINATION "${_qumesh_win_bindir}")
        # Also copy into the build tree so `cmake --build && QuMesh.exe`
        # finds the DLLs without an `install` first.
        add_custom_command(TARGET qumesh POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${_windeps_dlls}
                "$<TARGET_FILE_DIR:qumesh>/"
            VERBATIM
        )
    else()
        message(WARNING
            "Windows runtime DLLs (libcrypto, libssl, legacy, ssh) not "
            "found under any of: CMAKE_PREFIX_PATH='${CMAKE_PREFIX_PATH}', "
            "ENV{CMAKE_PREFIX_PATH}='$ENV{CMAKE_PREFIX_PATH}', "
            "OPENSSL_CRYPTO_LIBRARY='${OPENSSL_CRYPTO_LIBRARY}'. "
            "The packaged QuMesh.exe will fail to load at startup.")
    endif()
endif()

# Qt 6.5+ helper: produces a per-target deploy script that invokes
# macdeployqt / windeployqt with the right QML scan roots. The deploy
# script runs at install time, so it's already aware of our install
# prefix and bundle layout.
#
# Linux is deliberately excluded: the .deb depends on the distro Qt6
# packages, so the QML engine finds plugins under
# /usr/lib/<triplet>/qt6/qml/ at runtime. NO_UNSUPPORTED_PLATFORM_ERROR
# only suppresses the platform-unsupported diagnostic; the deploy
# script still copies Qt's QML plugin tree into the install staging
# dir, and CPack then tries to ship a 100-plus-MB .deb that overlaps
# the system Qt6 packages — and fails (issue #256).
#
# On Windows the deploy script runs `windeployqt --libdir
# ${QT_DEPLOY_BIN_DIR}` and writes qt.conf into that same directory.
# QT_DEPLOY_BIN_DIR defaults to CMAKE_INSTALL_BINDIR (`bin`), which put
# every Qt DLL in `QuMesh\bin\` while QuMesh.exe sat one level up, so
# the installed app failed to start with "Qt6QuickControls2.dll was not
# found" (#445). Qt's deploy support only fills QT_DEPLOY_BIN_DIR in
# when it's unset, so pre-seeding it in an install(CODE) that runs just
# before the script lands the DLLs and qt.conf next to the exe. plugins/
# and qml/ keep their default spots under the install root.
if(APPLE OR WIN32)
    qt_generate_deploy_qml_app_script(
        TARGET qumesh
        OUTPUT_SCRIPT qumesh_deploy_script
    )
    if(WIN32)
        install(CODE "set(QT_DEPLOY_BIN_DIR \"${_qumesh_win_bindir}\")")
    endif()
    install(SCRIPT ${qumesh_deploy_script})
endif()

# --- Code signing stubs ----------------------------------------------
#
# When CI provisions the relevant secrets, these blocks codesign the
# bundle before CPack assembles it. Without the secrets they are
# no-ops, and the unsigned bundle still produces a runnable
# .dmg / .exe (with the usual Gatekeeper / SmartScreen prompts on
# first launch).
#
# The env-var check has to happen *inside* install(CODE …): the cpack
# step (where MAC_SIGNING_IDENTITY / WIN_SIGN_THUMBPRINT are
# injected) runs after configure, so a configure-time `if()` here
# would always see empty values and skip the signing entirely.

if(APPLE)
    install(CODE "
        if(NOT \"\$ENV{MAC_SIGNING_IDENTITY}\" STREQUAL \"\")
            message(STATUS \"codesign-bundle.sh: signing QuMesh.app with \$ENV{MAC_SIGNING_IDENTITY}\")
            execute_process(
                COMMAND bash
                    \"${CMAKE_CURRENT_SOURCE_DIR}/codesign-bundle.sh\"
                    \"\${CMAKE_INSTALL_PREFIX}/QuMesh.app\"
                    \"\$ENV{MAC_SIGNING_IDENTITY}\"
                    \"${CMAKE_CURRENT_SOURCE_DIR}/QuMesh.entitlements\"
                RESULT_VARIABLE _sign_rc
            )
            if(NOT _sign_rc EQUAL 0)
                message(FATAL_ERROR \"codesign-bundle.sh failed (\${_sign_rc})\")
            endif()
        endif()
    ")
endif()

if(WIN32)
    install(CODE "
        if(NOT \"\$ENV{WIN_SIGN_THUMBPRINT}\" STREQUAL \"\")
            message(STATUS \"signtool: signing QuMesh.exe with thumbprint \$ENV{WIN_SIGN_THUMBPRINT}\")
            execute_process(
                COMMAND signtool sign /sha1 \"\$ENV{WIN_SIGN_THUMBPRINT}\"
                                      /fd SHA256 /tr http://timestamp.digicert.com /td SHA256
                                      \"\${CMAKE_INSTALL_PREFIX}/QuMesh.exe\"
                RESULT_VARIABLE _sign_rc
            )
            if(NOT _sign_rc EQUAL 0)
                message(FATAL_ERROR \"signtool sign failed (\${_sign_rc})\")
            endif()
        endif()
    ")
endif()
