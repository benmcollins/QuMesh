# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

cmake_minimum_required(VERSION 3.21)

project(QuMesh
    VERSION 1.4.2
    DESCRIPTION "QuMesh — native Qt6/QML console for Intel AMT (vPro) devices"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Qt6 6.6 REQUIRED COMPONENTS Core Gui Quick QuickControls2 Network Svg Test LinguistTools)
find_package(Qt6 6.6 OPTIONAL_COMPONENTS HttpServer)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# libssh — required for the per-machine SSH tunnel feature. On macOS we
# pick up Homebrew's keg; on Windows the release workflow vendors a
# prebuilt set of headers + libssh.dll alongside Qt/OpenSSL. Pinning
# REQUIRED here keeps the dep visible: if a developer is missing libssh
# the configure step fails loudly with the install command.
find_package(libssh CONFIG REQUIRED)

qt_standard_project_setup(REQUIRES 6.6)
qt_policy(SET QTP0004 NEW)

# leveldb (read-only access to the legacy NW.js Chromium DOMStorage)
include(FetchContent)
set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LEVELDB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    leveldb
    GIT_REPOSITORY https://github.com/google/leveldb.git
    GIT_TAG       1.23
    GIT_SHALLOW   TRUE
)
FetchContent_MakeAvailable(leveldb)

include(CTest)

# --- License: render Markdown → RTF for the install dialogs ----------
#
# Both the macOS DMG license-acceptance pane (driven by hdiutil) and
# NSIS's `MUI_PAGE_LICENSE` accept RTF or plain text — not Markdown.
# Passing LICENSE.md verbatim left users staring at raw `#`, `**`, `_`
# punctuation. `branding/build-license.py` is a stdlib-only converter
# that lays the file out with proper headings, paragraphs, and bullets;
# the same RTF then gets bundled into the app and dropped at the .dmg
# root so users can re-open it from either place and see it rendered.
#
# Generated up here, before `add_subdirectory(app)`, because the app
# target's POST_BUILD copy step needs to see QUMESH_LICENSE_RTF set
# in its parent scope. The CPack file-existence check (later, in the
# packaging block) wants it on disk at configure time too, so we
# render eagerly with execute_process() and back it with a build-time
# add_custom_command() that keeps it in sync if LICENSE.md changes.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(QUMESH_LICENSE_RTF "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.rtf")
set(_license_script "${CMAKE_CURRENT_SOURCE_DIR}/branding/build-license.py")
set(_license_md     "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md")

execute_process(
    COMMAND ${Python3_EXECUTABLE} "${_license_script}"
            "${_license_md}" "${QUMESH_LICENSE_RTF}"
    RESULT_VARIABLE _license_rc
    OUTPUT_VARIABLE _license_out
    ERROR_VARIABLE  _license_err
)
if(NOT _license_rc EQUAL 0)
    message(FATAL_ERROR
        "branding/build-license.py failed (rc=${_license_rc}):\n${_license_err}")
endif()

add_custom_command(
    OUTPUT "${QUMESH_LICENSE_RTF}"
    COMMAND ${Python3_EXECUTABLE} "${_license_script}"
            "${_license_md}" "${QUMESH_LICENSE_RTF}"
    DEPENDS "${_license_script}" "${_license_md}"
    COMMENT "Rendering LICENSE.md → LICENSE.rtf"
    VERBATIM
)
add_custom_target(qumesh_license_rtf ALL DEPENDS "${QUMESH_LICENSE_RTF}")

add_subdirectory(terminal)
add_subdirectory(certs)
add_subdirectory(ssh)
add_subdirectory(app)
add_subdirectory(migrate)
add_subdirectory(wsman)
add_subdirectory(rmcp)
add_subdirectory(redir)
add_subdirectory(ider)
add_subdirectory(kvm)

# --- Packaging ---------------------------------------------------------
#
# `cpack` produces a .dmg on macOS (CPack DragNDrop) and an NSIS-based
# .exe installer on Windows. Both bundle Qt + plugins (via macdeployqt /
# windeployqt) plus OpenSSL.
#
# Cut a release: bump PROJECT_VERSION above, push a `vX.Y.Z` tag, and
# the GitHub Actions release workflow handles the rest.

set(CPACK_PACKAGE_NAME "QuMesh")
set(CPACK_PACKAGE_VENDOR "Insynergy")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/benmcollins/QuMesh")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Native Qt6 console for Intel AMT (vPro) devices")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "QuMesh")
set(CPACK_VERBATIM_VARIABLES TRUE)
set(CPACK_STRIP_FILES TRUE)

set(CPACK_RESOURCE_FILE_LICENSE "${QUMESH_LICENSE_RTF}")

# Drop LICENSE.rtf at the install-prefix root. On macOS that lands it
# at the .dmg root next to QuMesh.app; on Windows it sits beside
# QuMesh.exe in `%ProgramFiles%\QuMesh\`. The app/CMakeLists.txt block
# additionally copies it into QuMesh.app/Contents/Resources/. On
# Linux this would land at /usr/LICENSE.rtf — skip there; the .deb
# install rule below puts LICENSE.md at /usr/share/doc/qumesh/copyright
# instead, which is what Debian policy expects.
if(APPLE OR WIN32)
    install(FILES "${QUMESH_LICENSE_RTF}" DESTINATION .)
endif()

# Note: CMake's CPack DragNDrop generator auto-creates the
# `Applications` symlink in the .dmg root (opt out with
# CPACK_DMG_DISABLE_APPLICATIONS_SYMLINK). We rely on that — see
# app/dmg-setup.applescript.in, which references item "Applications".

if(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_VOLUME_NAME "QuMesh-${PROJECT_VERSION}")
    set(CPACK_PACKAGE_FILE_NAME "QuMesh-${PROJECT_VERSION}-macos")

    # --- DMG mount-window polish -----------------------------------
    #
    # Three pieces work together: a background image that CPack
    # copies to `.background/background.tiff` inside the DMG, a
    # volume-icon ICNS dropped at the DMG root as `.VolumeIcon.icns`,
    # and an AppleScript that Finder runs once to size the window,
    # position the icons, bind the background picture, and flip the
    # HasCustomIcon Finder flag so the volume icon is picked up.
    # The AppleScript references the volume name, so it's templated
    # through configure_file() rather than passed verbatim.
    set(CPACK_DMG_BACKGROUND_IMAGE
        "${CMAKE_CURRENT_SOURCE_DIR}/branding/build/dmg-background.tiff")

    # `.VolumeIcon.icns` is the dotted filename Finder looks for at the
    # root of a mounted volume; combined with the HasCustomIcon flag
    # (set by the AppleScript via SetFile -a C) it themes both the
    # title bar of the mount window and the sidebar entry. We can't
    # ship it through CPack's normal install tree — the DragNDrop
    # generator's internal staging→DMG copy quietly drops dotfiles
    # other than `.background/` and `.DS_Store` — so the AppleScript
    # copies the icns onto the mounted volume itself with a path baked
    # in here via configure_file(). The set() must come *before*
    # configure_file so the @QUMESH_VOLUME_ICON_SOURCE@ placeholder is
    # not substituted with an empty string.
    set(QUMESH_VOLUME_ICON_SOURCE
        "${CMAKE_CURRENT_SOURCE_DIR}/branding/build/qumesh-dmg.icns")

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/app/dmg-setup.applescript.in"
        "${CMAKE_CURRENT_BINARY_DIR}/dmg-setup.applescript"
        @ONLY
    )
    set(CPACK_DMG_DS_STORE_SETUP_SCRIPT
        "${CMAKE_CURRENT_BINARY_DIR}/dmg-setup.applescript")
elseif(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "QuMesh")
    set(CPACK_NSIS_PACKAGE_NAME "QuMesh")
    set(CPACK_NSIS_HELP_LINK "https://github.com/benmcollins/QuMesh")
    set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/benmcollins/QuMesh")
    set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_MODIFY_PATH OFF)
    set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "QuMesh-${PROJECT_VERSION}")
    set(CPACK_PACKAGE_FILE_NAME "QuMesh-${PROJECT_VERSION}-windows-x64")
elseif(UNIX)
    # --- .deb for Debian/Ubuntu --------------------------------------
    #
    # CPack's DEB generator turns our `install()` rules into a real
    # .deb that apt accepts. The release workflow builds one .deb per
    # target distro (ubuntu:26.04, debian:13) inside a container and
    # attaches them to the GitHub Release; .github/workflows/
    # release-apt.yml then publishes both into a signed APT repo on
    # gh-pages. See PACKAGING.md for the maintainer-side GPG setup.
    set(CPACK_GENERATOR "DEB")

    # Lowercase Debian package name. The QuMesh-app binary name is
    # internal; the package the user installs is `qumesh`.
    set(CPACK_DEBIAN_PACKAGE_NAME "qumesh")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ben Collins <ben@ironrocketsmc.org>")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")

    # Let dpkg-shlibdeps figure out the dynamic-linker deps (Qt6,
    # libssh, libssl, libstdc++…). Keeping this auto-detected means
    # the same CMakeLists drops compatible deps for both Ubuntu 26.04
    # and Debian 13 without us hard-coding minor versions.
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

    # Conventional file name (qumesh_X.Y.Z_amd64.deb) — release.yml
    # appends the distro suffix when uploading so both can coexist
    # as release assets.
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

    # --- Linux install layout -------------------------------------
    #
    # We already install the binary to bin/ over in app/CMakeLists.txt.
    # Stage the rest of the Freedesktop layout here so it ships in
    # the .deb and works just as well for `make install` on a system
    # that builds from source.

    # /usr/bin/qumesh → QuMesh-app  (typing `qumesh` in a shell is
    # convention; the .desktop file still launches QuMesh-app).
    #
    # `install(CODE …)` does NOT auto-apply DESTDIR the way
    # `install(FILES …)` does — the standard install rules prepend
    # it internally, but user code has to do it manually. Without
    # the `$ENV{DESTDIR}` prefix, the script would try to write
    # the literal `/usr/bin/qumesh` (requiring root, also outside
    # CPack's staging tree). The path expression matches the
    # canonical CMake DESTDIR-aware pattern.
    install(CODE [[
        file(CREATE_LINK QuMesh-app
            "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/qumesh"
            SYMBOLIC)
    ]])

    install(FILES app/qumesh.desktop
        DESTINATION share/applications)

    install(FILES app/qumesh.metainfo.xml
        DESTINATION share/metainfo)

    # Hicolor theme icons. The build-icons.py script already renders
    # the mark at each standard size; install those into the theme
    # paths the apps menu reads.
    foreach(_size IN ITEMS 16 24 32 48 64 96 128 256 512)
        install(FILES "branding/build/png/qumesh-mark-${_size}.png"
            DESTINATION "share/icons/hicolor/${_size}x${_size}/apps"
            RENAME "qumesh.png")
    endforeach()

    # License under /usr/share/doc/qumesh/ — required by Debian policy
    # for the copyright file. Plain Markdown is fine; lintian doesn't
    # complain because it's just a "copyright file should exist" check.
    install(FILES LICENSE.md
        DESTINATION share/doc/qumesh
        RENAME copyright)
endif()

include(CPack)
