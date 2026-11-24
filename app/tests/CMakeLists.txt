# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

function(qumesh_app_test name)
    qt_add_executable(${name}
        ${name}.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/configstore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/configstore.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/computermodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/computermodel.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/secret_codec.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/secret_codec.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/migrationcontroller.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/migrationcontroller.h
    )
    # Platform-specific KeyStore backend — same conditional as the
    # production target in app/CMakeLists.txt. See #306.
    if(APPLE)
        target_sources(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore_mac.mm)
        set_source_files_properties(
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore_mac.mm
            PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
        find_library(_sec_fw Security REQUIRED)
        find_library(_found_fw Foundation REQUIRED)
        target_link_libraries(${name} PRIVATE ${_sec_fw} ${_found_fw})
    elseif(WIN32)
        target_sources(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore_win.cpp)
        target_link_libraries(${name} PRIVATE crypt32)
    else()
        target_sources(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/keystore_linux.cpp)
    endif()
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(${name} PRIVATE
        Qt6::Core
        Qt6::Network
        Qt6::Qml
        Qt6::Test
        OpenSSL::Crypto
        qumesh_migrate
        qumesh_wsman
    )
    add_test(NAME ${name} COMMAND ${name})
    # Skip the platform keystore in tests — on macOS that means no
    # Keychain prompts; on Windows / Linux it's a no-op since the
    # file fallbacks are unattended already. See #306.
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "QUMESH_NO_KEYSTORE=1")
endfunction()

qt_add_executable(test_smoke test_smoke.cpp)
target_link_libraries(test_smoke PRIVATE Qt6::Core Qt6::Test)
add_test(NAME smoke COMMAND test_smoke)

qumesh_app_test(test_configstore)
qumesh_app_test(test_computermodel)
qumesh_app_test(test_migrationcontroller)
qumesh_app_test(test_secret_codec)
qumesh_app_test(test_backup_codec)
qumesh_app_test(test_backupcontroller)
# test_backup_codec / test_backupcontroller need the new BackupCodec
# (+ BackupController) sources. Compile them straight into the test
# binary because the qumesh_app_test helper builds a per-target exe
# rather than linking against the qumesh_appcore static library.
target_sources(test_backup_codec PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backup_codec.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backup_codec.h)
target_sources(test_backupcontroller PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backup_codec.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backup_codec.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backupcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/backupcontroller.h)
# test_migrationcontroller also seeds a real leveldb fixture.
target_link_libraries(test_migrationcontroller PRIVATE leveldb)

qt_add_executable(test_kvmcontroller
    test_kvmcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmcontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmframebuffer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmframebuffer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.h
)
target_include_directories(test_kvmcontroller PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_kvmcontroller PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Test
    qumesh_kvm
    qumesh_redir
    qumesh_ssh
    qumesh_wsman
)
add_test(NAME test_kvmcontroller COMMAND test_kvmcontroller)

qt_add_executable(test_asciicast_recorder
    test_asciicast_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.h
)
target_include_directories(test_asciicast_recorder PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_asciicast_recorder PRIVATE
    Qt6::Core
    Qt6::Test
)
add_test(NAME test_asciicast_recorder COMMAND test_asciicast_recorder)

qt_add_executable(test_mjpeg_mov_recorder
    test_mjpeg_mov_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.h
)
target_include_directories(test_mjpeg_mov_recorder PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_mjpeg_mov_recorder PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Test
)
add_test(NAME test_mjpeg_mov_recorder COMMAND test_mjpeg_mov_recorder)

qt_add_executable(test_filename_formatter
    test_filename_formatter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/filename_formatter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/filename_formatter.h
)
target_include_directories(test_filename_formatter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_filename_formatter PRIVATE
    Qt6::Core
    Qt6::Test
)
add_test(NAME test_filename_formatter COMMAND test_filename_formatter)

# QML engine smoke test (#251). Loads `Main.qml` headless and asserts
# no warning/critical/fatal QtMsgs land during construction — catches
# the class of runtime QML errors that compile clean and only blow up
# at first launch (e.g. the `Icon.qml` `implicitHeight is a read-only
# property` regression from PR #250). Links `qumesh_appcore` so the
# QML module + every C++ type the production app registers is on hand
# without re-declaring them. Brings its own no-op `Updater` impl
# because `qumesh_appcore` deliberately omits Updater (each consumer
# picks a platform-specific impl); the test wants the stub.
qt_add_executable(test_qml_engine_loads
    test_qml_engine_loads.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.h
)
target_link_libraries(test_qml_engine_loads PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Svg
    Qt6::Test
    qumesh_appcore
    qumesh_appcoreplugin
    qumesh_appcoreplugin_init
)
add_test(NAME test_qml_engine_loads COMMAND test_qml_engine_loads)
# Belt and braces: even though the test sets QT_QPA_PLATFORM via
# qputenv before constructing QGuiApplication, surface the same hint
# through the ctest environment so a runner inspecting `ctest -V`
# output sees the offscreen mode clearly.
set_tests_properties(test_qml_engine_loads PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

# On Windows, run `windeployqt` against a QML test exe in a POST_BUILD
# step so every Qt DLL the test transitively imports — and every Qt
# plugin (qsvg image format, qoffscreen QPA, Qt Quick QML modules) —
# lands next to the .exe. Otherwise the loader can't start the binary
# under `ctest` and the test fails with zero captured output before
# main() even runs (the failure mode that drove #262). The other Qt
# tests in this dir get away with PATH alone because they don't pull
# in the QML stack and its plugins. On macOS/Linux this is a no-op (no
# windeployqt; not needed). See #262.
function(qumesh_deploy_qml_test target)
    if(NOT WIN32)
        return()
    endif()
    get_target_property(_qmake Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(_qt_bin "${_qmake}" DIRECTORY)
    find_program(WINDEPLOYQT_EXE
        NAMES windeployqt windeployqt6
        PATHS "${_qt_bin}"
        NO_DEFAULT_PATH
    )
    if(WINDEPLOYQT_EXE)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND "${WINDEPLOYQT_EXE}"
                --no-translations
                --no-system-d3d-compiler
                --no-opengl-sw
                --qmldir "${CMAKE_CURRENT_SOURCE_DIR}/../qml"
                "$<TARGET_FILE:${target}>"
            COMMENT "Running windeployqt on ${target}.exe"
            VERBATIM
        )
    else()
        message(WARNING
            "windeployqt not found near Qt6::qmake (${_qt_bin}); "
            "${target} will likely fail to load on Windows.")
    endif()
endfunction()
qumesh_deploy_qml_test(test_qml_engine_loads)

# SessionWindow's consent wiring, driven through the real QML module
# against FakeAmt (#459). Same link set as test_qml_engine_loads, for
# the same reasons, plus the controller headers it inspects.
qt_add_executable(test_session_window
    test_session_window.cpp
    fake_amt.h
    session_window_harness.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.h
)
target_include_directories(test_session_window PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_session_window PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Svg
    Qt6::Test
    qumesh_appcore
    qumesh_appcoreplugin
    qumesh_appcoreplugin_init
)
add_test(NAME test_session_window COMMAND test_session_window)
set_tests_properties(test_session_window PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)
qumesh_deploy_qml_test(test_session_window)
# Both QML tests deploy into the same output directory; two windeployqt
# runs at once would race on the same files.
if(WIN32)
    add_dependencies(test_session_window test_qml_engine_loads)
endif()

# The same window over a real SSH tunnel, through an in-process libssh
# server that forwards to FakeAmt (#459). POSIX-only for the reason
# given at test_ssh_tunnel_shutdown in ssh/tests/CMakeLists.txt.
if(NOT WIN32)
    qt_add_executable(test_session_window_ssh
        test_session_window_ssh.cpp
        fake_amt.h
        session_window_harness.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/updater.h
    )
    target_include_directories(test_session_window_ssh PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(test_session_window_ssh PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Network
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
        Qt6::Svg
        Qt6::Test
        qumesh_appcore
        qumesh_appcoreplugin
        qumesh_appcoreplugin_init
        ssh
        OpenSSL::Crypto
    )
    add_test(NAME test_session_window_ssh COMMAND test_session_window_ssh)
    set_tests_properties(test_session_window_ssh PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
endif()

qt_add_executable(test_solcontroller
    test_solcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/solcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/solcontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.h
)
target_include_directories(test_solcontroller PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_solcontroller PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Qt6::Test
    qumesh_redir
    qumesh_ssh
    qumesh_terminal
    qumesh_wsman
)
add_test(NAME test_solcontroller COMMAND test_solcontroller)

# BatchRunner unit test: drives the runner with a stub dispatcher so
# the WSMAN path is out of scope. Lives outside the qumesh_app_test
# helper because it only needs BatchRunner — no ConfigStore / model /
# migration plumbing.
qt_add_executable(test_batchrunner
    test_batchrunner.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/batchrunner.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/batchrunner.h
)
target_include_directories(test_batchrunner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_batchrunner PRIVATE
    Qt6::Core
    Qt6::Test
    qumesh_wsman
)
add_test(NAME test_batchrunner COMMAND test_batchrunner)

# #433 — the user-consent (OptIn) state machine. Drives
# MachineDetailsController against a scripted WSMAN endpoint to pin the
# rule that a *granted* consent (OptInState 3 / RECEIVED) is never
# re-requested, which is what dropped the KVM session mid-handshake.
qt_add_executable(test_optin_statemachine
    test_optin_statemachine.cpp
    fake_amt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/machinedetailscontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/machinedetailscontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.h
)
target_include_directories(test_optin_statemachine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_optin_statemachine PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Test
    qumesh_certs
    qumesh_redir
    qumesh_ssh
    qumesh_wsman
)
add_test(NAME test_optin_statemachine COMMAND test_optin_statemachine)

# #438 — the redaction guard. README promises users their log carries no
# passwords and invites them to paste it publicly; this asserts that
# holds by capturing everything the logging system emits with all
# categories forced on.
qt_add_executable(test_log_redaction
    test_log_redaction.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/machinedetailscontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/machinedetailscontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmcontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmframebuffer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kvmframebuffer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/solcontroller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/solcontroller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mjpeg_mov_recorder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/asciicast_recorder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ssh_tunnel_opener.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sshtunnelhost.h
)
target_include_directories(test_log_redaction PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(test_log_redaction PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Test
    qumesh_certs
    qumesh_kvm
    qumesh_redir
    qumesh_ssh
    qumesh_terminal
    qumesh_wsman
)
add_test(NAME test_log_redaction COMMAND test_log_redaction)
