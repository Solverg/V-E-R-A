use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::Duration,
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};

const SIDECAR_DIRECTORY: &str = "binaries/vera-backend-x86_64-pc-windows-msvc";
const SIDECAR_EXECUTABLE: &str = "vera-backend-x86_64-pc-windows-msvc.exe";

fn sidecar_path(app: &AppHandle) -> Result<PathBuf, String> {
    let packaged_path = app
        .path()
        .resource_dir()
        .map_err(|error| format!("Не удалось найти ресурсы приложения: {error}"))?
        .join(SIDECAR_DIRECTORY)
        .join(SIDECAR_EXECUTABLE);

    if packaged_path.is_file() {
        return Ok(packaged_path);
    }

    // `tauri build` also produces an unbundled executable used during local
    // verification.  In that case resources still live in src-tauri.
    let development_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(SIDECAR_DIRECTORY)
        .join(SIDECAR_EXECUTABLE);
    if development_path.is_file() {
        return Ok(development_path);
    }

    Err(format!(
        "Не найден sidecar backend: {}",
        packaged_path.display()
    ))
}

#[derive(Default)]
struct MonitorState { enabled: AtomicBool, interval: AtomicU64 }

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn backend_request_impl(app: &AppHandle, request: &str) -> Result<String, String> {
    let executable = sidecar_path(app)?;
    let app_executable = std::env::current_exe().ok();
    let mut command = Command::new(executable);
    command.args(["--request", request]);
    // The sidecar communicates through redirected standard streams, so it
    // does not need a visible console window when V.E.R.A. is launched from
    // Explorer or the Start menu.
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    if let Some(path) = app_executable { command.env("VERA_APP_EXE", path); }
    let output = command.output()
        .map_err(|error| format!("Не удалось запустить sidecar: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !output.status.success() {
        let details = if stderr.is_empty() { "без диагностического сообщения" } else { &stderr };
        return Err(format!("Sidecar завершился с ошибкой {}: {details}", output.status));
    }
    if output.stdout.is_empty() {
        let details = if stderr.is_empty() { "без диагностического сообщения" } else { &stderr };
        return Err(format!("Sidecar не вернул ответ: {details}"));
    }
    String::from_utf8(output.stdout).map_err(|_| "Sidecar вернул ответ не в UTF-8.".into())
}

#[tauri::command]
fn backend_request(app: AppHandle, request: String) -> Result<String, String> {
    backend_request_impl(&app, &request)
}

#[tauri::command]
fn monitor_configure(state: State<MonitorState>, enabled: bool, interval_seconds: u64) -> Result<(), String> {
    if !(1..=60).contains(&interval_seconds) { return Err("Интервал мониторинга должен быть от 1 до 60 секунд.".into()); }
    state.interval.store(interval_seconds, Ordering::Release); state.enabled.store(enabled, Ordering::Release); Ok(())
}

#[tauri::command]
fn open_process_location(path: String) -> Result<(), String> {
    let candidate = PathBuf::from(path);
    if !candidate.is_file() { return Err("Файл процесса больше не существует или путь недоступен.".into()); }
    let canonical = candidate.canonicalize().map_err(|_| "Не удалось проверить путь процесса.")?;
    Command::new("explorer.exe").arg(format!("/select,{}", canonical.display())).spawn().map_err(|_| "Не удалось открыть Проводник.")?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(MonitorState { enabled: AtomicBool::new(false), interval: AtomicU64::new(5) })
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Открыть V.E.R.A.", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let tray_icon = app.default_window_icon().cloned().ok_or_else(|| {
                std::io::Error::other("иконка приложения недоступна для системного трея")
            })?;
            let handle = app.handle().clone();
            let tray = TrayIconBuilder::with_id("vera-tray")
                .icon(tray_icon)
                .tooltip("V.E.R.A.")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            // Tauri removes a tray icon when its handle is dropped. Keep it in
            // application state so closing the main window can reliably hide
            // V.E.R.A. to the notification area instead of ending the app.
            app.manage(tray);
            thread::spawn(move || { let mut first = true; loop { thread::sleep(Duration::from_secs(1)); let state = handle.state::<MonitorState>(); if !state.enabled.load(Ordering::Acquire) { first = true; continue; } let interval = state.interval.load(Ordering::Acquire).max(1); static TICK: AtomicU64 = AtomicU64::new(0); let tick=TICK.fetch_add(1, Ordering::Relaxed)+1; if tick % interval == 0 { let body = if first { r#"{\"action\":\"processes.enforce\",\"launch_cycle\":true}"# } else { r#"{\"action\":\"processes.enforce\",\"launch_cycle\":false}"# }; let _ = backend_request_impl(&handle, body); first=false; } } });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![backend_request, monitor_configure, open_process_location])
        .run(tauri::generate_context!())
        .expect("failed to run V.E.R.A. desktop shell");
}
