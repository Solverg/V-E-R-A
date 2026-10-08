import { invoke, isTauri as isTauriRuntime } from "@tauri-apps/api/core";

const demoProcesses = [
  { pid: 1012, name: "explorer.exe", cpu_percent: 1.2, memory_mb: 164.8, status: "running", is_blocked: false, block_mode: "", security_status: "verified", exe: "C:\\Windows\\explorer.exe", description: "Отвечает за рабочий стол, панель задач и окна Проводника Windows.", description_status: "verified" },
  { pid: 9420, name: "chrome.exe", cpu_percent: 4.6, memory_mb: 492.7, status: "running", is_blocked: false, block_mode: "", security_status: "verified", exe: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", description: "Обеспечивает работу вкладок и фоновых компонентов браузера.", description_status: "verified" },
  { pid: 11804, name: "discord.exe", cpu_percent: 0.3, memory_mb: 238.4, status: "sleeping", is_blocked: true, block_mode: "permanent", security_status: "unknown", exe: "C:\\Users\\User\\AppData\\Local\\Discord\\discord.exe" },
];
// The preview also demonstrates the stacked-card treatment used for
// multi-process applications in the Tauri runtime.
demoProcesses.push(
  { ...demoProcesses[1], pid: 9421, cpu_percent: 1.8, memory_mb: 186.2, status: "running", description: "" },
  { ...demoProcesses[1], pid: 9422, cpu_percent: 0.7, memory_mb: 121.5, status: "sleeping", description: "" },
);

const demoProcessNames = ["RuntimeBroker.exe", "SearchHost.exe", "TextInputHost.exe", "ShellExperienceHost.exe", "svchost.exe", "audiodg.exe", "dwm.exe", "ctfmon.exe", "OneDrive.exe", "SecurityHealthSystray.exe", "WidgetService.exe", "PhoneExperienceHost.exe", "msedgewebview2.exe", "conhost.exe", "taskhostw.exe", "sihost.exe", "spoolsv.exe", "WmiPrvSE.exe", "StartMenuExperienceHost.exe", "ApplicationFrameHost.exe", "dllhost.exe", "fontdrvhost.exe", "smartscreen.exe", "SystemSettings.exe", "notepad.exe", "powershell.exe", "OpenConsole.exe"];
demoProcesses.push(...demoProcessNames.map((name, index) => ({
  pid: 13000 + index * 37,
  name,
  cpu_percent: Number(((index * 1.7) % 8).toFixed(1)),
  memory_mb: 24 + (index * 19) % 210,
  status: index % 4 === 0 ? "sleeping" : "running",
  is_blocked: false,
  block_mode: "",
  security_status: index % 6 === 0 ? "unknown" : "verified",
  exe: `C:\\Windows\\System32\\${name}`,
  description: index % 3 === 0 ? "Системный компонент Windows, выполняющий фоновую задачу операционной системы." : "",
  description_status: index % 3 === 0 ? "verified" : "unknown",
})));

// Tauri 2 deliberately exposes this as a public API.  Checking the internal
// bridge is not reliable in release WebViews and can silently select demo data.
const isTauri = () => isTauriRuntime();

async function requestDemo(action, payload = {}) {
  if (action === "health") return { ok: true, data: { service: "demo" } };
  if (action === "processes.list") return { ok: true, data: demoProcesses };
  if (action === "processes.snapshot") return { ok: true, data: { processes: demoProcesses, statistics: { total_processes: demoProcesses.length, active_rules: 1, active_blocked_processes: 1, session_terminated: 0 } } };
  if (action === "processes.verify_signatures") return { ok: true, data: (payload.processes || []).map(({ pid, exe }) => ({ pid, exe, security_status: "verified" })) };
  if (action === "processes.icons") return { ok: true, data: (payload.processes || []).map(({ pid, exe }) => ({ pid, exe, icon: "" })) };
  if (action === "rules.list") return { ok: true, data: [
    ...demoProcesses.filter((item) => item.is_blocked).map((item) => ({ ...item, kill_count: 3, description: "Правило для демонстрации постоянного контроля." })),
    { name: "Updater.exe", exe_path: "C:\\Apps\\Updater.exe", mode: "kill_on_launch", enabled: true, kill_count: 6, description: "Завершается только при запуске V.E.R.A." },
  ] };
  if (action === "processes.statistics") return { ok: true, data: { total_processes: demoProcesses.length, active_rules: 1, active_blocked_processes: 1, session_terminated: 0 } };
  if (action === "network.list") return { ok: true, data: [] };
  if (action === "network.public_ip") return { ok: true, data: { ip: "203.0.113.42", country_code: "GE", country_name: "Грузия", city: "Тбилиси", provider: "V.E.R.A. Preview", asn: "AS64500" } };
  if (action === "startup.list") return { ok: true, data: [
    { name: "OneDrive", source: "HKCU", target_path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", status: "active", raw_key: "OneDrive", needs_admin: false },
    { name: "Game Launcher", source: "FOLDER_USER", target_path: "C:\\Apps\\Game Launcher\\launcher.exe", status: "paused", raw_key: "C:\\Startup\\Game Launcher.lnk.disabled", needs_admin: false },
    { name: "System maintenance", source: "TASK_SCHEDULER", target_path: "C:\\Windows\\System32\\maintenance.exe", status: "active", raw_key: "\\System maintenance", needs_admin: true },
  ] };
  if (action === "settings.get" || action === "settings.set") return { ok: true, data: { provider: "gemini", gemini_model: "gemini-3.1-flash-preview", scan_interval_sec: 5, monitoring_enabled: false, autostart: false, minimize_to_tray: true, show_notifications: true } };
  if (action === "process.describe") return { ok: true, data: { description: "Описание доступно в Tauri-приложении.", status: "unknown" } };
  if (action === "assistant.chat") return { ok: true, data: { text: "AI-доступен в Tauri-приложении после настройки ключа.", model: "preview" } };
  return { ok: true, data: true };
}

export async function backendRequest(action, payload = {}) {
  if (!isTauri()) return requestDemo(action, payload);
  const request = JSON.stringify({ action, ...payload });
  const result = await invoke("backend_request", { request });
  const response = JSON.parse(result);
  if (!response.ok) throw new Error(response.error || "Backend вернул ошибку.");
  return response;
}

export { isTauri };
