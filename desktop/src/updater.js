import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export async function checkForUpdate() {
  const update = await check();
  return update ? { available: true, update } : { available: false };
}

export async function downloadUpdate(update, onProgress) {
  await update.download(onProgress);
}

export async function installDownloadedUpdate(update) {
  try {
    await update.install();
  } finally {
    await update.close().catch(() => undefined);
  }
  await relaunch();
}

export async function installUpdate(update, onProgress) {
  await downloadUpdate(update, onProgress);
  await installDownloadedUpdate(update);
}
