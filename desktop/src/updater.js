import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export async function checkForUpdate() {
  const update = await check();
  return update ? { available: true, update } : { available: false };
}

export async function installUpdate(update, onProgress) {
  try {
    await update.downloadAndInstall(onProgress);
  } finally {
    await update.close().catch(() => undefined);
  }
  await relaunch();
}
