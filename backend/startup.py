"""Safe Windows Startup inventory and pause/resume implementation."""
from __future__ import annotations
import ctypes, os, subprocess, sys, xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
try: import winreg
except ModuleNotFoundError: winreg=None

@dataclass
class StartupItem:
    name:str; target_path:str; source:str; status:str; raw_key:str; needs_admin:bool=False; backup_key:str=""

class StartupManager:
    RUN_KEY=r"Software\Microsoft\Windows\CurrentVersion\Run"; BACKUP=r"Software\V.E.R.A.\PausedStartup"; LEGACY_BACKUP=r"Software\KristinaHelper\PausedStartup"; SELF={"V.E.R.A.","VERA","Vera"}
    @staticmethod
    def is_admin():
        try:return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:return False
    @classmethod
    def _registry(cls,hive,source):
        if not winreg:return []
        out=[]
        needs_admin=source=="HKLM" and not cls.is_admin()
        for key_path,status in ((cls.RUN_KEY,"active"),(cls.BACKUP,"paused"),(cls.LEGACY_BACKUP,"paused")):
            try:
                with winreg.OpenKey(hive,key_path,0,winreg.KEY_READ) as key:
                    index=0
                    while True:
                        try:
                            name,target,_=winreg.EnumValue(key,index); index+=1
                            if name not in cls.SELF and isinstance(target,str):out.append(StartupItem(name,target,source,status,name,needs_admin,key_path if status=="paused" else ""))
                        except OSError:break
            except OSError:pass
        return out
    @classmethod
    def _folder(cls,path,source):
        out=[]
        try:names=os.listdir(path)
        except OSError:return out
        for name in names:
            lower=name.lower(); full=os.path.join(path,name)
            needs_admin=source=="FOLDER_SYSTEM" and not cls.is_admin()
            if lower.endswith(".lnk"):out.append(StartupItem(name[:-4],cls._resolve_shortcut(full) or full,source,"active",full,needs_admin))
            elif lower.endswith(".lnk.disabled"):out.append(StartupItem(name[:-13],full,source,"paused",full,needs_admin))
        return out
    @staticmethod
    def _resolve_shortcut(shortcut):
        """Show the executable behind an active shortcut, as the legacy UI did."""
        try:
            escaped=str(shortcut).replace("'","''")
            script=f"$shell=New-Object -ComObject WScript.Shell; $link=$shell.CreateShortcut('{escaped}'); [Console]::Out.Write($link.TargetPath)"
            result=subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",script],capture_output=True,text=True,timeout=3,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            return result.stdout.strip() or ""
        except (OSError,subprocess.TimeoutExpired):return ""
    @classmethod
    def parse_schtasks_xml(cls, xml:str):
        try:root=ET.fromstring(f"<root>{xml}</root>")
        except ET.ParseError:return []
        ns={"t":"http://schemas.microsoft.com/windows/2004/02/mit/task"}; out=[]; needs_admin=not cls.is_admin()
        for task in root.findall(".//t:Task",ns):
            if task.find(".//t:LogonTrigger",ns) is None:continue
            uri=(task.findtext(".//t:RegistrationInfo/t:URI",default="",namespaces=ns) or "").strip(); command=(task.findtext(".//t:Actions/t:Exec/t:Command",default="",namespaces=ns) or "").strip()
            if not command:continue
            name=uri.rsplit("\\",1)[-1] or "Unknown Task"
            if name in cls.SELF:continue
            enabled=(task.findtext(".//t:Settings/t:Enabled",default="false",namespaces=ns) or "").lower()=="true"
            out.append(StartupItem(name,command,"TASK_SCHEDULER","active" if enabled else "paused",uri or name,needs_admin))
        return out
    @classmethod
    def list(cls):
        user=os.path.join(os.environ.get("APPDATA",""),r"Microsoft\Windows\Start Menu\Programs\Startup"); system=os.path.join(os.environ.get("PROGRAMDATA",""),r"Microsoft\Windows\Start Menu\Programs\Startup")
        items=cls._registry(getattr(winreg,"HKEY_CURRENT_USER",None),"HKCU") if winreg else []
        if winreg:items+=cls._registry(winreg.HKEY_LOCAL_MACHINE,"HKLM")
        items+=cls._folder(user,"FOLDER_USER")+cls._folder(system,"FOLDER_SYSTEM")
        try:
            result=subprocess.run(["schtasks","/query","/fo","XML","/v"],capture_output=True,text=True,timeout=15,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            if result.returncode==0:items+=cls.parse_schtasks_xml(result.stdout)
        except (OSError,subprocess.TimeoutExpired):pass
        return [asdict(x) for x in sorted(items,key=lambda x:(x.name.lower(),x.source,x.status))]
    @classmethod
    def toggle(cls,item:dict):
        source=str(item.get("source") or ""); status=str(item.get("status") or ""); raw=str(item.get("raw_key") or "")
        if source not in {"HKCU","HKLM","FOLDER_USER","FOLDER_SYSTEM","TASK_SCHEDULER"} or not raw:raise ValueError("Некорректная запись автозапуска.")
        if (source in {"HKLM","FOLDER_SYSTEM","TASK_SCHEDULER"}) and not cls.is_admin():raise PermissionError("Access Denied: для системной записи требуются права администратора.")
        if source=="TASK_SCHEDULER":
            result=subprocess.run(["schtasks","/change","/tn",raw,"/DISABLE" if status=="active" else "/ENABLE"],capture_output=True,text=True,timeout=10,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            if result.returncode:return_error=result.stderr.strip() or "Не удалось изменить задачу"; raise ValueError(return_error)
            return {"status":"paused" if status=="active" else "active"}
        if source.startswith("FOLDER"):
            target=raw+".disabled" if status=="active" else raw.removesuffix(".disabled")
            if not os.path.isfile(raw):raise ValueError("Ярлык изменился или уже удалён.")
            os.rename(raw,target);return {"status":"paused" if status=="active" else "active"}
        if not winreg:raise ValueError("Реестр Windows недоступен.")
        hive=winreg.HKEY_LOCAL_MACHINE if source=="HKLM" else winreg.HKEY_CURRENT_USER
        if status=="active":
            with winreg.OpenKey(hive,cls.RUN_KEY,0,winreg.KEY_READ) as key:value,_=winreg.QueryValueEx(key,raw)
            with winreg.CreateKey(hive,cls.BACKUP) as key:winreg.SetValueEx(key,raw,0,winreg.REG_SZ,value)
            with winreg.OpenKey(hive,cls.RUN_KEY,0,winreg.KEY_SET_VALUE) as key:winreg.DeleteValue(key,raw)
        else:
            backup_key=str(item.get("backup_key") or cls.BACKUP)
            with winreg.OpenKey(hive,backup_key,0,winreg.KEY_READ) as key:value,_=winreg.QueryValueEx(key,raw)
            with winreg.OpenKey(hive,cls.RUN_KEY,0,winreg.KEY_SET_VALUE) as key:winreg.SetValueEx(key,raw,0,winreg.REG_SZ,value)
            with winreg.OpenKey(hive,backup_key,0,winreg.KEY_SET_VALUE) as key:winreg.DeleteValue(key,raw)
        return {"status":"paused" if status=="active" else "active"}
    @classmethod
    def app_autostart(cls, enabled=None, command=""):
        if not winreg:return False
        name="V.E.R.A."
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,cls.RUN_KEY) as key:
            if enabled is None:
                try:winreg.QueryValueEx(key,name);return True
                except FileNotFoundError:return False
            if enabled:
                command = command or os.environ.get("VERA_APP_EXE", "")
                if not command:
                    raise ValueError("Не удалось определить путь V.E.R.A. для автозапуска.")
                winreg.SetValueEx(key,name,0,winreg.REG_SZ,f'"{command}"')
            else:
                try:winreg.DeleteValue(key,name)
                except FileNotFoundError:pass
        return bool(enabled)
