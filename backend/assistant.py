"""Provider calls kept exclusively in the sidecar."""
from __future__ import annotations
import json, urllib.error, urllib.request
from pathlib import Path
from typing import Any
from backend.redaction import redact_secrets

SYSTEM_PROMPT="Ты V.E.R.A. — Verified Executive & Reliability Assistant. Помогай безопасно анализировать процессы Windows. Отвечай кратко на языке пользователя. Не утверждай, что файл безопасен без проверки подписи."

def _request(url:str, body:dict, headers:dict, timeout=30):
    request=urllib.request.Request(url,data=json.dumps(body).encode("utf-8"),headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=timeout) as response:return json.loads(response.read().decode("utf-8"))

def chat(settings, history:list[dict], message:str):
    provider=settings.public().get("provider","gemini")
    if not message.strip():raise ValueError("Введите сообщение.")
    try:
        if provider=="groq":
            key=settings.secret("groq_api_key")
            if not key:raise ValueError("Укажите API-ключ Groq в настройках.")
            messages=[{"role":"system","content":SYSTEM_PROMPT}]+[{"role":"assistant" if x.get("role") in {"model","assistant"} else "user","content":str(x.get("text") or x.get("content") or "")} for x in history]+[{"role":"user","content":message}]
            data=_request("https://api.groq.com/openai/v1/chat/completions",{"model":"llama-3.3-70b-versatile","messages":messages,"temperature":0.7},{"Content-Type":"application/json","Authorization":f"Bearer {key}"})
            text=(((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip(); model="llama-3.3-70b-versatile"
        else:
            key=settings.secret("gemini_api_key")
            if not key:raise ValueError("Укажите Gemini API-ключ в настройках.")
            model=str(settings.public().get("gemini_model") or "gemini-3.1-flash-preview")
            contents=[{"role":"model" if x.get("role") in {"model","assistant"} else "user","parts":[{"text":str(x.get("text") or x.get("content") or "")}]} for x in history]+[{"role":"user","parts":[{"text":message}]}]
            data=_request(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",{"contents":contents,"systemInstruction":{"parts":[{"text":SYSTEM_PROMPT}]},"generationConfig":{"temperature":0.7,"maxOutputTokens":2048}},{"Content-Type":"application/json","x-goog-api-key":key})
            text=((((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [{}])[0].get("text") or "").strip()
        if not text:raise ValueError("Модель вернула пустой ответ.")
        return {"text":text,"model":model}
    except ValueError:raise
    except Exception as exc:raise RuntimeError(redact_secrets("Ошибка обращения к AI-провайдеру.",settings.secret("gemini_api_key"),settings.secret("groq_api_key"))) from exc

def redact_path(value:str)->str:
    import re
    return re.sub(r"(?i)([a-z]:\\users\\)[^\\]+",r"\1<user>",value or "")

def _load_description_cache(cache_path: Path) -> dict[str, Any]:
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        return cache if isinstance(cache, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _description_keys(name: str, exe_path: str) -> list[str]:
    """Read both the Tauri and legacy cache key formats.

    The legacy desktop app keyed records only by the executable name.  Keeping
    that key as a fallback makes its descriptions immediately reusable after
    migration, while the full key avoids collisions for newly saved entries.
    """
    name_key = name.strip().lower()
    path_key = exe_path.strip().lower()
    return ([f"{name_key}|{path_key}"] if path_key else []) + [name_key]


def cached_description(cache_path: Path, name: str, exe_path: str = "") -> dict[str, str] | None:
    cache = _load_description_cache(cache_path)
    for key in _description_keys(name, exe_path):
        value = cache.get(key)
        if isinstance(value, str) and value.strip():
            return {"description": value.strip(), "status": "unknown"}
        if isinstance(value, dict) and str(value.get("description") or "").strip():
            return {
                "description": str(value["description"]).strip(),
                "status": str(value.get("status") or "unknown"),
            }
    return None


def _parse_description_response(text: str) -> dict[str, Any]:
    """Accept JSON inside an occasional Markdown code fence from a provider."""
    payload = text.strip()
    if payload.startswith("```"):
        payload = payload.split("\n", 1)[1] if "\n" in payload else ""
        payload = payload.rsplit("```", 1)[0].strip()
    return json.loads(payload)


def _description_prompt(name: str, exe_path: str, security_status: str) -> str:
    return (
        "Проанализируй процесс Windows.\n"
        f"Имя: '{name}'\n"
        f"Путь: '{redact_path(exe_path) or 'Путь недоступен'}'\n"
        f"Локальная проверка цифровой подписи: {security_status}.\n"
        "Верни короткое описание его назначения. Пиши сразу суть, например: "
        "«Обеспечивает работу звуковой подсистемы». Не повторяй имя файла и "
        "не начинай предложение со слов «это» или «данный процесс»."
    )


def _describe_with_provider(settings, prompt: str) -> str:
    """Make a structured LLM request instead of parsing a chat response.

    Process descriptions are data for the local cache, not a conversation.
    The response format is therefore constrained at the provider boundary.
    """
    schema = {
        "type": "OBJECT",
        "properties": {
            "description": {
                "type": "STRING",
                "description": "Одно короткое описание назначения процесса.",
            },
            "status": {
                "type": "STRING",
                "enum": ["verified", "dangerous", "unknown"],
            },
        },
        "required": ["description", "status"],
    }
    provider = settings.public().get("provider", "gemini")
    if provider == "groq":
        key = settings.secret("groq_api_key")
        if not key:
            raise ValueError("Укажите API-ключ Groq в настройках.")
        data = _request(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
            {"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        return str((((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip())

    key = settings.secret("gemini_api_key")
    if not key:
        raise ValueError("Укажите Gemini API-ключ в настройках.")
    model = str(settings.public().get("gemini_model") or "gemini-3.1-flash-preview")
    data = _request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
                "responseSchema": schema,
            },
        },
        {"Content-Type": "application/json", "x-goog-api-key": key},
    )
    return str(((((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [{}])[0].get("text") or "").strip())


def describe(
    settings,
    cache_path: Path,
    name: str,
    exe_path: str,
    security_status: str,
    force: bool = False,
) -> dict[str, str]:
    """Return a cached LLM description, or request and persist a fresh one."""
    if not name.strip():
        raise ValueError("Не указано имя процесса.")

    if not force:
        cached = cached_description(cache_path, name, exe_path)
        if cached:
            return cached

    try:
        parsed = _parse_description_response(
            _describe_with_provider(settings, _description_prompt(name, exe_path, security_status))
        )
        description = str(parsed.get("description") or "").strip()
        if not description:
            raise ValueError("Модель не вернула описание.")
        status = str(parsed.get("status") or "unknown").lower()
        result = {
            "description": description,
            "status": status if status in {"verified", "dangerous", "unknown"} else "unknown",
        }
    except Exception:
        result = {
            "description": "Не удалось получить AI-описание. Проверьте файл и его источник вручную.",
            "status": "unknown",
        }

    cache = _load_description_cache(cache_path)
    keys = _description_keys(name, exe_path)
    # Also update the legacy name key so descriptions remain useful if a
    # process moves between directories or is read by an older app version.
    cache[keys[-1]] = result
    if len(keys) > 1:
        cache[keys[0]] = result
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
