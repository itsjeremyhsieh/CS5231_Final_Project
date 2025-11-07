import os

try:
    from openai import OpenAI
    import base64
except Exception as e:
    OpenAI = None
    base64 = None


def call_openai_for_summary(graph_paths, terminal_output, model="gpt-4o-mini"):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set.")
    if OpenAI is None:
        raise RuntimeError("openai package not available")

    client = OpenAI(api_key=api_key)

    attachments = []
    for p in graph_paths:
        try:
            with open(p, "rb") as f:
                data = f.read()
            size = len(data)
            b64 = base64.b64encode(data).decode("utf-8") if base64 else None
            include_full = size <= 200_000
            attachments.append({"filename": os.path.basename(p), "size": size, "included": include_full, "b64": b64 if include_full else None})
        except Exception as e:
            attachments.append({"filename": os.path.basename(p), "size": 0, "error": str(e)})

    att_lines = []
    for a in attachments:
        if a.get("error"):
            att_lines.append(f"{a['filename']}: error reading ({a['error']})")
        elif a.get("included"):
            att_lines.append(f"{a['filename']}: included as base64 (size {a['size']} bytes)")
        else:
            att_lines.append(f"{a['filename']}: not embedded (size {a['size']} bytes)")

    try:
        lines = terminal_output.splitlines()
    except Exception:
        lines = [str(terminal_output)]
    tail_lines = lines[-80:]
    terminal_short = "\n".join(tail_lines)
    if len(terminal_short) > 4000:
        terminal_short = terminal_short[-4000:]

    user_msg = (
        "You are a helpful assistant experienced in IT security.\n"
        "I will provide a short excerpt of the pipeline output and a set of provenance graph images (filenames listed).\n"
        "Using that information, produce a concise paragraph (3-5 sentences) directed to IT security personnel that summarizes the findings, the level of concern, and immediate recommended next steps.\n\n"
        f"Pipeline output (excerpt, last lines):\n{terminal_short}\n\n"
        "Graph attachments summary:\n"
        + "\n".join(att_lines)
        + "\n\n"
        "Do not invent facts beyond what's shown. Be actionable and concise."
    )

    embed_images = os.getenv("OPENAI_EMBED_IMAGES", "false").lower() in ("1", "true", "yes")
    if embed_images and any(a.get("b64") for a in attachments):
        user_msg += "\nAttached images (base64):\n"
        for a in attachments:
            if a.get("b64"):
                user_msg += f"---BEGIN {a['filename']}---\n{a['b64']}\n---END {a['filename']}---\n"

    messages = [
        {"role": "system", "content": "You are concise and professional. Produce a paragraph for IT security operations staff."},
        {"role": "user", "content": user_msg},
    ]

    resp = client.chat.completions.create(model=model, messages=messages)

    content = None
    try:
        content = resp.choices[0].message.content
    except Exception:
        try:
            content = resp["choices"][0]["message"]["content"]
        except Exception:
            content = str(resp)
    return content.strip() if content else ""
