#!/usr/bin/env python3
"""Deploy hosted/index.html to Vercel project 'openbeam-online' via the
connected Vercel MCP wrapper (/opt/hatch/bin/vercel). No secrets in this
file — auth lives in the connector. REST-token flow is dead (403), so this
uses call-tool: get_project -> create_project -> upload_file ->
create_deployment -> poll get_deployment.
"""
import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

TEAM = "team_sU974w8hxEV5WofgWiQu4CQy"
PROJECT = "openbeam-online"
HERE = Path(__file__).resolve().parent
FILES = ["index.html", "peerjs.min.js", "package.json",
         "api/blob-upload.js", "api/register.js", "api/resolve.js"]


def call(tool, args):
    p = subprocess.run(
        ["/opt/hatch/bin/vercel", "call-tool", "--name", tool,
         "--arguments-json", json.dumps(args)],
        capture_output=True, text=True, timeout=300,
    )
    out = p.stdout.strip()
    try:
        d = json.loads(out)
    except Exception:
        return {"_raw": out, "_stderr": p.stderr[-500:]}
    # unwrap MCP content envelope
    try:
        inner = d["result"]["content"][0]["text"]
        return json.loads(inner)
    except Exception:
        return d


def dig(d, *keys):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
    return d


def main():
    proj = call("get_project", {"idOrName": PROJECT})
    pid = dig(proj, "result", "id") or dig(proj, "id")
    if not pid:
        print("project not found, creating…")
        proj = call("create_project", {
            "requestBody": {"name": PROJECT, "framework": None},
        })
        pid = dig(proj, "result", "id") or dig(proj, "id")
        if not pid:
            print("create_project response:", json.dumps(proj)[:800])
            sys.exit("could not create project")
    print("project id:", pid)

    refs = []
    for name in FILES:
        data = (HERE / name).read_bytes()
        sha = hashlib.sha1(data).hexdigest()
        up = call("upload_file", {
            "xVercelDigest": sha,
            "contentLength": len(data),
            "requestBody": base64.b64encode(data).decode(),
        })
        print("uploaded", name, sha[:10], "->", json.dumps(up)[:200])
        refs.append({"file": name, "sha": sha, "size": len(data)})

    dep = call("create_deployment", {
        "forceNew": "1",
        "requestBody": {
            "name": PROJECT,
            "files": refs,
            "target": "production",
            "projectSettings": {"framework": None},
        },
    })
    dep_id = (dig(dep, "result", "deployment", "id") or dig(dep, "result", "id")
              or dig(dep, "id"))
    dep_url = (dig(dep, "result", "deployment", "url") or dig(dep, "result", "url")
               or dig(dep, "url"))
    if not dep_id:
        print("create_deployment response:", json.dumps(dep)[:1200])
        sys.exit("deployment failed to start")
    print("deployment:", dep_id, dep_url)

    for _ in range(36):
        time.sleep(5)
        d = call("get_deployment", {"idOrUrl": dep_id})
        state = (dig(d, "result", "deployment", "readyState")
                 or dig(d, "result", "readyState") or dig(d, "readyState"))
        url = (dig(d, "result", "deployment", "url") or dig(d, "result", "url")
               or dig(d, "url") or dep_url)
        print("state:", state, url)
        if state in ("READY",):
            print("DEPLOYED_URL=https://" + url)
            return
        if state in ("ERROR", "CANCELED"):
            print("deployment events tail:")
            ev = call("list_deployment_events",
                      {"id": dep_id})
            print(json.dumps(ev)[:2000])
            sys.exit("deployment errored")
    sys.exit("timed out waiting for deployment")


if __name__ == "__main__":
    main()
