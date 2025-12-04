#Python based directory buster tool.
import asyncio
import httpx
import random
import sys
import argparse
from types import SimpleNamespace
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/8.0.1",
    "Wget/1.21.4"
]

HTTP_NAMES = {
    200: "OK",
    301: "MOVED",
    302: "FOUND",
    307: "REDIRECT",
    308: "REDIRECT",
    401: "UNAUTH",
    403: "FORBIDDEN",
    404: "NOTFOUND",
    500: "ERROR"
}

def status_box(status):
    name = HTTP_NAMES.get(status, "")
    box = f"{status} {name}".ljust(12)
    if status == 200:
        return Fore.GREEN + box + Style.RESET_ALL
    if status in (301, 302, 307, 308):
        return Fore.YELLOW + box + Style.RESET_ALL
    if status in (401, 403, 404):
        return Fore.RED + box + Style.RESET_ALL
    if status >= 500:
        return Fore.MAGENTA + box + Style.RESET_ALL
    return Fore.CYAN + box + Style.RESET_ALL

def build_url(base, path):
    return base.rstrip("/") + "/" + path.strip("/")

def parse_extensions(ext_string):
    if not ext_string:
        return []
    parts = [e.strip() for e in ext_string.split(",") if e.strip()]
    return parts

def load_wordlist(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)

async def http_get(client, url, timeout, delay):
    try:
        r = await client.get(url, follow_redirects=False, timeout=timeout)
        if delay > 0:
            await asyncio.sleep(delay)
        return r
    except Exception:
        return None

async def worker(client, queue, results, cfg, prog_state):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        url, path = item
        prog_state.current_path = path

        resp = await http_get(client, url, cfg.timeout, cfg.delay)
        if resp is not None:
            status = resp.status_code
            size = len(resp.content or b"")

            if cfg.show_status and status not in cfg.show_status:
                pass
            elif cfg.hide_status and status in cfg.hide_status:
                pass
            else:
                sb = status_box(status)
                p = f"/{path}".ljust(24)
                sz = f"Size: {size}".ljust(12)

                if status == 200:
                    line = f"{p} [{sb}]  {sz} → {url}"
                else:
                    line = f"{p} [{sb}]  {sz}"

                sys.stdout.write("\n" + line + "\n")
                sys.stdout.flush()

                results.append((url, path, status, size))

                try:
                    with open(f"status_{status}.txt", "a") as f:
                        f.write(f"{url} {size}\n")
                except Exception:
                    pass

        prog_state.done += 1
        queue.task_done()

async def progress_printer(prog_state, cfg):
    if cfg.no_progress:
        return
    while not prog_state.stop:
        if prog_state.total > 0:
            pct = (prog_state.done / prog_state.total) * 100
        else:
            pct = 100.0
        current = prog_state.current_path or ""
        current_short = current[:40]
        sys.stdout.write(f"\rProgress: {pct:.2f}%/{current_short}")
        sys.stdout.flush()
        await asyncio.sleep(0.2)
    if prog_state.total > 0:
        pct = (prog_state.done / prog_state.total) * 100
    else:
        pct = 100.0
    current = prog_state.current_path or ""
    current_short = current[:40]
    sys.stdout.write(f"\rProgress: {pct:.2f}%/{current_short}\n")
    sys.stdout.flush()

def banner():
    print("=== HTTP DIRECTORY ENUMERATOR ===")
    print()

def print_config(args, total_paths):
    print(f"[+] Target       : {args.url}")
    print(f"[+] Wordlist     : {args.wordlist} ({total_paths} base entries)")
    print(f"[+] Threads      : {args.threads}")
    if args.extensions:
        print(f"[+] Extensions   : {args.extensions}")
    else:
        print(f"[+] Extensions   : (none)")
    if args.status_codes:
        print(f"[+] Match Codes  : {args.status_codes}")
    if args.hide_status:
        print(f"[+] Hide Codes   : {args.hide_status}")
    if args.proxy:
        print(f"[+] Proxy        : {args.proxy}")
    if args.delay:
        print(f"[+] Delay        : {args.delay}s per request")
    if args.random_agent:
        print(f"[+] User-Agent   : random")
    elif args.user_agent:
        print(f"[+] User-Agent   : {args.user_agent}")
    else:
        print(f"[+] User-Agent   : default")
    if args.output:
        print(f"[+] Output File  : {args.output}")
    print()

async def main_async(args):
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("[!] Use full URL with http:// or https://")
        return

    exts = parse_extensions(args.extensions)
    words = load_wordlist(args.wordlist)

    targets = []
    seen = set()

    for w in words:
        url = build_url(args.url, w)
        if url not in seen:
            seen.add(url)
            targets.append((url, w))
        if exts:
            for e in exts:
                p = f"{w}.{e}"
                u = build_url(args.url, p)
                if u not in seen:
                    seen.add(u)
                    targets.append((u, p))

    total_paths = len(words)
    total_targets = len(targets)

    banner()
    print_config(args, total_paths)
    print(f"[+] Total requests queued: {total_targets}")
    print()

    headers = {}

    if args.random_agent:
        headers["User-Agent"] = random.choice(DEFAULT_UAS)
    elif args.user_agent:
        headers["User-Agent"] = args.user_agent
    else:
        headers["User-Agent"] = DEFAULT_UAS[0]

    client_kwargs = {
        "headers": headers,
        "timeout": args.timeout
    }

    if args.proxy:
        client_kwargs["proxies"] = {"all://": args.proxy}

    client = httpx.AsyncClient(**client_kwargs)

    show_status = set()
    hide_status = set()

    if args.status_codes:
        for s in args.status_codes.split(","):
            s = s.strip()
            if s.isdigit():
                show_status.add(int(s))

    if args.hide_status:
        for s in args.hide_status.split(","):
            s = s.strip()
            if s.isdigit():
                hide_status.add(int(s))

    if not show_status:
        show_status = {200, 301, 302, 307, 308, 401, 403, 500}

    cfg = SimpleNamespace(
        timeout=args.timeout,
        delay=args.delay,
        show_status=show_status,
        hide_status=hide_status,
        no_progress=args.no_progress,
        output=args.output
    )

    prog_state = SimpleNamespace(
        done=0,
        total=total_targets,
        current_path="",
        stop=False
    )

    queue = asyncio.Queue()
    for t in targets:
        await queue.put(t)

    results = []

    workers = [
        asyncio.create_task(worker(client, queue, results, cfg, prog_state))
        for _ in range(args.threads)
    ]

    prog_task = asyncio.create_task(progress_printer(prog_state, cfg))

    try:
        await queue.join()
    except KeyboardInterrupt:
        sys.stdout.write("\n[!] Interrupted by user, shutting down...\n")
        sys.stdout.flush()

    prog_state.stop = True
    await prog_task

    for _ in workers:
        await queue.put(None)

    await asyncio.gather(*workers, return_exceptions=True)
    await client.aclose()

    if args.output:
        try:
            with open(args.output, "w") as f:
                for url, path, status, size in results:
                    f.write(f"{url} {status} {size}\n")
            print(f"\n[+] Results written to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")

    print("\n[+] Scan complete.")
    print(f"[+] Total hits: {len(results)}")

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Async HTTP directory enumerator (Gobuster-like, advanced).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    p.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g. https://example.com)"
    )
    p.add_argument(
        "-w", "--wordlist",
        default=DEFAULT_WORDLIST,
        help="Path to wordlist file"
    )
    p.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Number of concurrent workers"
    )
    p.add_argument(
        "-x", "--extensions",
        help="Comma-separated list of extensions to append (e.g. php,html,txt)"
    )
    p.add_argument(
        "-s", "--status-codes",
        help="Comma-separated list of status codes to show (match). If not set, show 200,301,302,307,308,401,403,500"
    )
    p.add_argument(
        "--hide-status",
        help="Comma-separated list of status codes to hide"
    )
    p.add_argument(
        "--proxy",
        help="Proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050)"
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Request timeout in seconds"
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds after each request (per worker)"
    )
    p.add_argument(
        "--random-agent",
        action="store_true",
        help="Use a random User-Agent for requests"
    )
    p.add_argument(
        "-a", "--user-agent",
        help="Custom User-Agent string"
    )
    p.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable live progress display"
    )
    p.add_argument(
        "-o", "--output",
        help="Write all found results to a file"
    )

    return p

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.threads < 1:
        args.threads = 1

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Stopped cleanly by user.")

if __name__ == "__main__":
    main()
