/** Client-side convenience: a repo "blob" URL points at an HTML PAGE, not the
 *  file, so fetching it returns markup the text-gate rejects. Convert the
 *  common GitHub/GitLab blob URLs to their raw-file equivalent. This is only a
 *  hint/nudge — the backend's SSRF + text gate remain the real guard.
 *
 *  GitHub:  github.com/<o>/<r>/blob/<ref>/<path>
 *        -> raw.githubusercontent.com/<o>/<r>/<ref>/<path>
 *  GitLab:  gitlab.com/<o>/<r>/-/blob/<ref>/<path>
 *        -> gitlab.com/<o>/<r>/-/raw/<ref>/<path>
 */
export function rawFileUrl(input: string): string {
  const url = input.trim();
  let u: URL;
  try { u = new URL(url); } catch { return url; }

  // GitHub: /<owner>/<repo>/blob/<rest>
  if (u.hostname === "github.com") {
    const m = u.pathname.match(/^\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
    if (m) return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}${u.search}`;
  }
  // GitLab: /<...group/repo>/-/blob/<rest>  ->  /-/raw/<rest>
  if (u.hostname === "gitlab.com" && u.pathname.includes("/-/blob/")) {
    return `${u.origin}${u.pathname.replace("/-/blob/", "/-/raw/")}${u.search}`;
  }
  return url;
}

/** True when the input is a repo blob/web-page URL we can convert — used to
 *  show an inline "that's a web page link" hint. */
export function isBlobPageUrl(input: string): boolean {
  const raw = rawFileUrl(input);
  return raw !== input.trim();
}
