# VERSION: 1.3
#
# LICENSING INFORMATION
# This is free and unencumbered software released into the public domain.
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# For more information, please refer to <https://unlicense.org>

import gzip
import html
import math
import os
import re
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib

from novaprinter import prettyPrinter

try:
    # Optional but recommended: makes requests look like real Chrome at the TLS
    # level, which helps against sites that block plain Python scripts.
    # Install it for the same Python interpreter qBittorrent uses:
    #     python -m pip install curl_cffi
    from curl_cffi import requests as curl_requests
except Exception:
    curl_requests = None

LOG_NAME = 'btdig.log'
DUMP_NAME = 'btdig_last_failed_page.html'
MAX_LOG_BYTES = 256 * 1024

# Text that shows up on bot-protection / challenge pages.
CHALLENGE_MARKERS = (
    'just a moment', 'cf-chl', 'challenge-platform', 'attention required',
    'checking your browser', 'verify you are human', 'captcha', 'not a bot',
    'ddos-guard',
)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
    'Accept-Language': 'en-GB,en;q=0.5',
    # Only advertise encodings we can actually decode (no br / zstd).
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'DNT': '1',
    'Sec-GPC': '1',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
}


def _writable_path(name):
    """Path for a log/debug file: next to this plugin, else the system temp dir."""
    for base in (os.path.dirname(os.path.abspath(__file__)), tempfile.gettempdir()):
        path = os.path.join(base, name)
        try:
            with open(path, 'a'):
                pass
            return path
        except OSError:
            continue
    return None


def _log(level, message):
    """Write to btdig.log. Only ERROR messages also go to stderr, because
    qBittorrent reports anything written to stderr as an error in its
    Execution Log ("Error occurred in search engine")."""
    line = '%s [%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), level, message)
    if level == 'ERROR':
        try:
            print('[btdig] ' + message.splitlines()[0], file=sys.stderr, flush=True)
        except Exception:
            pass
    path = _writable_path(LOG_NAME)
    if not path:
        return
    try:
        if os.path.getsize(path) > MAX_LOG_BYTES:
            os.replace(path, path + '.old')
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError:
        pass


class BtdigError(Exception):
    def __init__(self, message, body=None):
        super().__init__(message)
        self.body = body


class btdig(object):
    url = 'https://www.btdig.com'
    name = 'btdig'
    supported_categories = {'all': '0'}

    MAX_PAGES = 10   # ~10 results per page; raise for more results (slower)
    PAGE_DELAY = 1   # seconds between page requests
    TIMEOUT = 20     # seconds per request

    RESULT_BLOCK = re.compile(r'<div class="one_result".*?(?=<div class="one_result"|$)', re.DOTALL)
    MAGNET = re.compile(r'href=["\'](magnet:\?xt=urn:btih:[^"\']+)["\']', re.I)

    # ------------------------------------------------------------------ search

    def search(self, what, cat='all'):
        self._printed = 0
        self._seen = set()
        # qBittorrent already percent-encodes `what`; don't encode it again.
        query = what.replace(' ', '+')
        try:
            self._run_search(query)
        except Exception as e:
            self._error('Unexpected plugin error: %s: %s' % (type(e).__name__, e),
                        detail=traceback.format_exc())
        _log('INFO', "search '%s' via %s finished: %d result(s) sent to qBittorrent" % (
            urllib.parse.unquote_plus(what),
            'curl_cffi' if curl_requests else 'urllib',
            self._printed))

    def _run_search(self, query):
        url = '%s/search?q=%s&order=0' % (self.url, query)
        try:
            body = self._get_page(url)
        except BtdigError as e:
            self._error(str(e), body=e.body, url=url)
            return

        blocks = self._parse_page(body)
        if self._printed == 0:
            self._explain_empty_page(body, blocks, url)
            return

        total_pages = self._total_pages(body)
        if total_pages is None:
            _log('WARN', 'Could not find the total result count on the page; fetching pages '
                         'until one has nothing new (max %d pages)' % self.MAX_PAGES)
            total_pages = self.MAX_PAGES
        else:
            total_pages = min(total_pages, self.MAX_PAGES)

        for page in range(1, total_pages):
            time.sleep(self.PAGE_DELAY)
            url = '%s/search?q=%s&p=%d&order=0' % (self.url, query, page)
            try:
                body = self._get_page(url)
            except BtdigError as e:
                self._error('Page %d failed, so results are incomplete: %s' % (page + 1, e),
                            body=e.body, url=url)
                return
            before = self._printed
            found = self._parse_page(body)
            if self._printed == before:
                if found:
                    _log('WARN', 'Page %d only contained results already seen; stopping' % (page + 1))
                elif any(m in body.lower() for m in CHALLENGE_MARKERS):
                    self._error('Page %d returned a bot-protection page, so results are incomplete'
                                % (page + 1), body=body, url=url)
                else:
                    _log('INFO', 'Page %d had no results; stopping' % (page + 1))
                    self._dump(body)  # kept in case this was an early, unexpected stop
                break

    def _total_pages(self, body):
        """Number of result pages, or None if the result count can't be found."""
        m = re.search(r'(\d[\d,.]*)\s+results?\s+found', body, re.I)
        digits = re.sub(r'\D', '', m.group(1)) if m else ''
        if not digits:
            return None
        pages = max(1, math.ceil(int(digits) / 10))
        _log('INFO', 'btdig reports %s results (%d page(s))' % (digits, pages))
        return pages

    # ------------------------------------------------------------------- HTTP

    def _get_page(self, url):
        status, body = self._http_get(url)
        if status == 200:
            return body
        if status in (403, 429, 503) or any(m in body.lower() for m in CHALLENGE_MARKERS):
            raise BtdigError(self._blocked_message(status), body)
        raise BtdigError('HTTP %s from btdig' % status, body)

    def _http_get(self, url):
        """Return (status_code, body_text). Raises BtdigError on network-level failure."""
        if curl_requests is not None:
            try:
                r = curl_requests.get(url, impersonate='chrome', timeout=self.TIMEOUT)
                return r.status_code, r.text
            except Exception as e:
                raise BtdigError('Request failed (curl_cffi): %s: %s' % (type(e).__name__, e))
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                return resp.getcode(), self._decode(resp)
        except BtdigError:
            raise
        except urllib.error.HTTPError as e:  # must come before URLError
            try:
                body = self._decode(e)
            except Exception:
                body = ''
            return e.code, body
        except urllib.error.URLError as e:
            raise BtdigError('Could not connect to %s: %s' % (self.url, e.reason))
        except Exception as e:
            raise BtdigError('Request failed: %s: %s' % (type(e).__name__, e))

    @staticmethod
    def _decode(resp):
        data = resp.read()
        encoding = (resp.headers.get('Content-Encoding') or '').lower()
        if encoding == 'gzip':
            data = gzip.decompress(data)
        elif encoding == 'deflate':
            try:
                data = zlib.decompress(data)
            except zlib.error:
                data = zlib.decompress(data, -zlib.MAX_WBITS)
        elif encoding in ('br', 'zstd'):
            raise BtdigError('Server sent %s-compressed data that urllib cannot decode' % encoding)
        return data.decode('utf-8', errors='replace')

    def _blocked_message(self, status):
        msg = 'btdig appears to be blocking automated requests (HTTP %s).' % status
        if curl_requests is None:
            msg += ' Installing curl_cffi for the Python qBittorrent uses may help.'
        else:
            msg += ' curl_cffi is installed but was still blocked: a JavaScript challenge or an IP/region block is likely.'
        return msg

    # ---------------------------------------------------------------- parsing

    def _parse_page(self, html_content):
        """Print every new result on the page. Returns the number of result items found."""
        items = self.RESULT_BLOCK.findall(html_content)
        if not items:
            # Fallback if the page layout changed: read bare magnet links only.
            items = ['href="%s"' % m for m in self.MAGNET.findall(html_content)]
            if items:
                _log('WARN', "No 'one_result' blocks found; falling back to bare magnet links "
                             "(names/sizes may be incomplete). btdig's layout has probably changed.")
        skipped = 0
        for item in items:
            try:
                if not self._emit(item):
                    skipped += 1
            except Exception as e:
                skipped += 1
                _log('WARN', 'Could not process a result: %s: %s' % (type(e).__name__, e))
        if skipped:
            _log('WARN', '%d of %d results on a page had no usable magnet link or failed to print'
                 % (skipped, len(items)))
        return len(items)

    def _emit(self, block):
        """Parse one result block and print it. False if it has no magnet link."""
        magnet = self.MAGNET.search(block)
        if not magnet:
            return False
        link = magnet.group(1).replace('&amp;', '&')

        h = re.search(r'btih:([0-9a-zA-Z]+)', link)
        key = (h.group(1) if h else link).lower()
        if key in self._seen:
            return True
        self._seen.add(key)

        name = ''
        m = re.search(r'<div class="torrent_name".*?><a.*?>(.*?)</a>', block, re.DOTALL)
        if m:
            name = html.unescape(re.sub(r'<.*?>', '', m.group(1))).strip()
        if not name:
            dn = re.search(r'[?&]dn=([^&]+)', link)
            name = urllib.parse.unquote_plus(dn.group(1)) if dn else key

        size = '-1'
        m = re.search(r'<span class="torrent_size"[^>]*>(.*?)</span>', block, re.DOTALL)
        if m:
            size = html.unescape(re.sub(r'<.*?>', '', m.group(1))).replace('\xa0', ' ').strip() or '-1'

        desc_link = self.url
        m = re.search(r'<div class="torrent_name".*?><a href="([^"]+)"', block, re.DOTALL)
        if m:
            desc_link = urllib.parse.urljoin(self.url + '/', html.unescape(m.group(1)))

        result = {
            'link': link,
            'name': name,
            'size': size,
            'seeds': '-1',
            'leech': '-1',
            'engine_url': self.url,
            'desc_link': desc_link,
        }
        try:
            prettyPrinter(result)
        except Exception:
            result['size'] = '-1'  # retry in case only the size string was the problem
            prettyPrinter(result)
        self._printed += 1
        return True

    def _explain_empty_page(self, body, blocks, url):
        low = body.lower()
        if any(m in low for m in CHALLENGE_MARKERS):
            self._error(self._blocked_message(200), body=body, url=url)
        elif blocks:
            self._error('Found %d result block(s) but none had a usable magnet link; '
                        'btdig may have changed its HTML' % blocks, body=body, url=url)
        elif re.search(r'\b0\s+results?\s+found|no\s+results?\s+found', low):
            _log('INFO', 'btdig reports no results for this search')
        else:
            self._error('Page loaded (%d bytes) but no results could be parsed: either nothing '
                        'matched or btdig changed its HTML' % len(body), body=body, url=url)

    # -------------------------------------------------------- error reporting

    def _error(self, message, detail=None, body=None, url=None):
        """Log the problem (also to the Execution Log via stderr) and show it as a
        row in qBittorrent's search results."""
        message = ' '.join(str(message).split())  # one line only: the output protocol is line-based
        _log('ERROR', message + (' (%s)' % url if url else '') + ('\n' + detail if detail else ''))
        if body:
            self._dump(body)
        try:
            prettyPrinter({
                'link': self.url,  # not a real torrent
                'name': '[btdig ERROR] %s (see btdig.log)' % message[:300],
                'size': '-1',
                'seeds': '-1',
                'leech': '-1',
                'engine_url': self.url,
                'desc_link': self.url,
            })
        except Exception:
            pass

    def _dump(self, body):
        path = _writable_path(DUMP_NAME)
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(body)
            _log('INFO', 'Saved the page to %s' % path)
        except OSError:
            pass
