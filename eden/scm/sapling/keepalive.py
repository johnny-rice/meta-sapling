# Portions Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2.

#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, see
#   <http://www.gnu.org/licenses/>.

# This file is part of urlgrabber, a high-level cross-protocol url-grabber
# Copyright 2002-2004 Michael D. Stenner, Ryan Tomayko

# Modified by Benoit Boissinot:
#  - fix for digest auth (inspired from urllib2.py @ Python v2.4)
# Modified by Dirkjan Ochtman:
#  - import md5 function from a local util module
# Modified by Augie Fackler:
#  - add safesend method and use it to prevent broken pipe errors
#    on large POST requests

"""An HTTP handler for urllib2 that supports HTTP 1.1 and keepalive.

>>> import urllib2
>>> from keepalive import HTTPHandler
>>> keepalive_handler = HTTPHandler()
>>> opener = urlreq.buildopener(keepalive_handler)
>>> urlreq.installopener(opener)
>>>
>>> fo = urlreq.urlopen('http://www.python.org')

If a connection to a given host is requested, and all of the existing
connections are still in use, another connection will be opened.  If
the handler tries to use an existing connection but it fails in some
way, it will be closed and removed from the pool.

To remove the handler, simply re-run build_opener with no arguments, and
install that opener.

You can explicitly close connections by using the close_connection()
method of the returned file-like object (described below) or you can
use the handler methods:

  close_connection(host)
  close_all()
  open_connections()

NOTE: using the close_connection and close_all methods of the handler
should be done with care when using multiple threads.
  * there is nothing that prevents another thread from creating new
    connections immediately after connections are closed
  * no checks are done to prevent in-use connections from being closed

>>> keepalive_handler.close_all()

EXTRA ATTRIBUTES AND METHODS

  Upon a status of 200, the object returned has a few additional
  attributes and methods, which should not be used if you want to
  remain consistent with the normal urllib2-returned objects:

    close_connection()  -  close the connection to the host
    readlines()         -  you know, readlines()
    status              -  the return status (i.e. 404)
    reason              -  english translation of status (i.e. 'File not found')

  If you want the best of both worlds, use this inside an
  AttributeError-catching try:

  >>> try: status = fo.status
  >>> except AttributeError: status = None

  Unfortunately, these are ONLY there if status == 200, so it's not
  easy to distinguish between non-200 responses.  The reason is that
  urllib2 tries to do clever things with error codes 301, 302, 401,
  and 407, and it wraps the object upon return.
"""

# $Id: keepalive.py,v 1.14 2006/04/04 21:00:32 mstenner Exp $

import email
import errno
import hashlib
import http.client as httplib
import socket
import sys
import threading
from typing import List

from . import urllibcompat, util
from .i18n import _

urlerr = util.urlerr
urlreq = util.urlreq

DEBUG = None


class ConnectionManager:
    """
    The connection manager must be able to:
      * keep track of all existing
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._hostmap = {}  # map hosts to a list of connections
        self._connmap = {}  # map connections to host
        self._readymap = {}  # map connection to ready state

    def add(self, host, connection, ready):
        self._lock.acquire()
        try:
            if host not in self._hostmap:
                self._hostmap[host] = []
            self._hostmap[host].append(connection)
            self._connmap[connection] = host
            self._readymap[connection] = ready
        finally:
            self._lock.release()

    def remove(self, connection):
        self._lock.acquire()
        try:
            try:
                host = self._connmap[connection]
            except KeyError:
                pass
            else:
                del self._connmap[connection]
                del self._readymap[connection]
                self._hostmap[host].remove(connection)
                if not self._hostmap[host]:
                    del self._hostmap[host]
        finally:
            self._lock.release()

    def set_ready(self, connection, ready):
        try:
            self._readymap[connection] = ready
        except KeyError:
            pass

    def get_ready_conn(self, host):
        conn = None
        self._lock.acquire()
        try:
            if host in self._hostmap:
                for c in self._hostmap[host]:
                    if self._readymap[c]:
                        self._readymap[c] = 0
                        conn = c
                        break
        finally:
            self._lock.release()
        return conn

    def get_all(self, host=None):
        if host:
            return list(self._hostmap.get(host, []))
        else:
            return dict(self._hostmap)


class KeepAliveHandler:
    def __init__(self):
        self._cm = ConnectionManager()

    #### Connection Management
    def open_connections(self):
        """return a list of connected hosts and the number of connections
        to each.  [('foo.com:80', 2), ('bar.org', 1)]"""
        return [(host, len(li)) for (host, li) in self._cm.get_all().items()]

    def close_connection(self, host):
        """close connection(s) to <host>
        host is the host:port spec, as in 'www.cnn.com:8080' as passed in.
        no error occurs if there is no connection to that host."""
        for h in self._cm.get_all(host):
            self._cm.remove(h)
            h.close()

    def close_all(self):
        """close all open connections"""
        for host, conns in self._cm.get_all().items():
            for h in conns:
                self._cm.remove(h)
                h.close()

    def _request_closed(self, request, host, connection):
        """tells us that this request is now closed and that the
        connection is ready for another request"""
        self._cm.set_ready(connection, 1)

    def _remove_connection(self, host, connection, close=0):
        if close:
            connection.close()
        self._cm.remove(connection)

    #### Transaction Execution
    def http_open(self, req):
        return self.do_open(HTTPConnection, req)

    def do_open(self, http_class, req):
        host = urllibcompat.gethost(req)
        if not host:
            raise urlerr.urlerror("no host given")

        try:
            h = self._cm.get_ready_conn(host)
            while h:
                r = self._reuse_connection(h, req, host)

                # if this response is non-None, then it worked and we're
                # done.  Break out, skipping the else block.
                if r:
                    break

                # connection is bad - possibly closed by server
                # discard it and ask for the next free connection
                h.close()
                self._cm.remove(h)
                h = self._cm.get_ready_conn(host)
            else:
                # no (working) free connections were found.  Create a new one.
                h = http_class(host)
                if DEBUG:
                    DEBUG.info("creating new connection to %s (%d)", host, id(h))
                self._cm.add(host, h, 0)
                self._start_transaction(h, req)
                r = h.getresponse()
        # The string form of BadStatusLine is the status line. Add some context
        # to make the error message slightly more useful.
        except httplib.BadStatusLine as err:
            raise urlerr.urlerror(_("bad HTTP status line: %s") % err.line)
        except (socket.error, httplib.HTTPException) as err:
            raise urlerr.urlerror(err)

        # if not a persistent connection, don't try to reuse it
        if r.will_close:
            self._cm.remove(h)

        if DEBUG:
            DEBUG.info("STATUS: %s, %s", r.status, r.reason)
        r._handler = self
        r._host = host
        r._url = req.get_full_url()
        r._connection = h
        r.code = r.status
        r.headers = r.msg
        r.msg = r.reason

        return r

    def _reuse_connection(self, h, req, host):
        """start the transaction with a reused connection
        return a response object (r) upon success or None on failure.
        This DOES not close or remove bad connections in cases where
        it returns.  However, if an unexpected exception occurs, it
        will close and remove the connection before re-raising.
        """
        try:
            self._start_transaction(h, req)
            r = h.getresponse()
            # note: just because we got something back doesn't mean it
            # worked.  We'll check the version below, too.
        except (socket.error, httplib.HTTPException):
            r = None
        except:  # re-raises
            # adding this block just in case we've missed
            # something we will still raise the exception, but
            # lets try and close the connection and remove it
            # first.  We previously got into a nasty loop
            # where an exception was uncaught, and so the
            # connection stayed open.  On the next try, the
            # same exception was raised, etc.  The trade-off is
            # that it's now possible this call will raise
            # a DIFFERENT exception
            if DEBUG:
                DEBUG.error(
                    "unexpected exception - closing connection to %s (%d)",
                    host,
                    id(h),
                )
            self._cm.remove(h)
            h.close()
            raise

        if r is None or r.version == 9:
            # httplib falls back to assuming HTTP 0.9 if it gets a
            # bad header back.  This is most likely to happen if
            # the socket has been closed by the server since we
            # last used the connection.
            if DEBUG:
                DEBUG.info("failed to reuse connection to %s (%d)", host, id(h))
            r = None
        else:
            if DEBUG:
                DEBUG.info("reusing connection to %s (%d)", host, id(h))

        return r

    def _start_transaction(self, h, req):
        # What follows mostly reimplements HTTPConnection.request()
        # except it adds self.parent.addheaders in the mix and sends headers
        # in a deterministic order (to make testing easier).
        headers = util.altsortdict(self.parent.addheaders)
        headers.update(sorted(req.headers.items()))
        headers.update(sorted(req.unredirected_hdrs.items()))
        headers = util.altsortdict((n.lower(), v) for n, v in headers.items())
        skipheaders = {}
        data = None
        for n in ("host", "accept-encoding"):
            if n in headers:
                skipheaders["skip_" + n.replace("-", "_")] = 1
        try:
            if urllibcompat.hasdata(req):
                data = urllibcompat.getdata(req)
                h.putrequest(
                    req.get_method(), urllibcompat.getselector(req), **skipheaders
                )
                if "content-type" not in headers:
                    h.putheader("Content-type", "application/x-www-form-urlencoded")
                if "content-length" not in headers:
                    h.putheader("Content-length", "%d" % len(data))
            else:
                h.putrequest(
                    req.get_method(), urllibcompat.getselector(req), **skipheaders
                )
        except socket.error as err:
            raise urlerr.urlerror(err)
        for k, v in headers.items():
            h.putheader(k, v)
        h.endheaders(message_body=data)


# pyre-fixme[11]: Annotation `httphandler` is not defined as a type.
class HTTPHandler(KeepAliveHandler, urlreq.httphandler):
    pass


class HTTPResponse(httplib.HTTPResponse):
    # we need to subclass HTTPResponse in order to
    # 1) add readline() and readlines() methods
    # 2) add close_connection() methods
    # 3) add info() and geturl() methods

    # in order to add readline(), read must be modified to deal with a
    # buffer.  example: readline must read a buffer and then spit back
    # one line at a time.  The only real alternative is to read one
    # BYTE at a time (ick).  Once something has been read, it can't be
    # put back (ok, maybe it can, but that's even uglier than this),
    # so if you THEN do a normal read, you must first take stuff from
    # the buffer.

    # the read method wraps the original to accommodate buffering,
    # although read() never adds to the buffer.
    # Both readline and readlines have been stolen with almost no
    # modification from socket.py

    def __init__(self, sock, debuglevel=0, strict=0, method=None):
        extrakw = {}
        httplib.HTTPResponse.__init__(
            self, sock, debuglevel=debuglevel, method=method, **extrakw
        )
        self.fileno = sock.fileno
        self.code = None
        self._rbuf = b""
        self._rbufsize = 8096
        self._handler = None  # inserted by the handler later
        self._host = None  # (same)
        self._url = ""  # (same)
        self._connection = None  # (same)

    _raw_read = httplib.HTTPResponse.read

    def close(self) -> None:
        httplib.HTTPResponse.close(self)

        handler = self._handler
        if handler:
            handler._request_closed(self, self._host, self._connection)

    def close_connection(self):
        self._handler._remove_connection(self._host, self._connection, close=1)
        self.close()

    def info(self) -> "email.message.Message":
        return self.headers

    def geturl(self) -> str:
        return self._url

    def read(self, amt=None) -> bytes:
        # the _rbuf test is only in this first if for speed.  It's not
        # logically necessary
        if amt:
            if self._rbuf:
                L = len(self._rbuf)
                if amt > L:
                    amt -= L
                else:
                    s = self._rbuf[:amt]
                    self._rbuf = self._rbuf[amt:]
                    return s

        s = self._rbuf + self._raw_read(amt)
        self._rbuf = b""
        return s

    # stolen from Python SVN #68532 to fix issue1088
    def _read_chunked(self, amt) -> bytes:
        chunk_left = self.chunk_left
        parts = []

        while True:
            if chunk_left is None:
                line = self.fp.readline()
                i = line.find(b";")
                if i >= 0:
                    line = line[:i]  # strip chunk-extensions
                try:
                    chunk_left = int(line, 16)
                except ValueError:
                    # close the connection as protocol synchronization is
                    # probably lost
                    self.close()
                    raise httplib.IncompleteRead("".join(parts))
                if chunk_left == 0:
                    break
            if amt is None:
                parts.append(self._safe_read(chunk_left))
            elif amt < chunk_left:
                parts.append(self._safe_read(amt))
                self.chunk_left = chunk_left - amt
                return b"".join(parts)
            elif amt == chunk_left:
                parts.append(self._safe_read(amt))
                self._safe_read(2)  # toss the CRLF at the end of the chunk
                self.chunk_left = None
                return b"".join(parts)
            else:
                parts.append(self._safe_read(chunk_left))
                amt -= chunk_left

            # we read the whole chunk, get another
            self._safe_read(2)  # toss the CRLF at the end of the chunk
            chunk_left = None

        # read and discard trailer up to the CRLF terminator
        ### note: we shouldn't have any trailers!
        while True:
            line = self.fp.readline()
            if not line:
                # a vanishingly small number of sites EOF without
                # sending the trailer
                break
            if line == b"\r\n":
                break

        # we read everything; close the "file"
        self.close()

        return b"".join(parts)

    def readline(self, size: int = -1) -> bytes:
        # Fast path for a line is already available in read buffer.
        i = self._rbuf.find(b"\n")
        if i >= 0:
            i += 1
            line = self._rbuf[:i]
            self._rbuf = self._rbuf[i:]
            return line

        # No newline in local buffer. Read until we find one.
        chunks = [self._rbuf]
        i = -1
        readsize = self._rbufsize
        while True:
            new = self._raw_read(readsize)
            if not new:
                break

            chunks.append(new)
            i = new.find(b"\n")
            if i >= 0:
                break

        # We either have exhausted the stream or have a newline in chunks[-1].

        # EOF
        if i == -1:
            self._rbuf = b""
            return b"".join(chunks)

        i += 1
        self._rbuf = chunks[-1][i:]
        chunks[-1] = chunks[-1][:i]
        return b"".join(chunks)

    def readlines(self, hint: int = 0) -> "List[bytes]":
        total = 0
        list = []
        while True:
            line = self.readline()
            if not line:
                break
            list.append(line)
            total += len(line)
            if hint and total >= hint:
                break
        return list


def safesend(self, str):
    """Send `str' to the server.

    Shamelessly ripped off from httplib to patch a bad behavior.
    """
    # _broken_pipe_resp is an attribute we set in this function
    # if the socket is closed while we're sending data but
    # the server sent us a response before hanging up.
    # In that case, we want to pretend to send the rest of the
    # outgoing data, and then let the user use getresponse()
    # (which we wrap) to get this last response before
    # opening a new socket.
    if getattr(self, "_broken_pipe_resp", None) is not None:
        return

    if self.sock is None:
        if self.auto_open:
            self.connect()
        else:
            raise httplib.NotConnected

    # send the data to the server. if we get a broken pipe, then close
    # the socket. we want to reconnect when somebody tries to send again.
    #
    # NOTE: we DO propagate the error, though, because we cannot simply
    #       ignore the error... the caller will know if they can retry.
    if self.debuglevel > 0:
        print("send:", repr(str))
    try:
        blocksize = 8192
        read = getattr(str, "read", None)
        if read is not None:
            # Uploading data is always expected to consume the entire file
            # or buffer as we send a content-length for the full length. So
            # it's safe for us to rewind the cursor back to the beginning of
            # our file/buffer. This avoid the problem that when we retry a
            # request that we can't read the data that we need, as we've already
            # consumed all the data by reading it.
            seek = getattr(str, "seek", None)
            if seek is not None:
                if self.debuglevel > 0:
                    print("sending a seek()able")
                seek(0)

            expectedlen = len(str)
            totalwritten = 0
            if self.debuglevel > 0:
                print("sending a read()able")
            data = read(blocksize)
            while data:
                totalwritten += len(data)
                self.sock.sendall(data)
                data = read(blocksize)

            # This is a safety check to avoid waiting for a server response in
            # the case where we haven't written the amount of data that the
            # server is expecting. Earlier in the stack we set the Content-Length
            # to the length of 'str'. It's possible a server could wait indefenitely
            # in some cases where less data has been written then expected, therefore
            # always ensure we have actually written what we are expecting.
            if expectedlen != totalwritten:
                raise urlerr.urlerror(
                    "couldn't read {} bytes, only got {}".format(
                        expectedlen, totalwritten
                    )
                )
        else:
            self.sock.sendall(str)
    except socket.error as v:
        reraise = True
        if v.errno == errno.EPIPE:  # Broken pipe
            if self._HTTPConnection__state == httplib._CS_REQ_SENT:
                self._broken_pipe_resp = None
                self._broken_pipe_resp = self.getresponse()
                reraise = False
            self.close()
        if reraise:
            raise


def wrapgetresponse(cls):
    """Wraps getresponse in cls with a broken-pipe sane version."""

    def safegetresponse(self):
        # In safesend() we might set the _broken_pipe_resp
        # attribute, in which case the socket has already
        # been closed and we just need to give them the response
        # back. Otherwise, we use the normal response path.
        r = getattr(self, "_broken_pipe_resp", None)
        if r is not None:
            return r
        return cls.getresponse(self)

    safegetresponse.__doc__ = cls.getresponse.__doc__
    return safegetresponse


class HTTPConnection(httplib.HTTPConnection):
    # use the modified response class
    response_class = HTTPResponse
    send = safesend
    getresponse = wrapgetresponse(httplib.HTTPConnection)


#########################################################################
#####   TEST FUNCTIONS
#########################################################################


def continuity(url):
    md5 = hashlib.md5
    format = "%25s: %s"

    # first fetch the file with the normal http handler
    opener = urlreq.buildopener()
    urlreq.installopener(opener)
    fo = urlreq.urlopen(url)
    foo = fo.read()
    fo.close()
    m = md5(foo)
    print(format % ("normal urllib", m.hexdigest()))

    # now install the keepalive handler and try again
    opener = urlreq.buildopener(HTTPHandler())
    urlreq.installopener(opener)

    fo = urlreq.urlopen(url)
    foo = fo.read()
    fo.close()
    m = md5(foo)
    print(format % ("keepalive read", m.hexdigest()))

    fo = urlreq.urlopen(url)
    foo = ""
    while True:
        f = fo.readline()
        if f:
            foo = foo + f
        else:
            break
    fo.close()
    m = md5(foo)
    print(format % ("keepalive readline", m.hexdigest()))


def comp(N, url):
    print("  making %i connections to:\n  %s" % (N, url))

    util.stdout.write("  first using the normal urllib handlers")
    # first use normal opener
    opener = urlreq.buildopener()
    urlreq.installopener(opener)
    t1 = fetch(N, url)
    print("  TIME: %.3f s" % t1)

    util.stdout.write("  now using the keepalive handler       ")
    # now install the keepalive handler and try again
    opener = urlreq.buildopener(HTTPHandler())
    urlreq.installopener(opener)
    t2 = fetch(N, url)
    print("  TIME: %.3f s" % t2)
    print("  improvement factor: %.2f" % (t1 / t2))


def fetch(N, url, delay=0):
    import time

    lens = []
    starttime = time.time()
    for i in range(N):
        if delay and i > 0:
            time.sleep(delay)
        fo = urlreq.urlopen(url)
        foo = fo.read()
        fo.close()
        lens.append(len(foo))
    diff = time.time() - starttime

    j = 0
    for i in lens[1:]:
        j = j + 1
        if not i == lens[0]:
            print("WARNING: inconsistent length on read %i: %i" % (j, i))

    return diff


def test_timeout(url):
    global DEBUG
    dbbackup = DEBUG

    class FakeLogger:
        def debug(self, msg, *args):
            print(msg % args)

        info = warning = error = debug

    DEBUG = FakeLogger()
    print("  fetching the file to establish a connection")
    fo = urlreq.urlopen(url)
    data1 = fo.read()
    fo.close()

    i = 20
    print("  waiting %i seconds for the server to close the connection" % i)
    while i > 0:
        util.stdout.write("\r  %2i" % i)
        util.stdout.flush()
        time.sleep(1)
        i -= 1
    util.stderr.write("\r")

    print("  fetching the file a second time")
    fo = urlreq.urlopen(url)
    data2 = fo.read()
    fo.close()

    if data1 == data2:
        print("  data are identical")
    else:
        print("  ERROR: DATA DIFFER")

    DEBUG = dbbackup


def test(url, N=10):
    print("performing continuity test (making sure stuff isn't corrupted)")
    continuity(url)
    print("")
    print("performing speed comparison")
    comp(N, url)
    print("")
    print("performing dropped-connection check")
    test_timeout(url)


if __name__ == "__main__":
    import time

    try:
        N = int(sys.argv[1])
        url = sys.argv[2]
    except (IndexError, ValueError):
        print("%s <integer> <url>" % sys.argv[0])
    else:
        test(url, N)
