/* 
 * Copyright 2016-2017 The Regents of the University of California
 * All rights reserved.
 * 
 * This file is part of Spoofer.
 * 
 * Spoofer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Spoofer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Spoofer.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdio>
#include <sstream>
#include <iomanip>
#include "spoof.h"
#include "PBStreamer.h"

bool PBStreamer::resizeBuf(size_t size)
{
    if (capacity < size) {
	char *oldbuf = buf;
	buf = new char[size];
	if (!buf) {
	    capacity = 0;
	    return false;
	}
	capacity = size;
	if (oldbuf) {
	    if (progress) memcpy(buf, oldbuf, progress);
	    delete[] oldbuf;
	}
    }
    return true;
}

void PBStreamer::consume(size_t len) {
    progress -= len;
    if (progress > 0) memmove(buf, buf + len, progress);
}

PBStreamer::Result PBStreamer::writeMessage(
    ::google::protobuf::MessageLite *msg)
{
    if (!wrotemagic && _magic) {
	ssize_t n;
#ifdef HAVE_LIBSSL
	if (_ssl) {
	    n = SSL_write(_ssl, _magic->data(), safe_int<int>(_magic->size()));
	    if (n <= 0) {
		int err = SSL_get_error(_ssl, static_cast<int>(n));
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		    return set_errbuf(INCOMPLETE); // renegotiation in progress?
	    }
	} else
#endif
	{
#ifdef _WIN32
	    // send() works only on sockets (on all platforms)
	    n = send(_fd, _magic->data(), safe_int<SEND_LEN_T>(_magic->size()), 0);
#else
	    // on Unix, write() works on all types of file descriptors
	    n = write(_fd, _magic->data(), _magic->size());
#endif
	}
	if (n < 0 || safe_int<size_t>(n) != _magic->size())
	    return IO_ERROR;
	wrotemagic = true;
	if (readmagic) {
	    _magic = nullptr; // no longer needed;
	}
    }

    if (msg_size == 0) {
	msg_size = safe_int<msg_size_t>(msg->ByteSize());
	if (!resizeBuf(sizeof(msg_size_t) + msg_size))
	    return cleanup(OUT_OF_MEMORY);
	htonpl(buf, msg_size);
	msg->SerializeWithCachedSizesToArray((uint8_t*)buf + sizeof(msg_size_t));
	progress = 0;
    }
    Result result = writeBytes(sizeof(msg_size_t) + msg_size);
    return cleanup(result, false);
}

PBStreamer::Result PBStreamer::readMessage(
    ::google::protobuf::MessageLite *msg)
{
    Result result;

#define HEADROOM 256
    if (!readmagic && _magic) {
	if (!resizeBuf(HEADROOM))
	    return cleanup(OUT_OF_MEMORY);
	result = readBytes(HEADROOM);
	if (result != OK && result != INCOMPLETE)
	    return cleanup(result, false);
	const std::string *match;
	for (match = _magic; !match->empty(); match++) {
	    if (progress >= match->length() &&
		memcmp(match->data(), buf, match->length()) == 0)
		    break;
	}
	if (match->empty()) {
	    std::ostringstream ess;
	    ess << std::hex << std::setfill('0') << "bad magic: \"";
	    for (unsigned i = 0; i < progress; i++) {
		if (isprint(buf[i]) && buf[i] != '\\')
		    ess << buf[i];
		else
		    ess << "\\x" << std::setw(2) << (unsigned)buf[i];
	    }
	    ess << "\"";
	    errstr = ess.str();
	    return cleanup(BAD_MAGIC, false);
	}
	consume(match->length());
	readmagic = true;
	_magic = wrotemagic ?
	    nullptr : // no longer needed;
	    match; // so the next writeMessage() will use the same magic
    }

    if (!resizeBuf(sizeof(msg_size_t)))
	return cleanup(OUT_OF_MEMORY);
    if (msg_size == 0) {
	result = readBytes(sizeof(msg_size_t));
	if (result != OK)
	    return cleanup(result, false);
	msg_size = nptohl(buf);
	// Sanity check: a maximum length of 0x00FFFFFF will block any non-PBS
	// stream that starts with an ASCII character or other nonzero byte,
	// but still allow PBS messages up to 16 MiB.
	if (msg_size > 0x00FFFFFF)
	    return cleanup(PARSE_ERROR);
	consume(sizeof(msg_size_t));
    }
    if (!resizeBuf(msg_size))
	return cleanup(OUT_OF_MEMORY);
    result = readBytes(msg_size);
    if (result != OK)
	return cleanup(result, false);
    msg->Clear(); // XXX is this necessary?
    if (!msg->ParseFromArray(buf, safe_int<int>(msg_size)))
	return cleanup(PARSE_ERROR);
    return cleanup(OK);
}

// fills in errstr if result is not OK
PBStreamer::Result PBStreamer::writeBytes(size_t goal)
{
    ssize_t n;

    if (progress == goal) return OK;
#ifdef HAVE_LIBSSL
    if (_ssl) {
	n = SSL_write(_ssl, buf + progress, safe_int<int>(goal - progress));
	if (n <= 0) {
	    int err = SSL_get_error(_ssl, static_cast<int>(n));
	    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return set_errbuf(INCOMPLETE); // renegotiation in progress?
	}
    } else
#endif
    {
#ifdef _WIN32
	// send() works only on sockets (on all platforms)
	n = send(_fd, buf + progress, safe_int<SEND_LEN_T>(goal - progress), 0);
#else
	// on Unix, write() works on all types of file descriptors
	n = write(_fd, buf + progress, goal - progress);
#endif
    }
    if (n >= 0) {
	progress += safe_int<size_t>(n);
	if (progress == goal) return OK; // finished
	return set_errbuf(INCOMPLETE);
#ifndef _WIN32 // nonblocking not supported on Windows
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
	return set_errbuf(INCOMPLETE);
#endif
    } else {
	return set_errbuf(IO_ERROR);
    }
}

// fills in errstr if result is not OK
PBStreamer::Result PBStreamer::readBytes(size_t goal)
{
    ssize_t n;

    if (progress >= goal) return OK;
#ifdef HAVE_LIBSSL
    if (_ssl) {
	n = SSL_read(_ssl, buf + progress, safe_int<int>(goal - progress));
	if (n <= 0) {
	    int err = SSL_get_error(_ssl, static_cast<int>(n));
	    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return set_errbuf(INCOMPLETE); // renegotiation in progress?
	}
    } else
#endif
    {
#ifdef _WIN32
	// recv() works only on sockets (on all platforms)
	n = recv(_fd, buf + progress, safe_int<SEND_LEN_T>(goal - progress), 0);
#else
	// on Unix, read() works on all types of file descriptors
	n = read(_fd, buf + progress, goal - progress);
#endif
    }

#if DEBUG-0
    if (n < 0)
	fprintf(stderr, "read: %s\n", SockLastErrmsg()());
    else
	fprintf(stderr, "read %zd of %zd bytes\n", n, goal - progress);
#endif

    if (n == 0) {
	return set_errbuf(CLOSED); // peer closed
    } else if (n > 0) {
	progress += safe_int<size_t>(n);
	if (progress == goal) return OK; // finished
	return set_errbuf(INCOMPLETE);
#ifndef _WIN32 // nonblocking not supported on Windows
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
	return set_errbuf(INCOMPLETE);
#endif
    } else {
	return set_errbuf(IO_ERROR);
    }
}

const char *PBStreamer::errmsg(PBStreamer::Result result)
{
    static char buf[1024];
    switch (result) {
    case OK:            return "no error";
    case INCOMPLETE:    return "operation is incomplete";
    case CLOSED:        return "remote host closed connection";
    case OUT_OF_MEMORY: return "out of memory";
    case IO_ERROR:      sprintf(buf, "I/O error: %s", SockLastErrmsg()());
			return buf;
    case BAD_MAGIC:     return "bad magic";
    case PARSE_ERROR:   return "protocol parse error";
    default:            sprintf(buf, "unknown error %d", result);
			return buf;
    }
}
