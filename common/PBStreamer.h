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

/** @file PBStreamer.h
 * Wrapper for a file descriptor that can do a streaming read or write of
 * google::protobuf::MessageLite.
 */

#include "port.h"

#ifndef COMMON_PBSTREAMER_H
#define COMMON_PBSTREAMER_H

#include <google/protobuf/message_lite.h>

#ifdef HAVE_LIBSSL
 #include <openssl/ssl.h>
#endif


/**
 * Wrapper for a file descriptor that can do a streaming read or write of
 * google::protobuf::MessageLite.
 * 
 * On Unix-like platforms, the file descriptor may be blocking or nonblocking,
 * and any type of file descriptor is allowed (socket, pipe, file, etc.).  On
 * Windows, only blocking sockets are allowed.
 */
class PBStreamer {
public:
    /** Result of readMessage() or writeMessage() */
    enum Result {
	OK,            ///< a complete message was read or written
	INCOMPLETE,    ///< operation is incomplete; try again later
	CLOSED,        ///< remote side of fd was closed
	OUT_OF_MEMORY, ///< PBStreamer failed to obtain memory; a later
	               ///< attempt may succeed if memory becomes available.
	IO_ERROR,      ///< An I/O error occurred.  Use errno (unix) or
	               ///< WSAGetLastError() (windows) to learn more.
	BAD_MAGIC,     ///< the stream did not begin with the magic string
	PARSE_ERROR    ///< the Message read by readMessage() was not parsable
    };

    /**
      * Constructor.
      * @param fd        an open file descriptor
      */
    PBStreamer(socket_t fd, const std::string *magic) :
	_fd(fd), msg_size(0), buf(0), capacity(0), progress(0),
	_magic(magic), readmagic(false), wrotemagic(false),
	errstr()
    { }
#ifdef HAVE_LIBSSL
    PBStreamer(SSL *ssl, const std::string *magic) :
	_fd(INVALID_SOCKET), _ssl(ssl), msg_size(0), buf(0), capacity(0), progress(0),
	_magic(magic), readmagic(false), wrotemagic(false),
	errstr()
    { }
#endif

private:
    PBStreamer(const PBStreamer &) NO_METHOD; // no copy-ctor
    PBStreamer operator=(const PBStreamer &) NO_METHOD; // no copy-assign

public:
    /**
      * Destructor.
      * Does not close the file descriptor.
      */
    ~PBStreamer() {
	if (buf) delete buf;
    }

    /**
      * Write a MessageLite to the file descriptor.
      *
      * @param msg      pointer to the message
      * @return         result code
      *
      * This method returns OK if the message in *msg has been written
      * completely to the fd.  The PBStreamer may then be used again to read
      * from or write to the same fd.
      *
      * If the file descriptor is blocking, this method will block until the
      * write is complete or an error occurs.
      *
      * If the file descriptor is nonblocking, this method may return
      * INCOMPLETE to indicate that the entire message could not be written
      * yet.  This can happen even if select() has indicated the fd is
      * writable.  In this case, you should repeat the call later to continue
      * writing the message (e.g., after select() indicates the file
      * descriptor is writable again).  The msg parameter will be ignored in
      * the repeat call; the PBStreamer will continue to write the original
      * message.  Do not call any other method after an INCOMPLETE.
      */
    Result writeMessage(::google::protobuf::MessageLite *msg);

    /**
      * Read a MessageLite (that was written by PBStreamer::writeMessage) from
      * the file descriptor.
      *
      * @param msg      pointer to memory that will hold the incoming message
      * @return         result code
      *
      * The message to be read must have been written by
      * PBStreamer::writeMessage.  Unlike the protobuf methods, this method
      * will stop at a message boundary.
      *
      * This method returns OK if a complete message has been read and stored
      * in *msg.  The PBStreamer may then be used again to read from or write
      * to the same fd.
      *
      * If the file descriptor is blocking, this method will block until at
      * least part of the message is readable.
      *
      * On both blocking and nonblocking fds, this method may return
      * INCOMPLETE to indicate that the entire message could not be read yet.
      * This can happen even if select() has indicated the fd is readable, if
      * only part of the message was actually available from the fd.  In this
      * case, you should repeat the call later to continue reading the
      * message.  On a blocking fd, you may repeat immediately if desired (or
      * just use readFullMessage()).  On a nonblocking fd, an immediate repeat
      * is likely to return INCOMPLETE again, so you should wait, e.g. until
      * select() indicates the file descriptor is readable again.  The msg
      * parameter does not need to be the same in the repeat call; it will not
      * be filled in until the complete message is received.
      * Do not call any other method after an INCOMPLETE.
      */
    Result readMessage(::google::protobuf::MessageLite *msg);

    /**
      * Like readMessage(), but will block until the full message is read or
      * an error occurs.  Will never return INCOMPLETE.  Should only be used
      * on blocking file descriptors (using it on nonblocking fds may cause a
      * busy-wait).
      */
    Result readFullMessage(::google::protobuf::MessageLite *msg) {
	Result result;
	do { result = readMessage(msg); } while (result == INCOMPLETE);
	return result;
    }

    /**
      * Returns an error message corresponding to result.  May be less
      * informative than last_errmsg().
      */
    static const char *errmsg(PBStreamer::Result result);

    /**
      * Returns a pointer to the last error message.  May be more informative
      * than errmsg().
      */
    const char *last_errmsg() { return errstr.c_str(); }

private:
    typedef uint32_t msg_size_t; // part of protocol, must be a fixed type
    socket_t _fd;
#ifdef HAVE_LIBSSL
    SSL *_ssl = nullptr;
#endif
    msg_size_t msg_size; // size of serialized form of msg
    char *buf;           // buffer for serialized form of msg
    size_t capacity;     // allocated size of buf
    size_t progress;     // how many bytes have been read or written
    const std::string *_magic;
    bool readmagic, wrotemagic;
    std::string errstr;

    Result writeBytes(size_t goal);
    Result readBytes(size_t goal);
    Result set_errbuf(const Result result) {
	errstr = std::string(errmsg(result));
	return result;
    }
    Result cleanup(const Result result, bool fill_errstr = true) {
	if (result != INCOMPLETE) progress = msg_size = 0;
	if (result != OK && fill_errstr) errstr = std::string(errmsg(result));
	return result;
    }
    bool resizeBuf(size_t size);
    void consume(size_t len);
};

#endif // COMMON_PBSTREAMER_H
