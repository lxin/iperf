/*
 * iperf, Copyright (c) 2014-2019, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include "iperf_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <limits.h>

#ifdef HAVE_NETINET_QUIC_H
#include <netinet/quic.h>
#endif /* HAVE_NETINET_QUIC_H */

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_quic.h"
#include "net.h"



/* iperf_quic_recv
 *
 * receives the data for QUIC
 */
int
iperf_quic_recv(struct iperf_stream *sp)
{
#if defined(HAVE_QUIC_H)
    int r;

    r = Nread(sp->socket, sp->buffer, sp->settings->blksize, Pquic);
    if (r < 0)
        return r;

    /* Only count bytes received while we're in the correct state. */
    if (sp->test->state == TEST_RUNNING) {
	sp->result->bytes_received += r;
	sp->result->bytes_received_this_interval += r;
    }
    else {
	if (sp->test->debug)
	    printf("Late receive, state = %d\n", sp->test->state);
    }

    return r;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}


/* iperf_quic_send
 *
 * sends the data for QUIC
 */
int
iperf_quic_send(struct iperf_stream *sp)
{
#if defined(HAVE_QUIC_H)
    int r;

    r = Nwrite(sp->socket, sp->buffer, sp->settings->blksize, Pquic);
    if (r < 0)
        return r;

    sp->result->bytes_sent += r;
    sp->result->bytes_sent_this_interval += r;

    return r;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}



/* iperf_quic_accept
 *
 * accept a new QUIC stream connection
 */
int
iperf_quic_accept(struct iperf_test * test)
{
#if defined(HAVE_QUIC_H)
    int     s;
    signed char rbuf = ACCESS_DENIED;
    char    cookie[COOKIE_SIZE];
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);
    s = accept(test->listener, (struct sockaddr *) &addr, &len);
    if (s < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (quic_server_handshake(s, test->settings->pkey_file, test->settings->cert_file, NULL)) {
        close(s);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If fq socket pacing is specified, enable it. */

    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */

    if (Nread(s, cookie, COOKIE_SIZE, Pquic) < 0) {
        i_errno = IERECVCOOKIE;
        close(s);
        return -1;
    }

    if (strncmp(test->cookie, cookie, COOKIE_SIZE) != 0) {
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Pquic) < 0) {
            i_errno = IESENDMESSAGE;
            close(s);
            return -1;
        }
        close(s);
    }

    return s;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}


/* iperf_quic_listen
 *
 * start up a listener for QUIC stream connections
 */
int
iperf_quic_listen(struct iperf_test *test)
{
#if defined(HAVE_QUIC_H)
    struct quic_transport_param param = {};
    struct addrinfo hints, *res;
    int s, opt, saved_errno;
    char portstr[6];

    close(test->listener);
    test->listener = -1;

    snprintf(portstr, 6, "%d", test->server_port);
    memset(&hints, 0, sizeof(hints));
    /*
     * If binding to the wildcard address with no explicit address
     * family specified, then force us to get an AF_INET6 socket.
     * More details in the comments in netanounce().
     */
    if (test->settings->domain == AF_UNSPEC && !test->bind_address) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = test->settings->domain;
    }
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((gerror = getaddrinfo(test->bind_address, portstr, &hints, &res)) != 0) {
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    if ((s = socket(res->ai_family, SOCK_STREAM, IPPROTO_QUIC)) < 0) {
        freeaddrinfo(res);
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    if ((opt = test->settings->socket_bufsize)) {
        int saved_errno;
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }

    if ((opt = test->settings->no_cryption)) {
        int saved_errno;
        param.disable_1rtt_encryption = opt;
        if (setsockopt(s, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IESENDPARAMS;
            return -1;
	}
    }

#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
    if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC ||
        test->settings->domain == AF_INET6)) {
        if (test->settings->domain == AF_UNSPEC)
            opt = 0;
        else
            opt = 1;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
		       (char *) &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
	    i_errno = IEPROTOCOL;
	    return -1;
	}
    }
#endif /* IPV6_V6ONLY */

    if (bind(s, (struct sockaddr *) res->ai_addr, res->ai_addrlen) < 0) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(res);
        errno = saved_errno;
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    freeaddrinfo(res);

    if (listen(s, INT_MAX) < 0) {
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    test->listener = s;

    return s;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}


/* iperf_quic_connect
 *
 * connect to a QUIC stream listener
 */
int
iperf_quic_connect(struct iperf_test *test)
{
#if defined(HAVE_QUIC_H)
    struct addrinfo hints, *local_res = NULL, *server_res = NULL;
    struct quic_transport_param param = {};
    struct quic_stream_info sinfo;
    int s, opt, saved_errno;
    unsigned int optlen;
    char portstr[6];

    if (test->bind_address) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = test->settings->domain;
        hints.ai_socktype = SOCK_STREAM;
        if ((gerror = getaddrinfo(test->bind_address, NULL, &hints, &local_res)) != 0) {
            i_errno = IESTREAMCONNECT;
            return -1;
        }
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = test->settings->domain;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", test->server_port);
    if ((gerror = getaddrinfo(test->server_hostname, portstr, &hints, &server_res)) != 0) {
	if (test->bind_address)
	    freeaddrinfo(local_res);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    s = socket(server_res->ai_family, SOCK_STREAM, IPPROTO_QUIC);
    if (s < 0) {
	freeaddrinfo(local_res);
	freeaddrinfo(server_res);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if ((opt = test->settings->socket_bufsize)) {
        int saved_errno;
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }

    if ((opt = test->settings->no_cryption)) {
        int saved_errno;
        param.disable_1rtt_encryption = opt;
        if (setsockopt(s, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IESENDPARAMS;
            return -1;
	}
    }

    /*
     * Various ways to bind the local end of the connection.
     * 1.  --bind (with or without --cport).
     */
    if (test->bind_address) {
        struct sockaddr_in *lcladdr;
        lcladdr = (struct sockaddr_in *)local_res->ai_addr;
        lcladdr->sin_port = htons(test->bind_port);

        if (bind(s, (struct sockaddr *) local_res->ai_addr, local_res->ai_addrlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(local_res);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESTREAMCONNECT;
            return -1;
        }
        freeaddrinfo(local_res);
    }
    /* --cport, no --bind */
    else if (test->bind_port) {
	size_t addrlen;
	struct sockaddr_storage lcl;

	/* IPv4 */
	if (server_res->ai_family == AF_INET) {
	    struct sockaddr_in *lcladdr = (struct sockaddr_in *) &lcl;
	    lcladdr->sin_family = AF_INET;
	    lcladdr->sin_port = htons(test->bind_port);
	    lcladdr->sin_addr.s_addr = INADDR_ANY;
	    addrlen = sizeof(struct sockaddr_in);
	}
	/* IPv6 */
	else if (server_res->ai_family == AF_INET6) {
	    struct sockaddr_in6 *lcladdr = (struct sockaddr_in6 *) &lcl;
	    lcladdr->sin6_family = AF_INET6;
	    lcladdr->sin6_port = htons(test->bind_port);
	    lcladdr->sin6_addr = in6addr_any;
	    addrlen = sizeof(struct sockaddr_in6);
	}
	/* Unknown protocol */
	else {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IEPROTOCOL;
            return -1;
	}

        if (bind(s, (struct sockaddr *) &lcl, addrlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESTREAMCONNECT;
            return -1;
        }
    }

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If socket pacing is specified try to enable it. */
    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */

    if (connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen) < 0 && errno != EINPROGRESS) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (quic_client_handshake(s, NULL, NULL, NULL)) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(server_res);
        errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    optlen = sizeof(sinfo);
    sinfo.stream_flags = 0;
    sinfo.stream_id = 0;
    if (getsockopt(s, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &optlen)) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(server_res);
        errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    /* Send cookie for verification */
    if (Nwrite(s, test->cookie, COOKIE_SIZE, Pquic) < 0) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
        i_errno = IESENDCOOKIE;
        return -1;
    }

    freeaddrinfo(server_res);
    return s;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}



int
iperf_quic_init(struct iperf_test *test)
{
#if defined(HAVE_QUIC_H)
    return 0;
#else
    i_errno = IENOQUIC;
    return -1;
#endif /* HAVE_QUIC_H */
}
