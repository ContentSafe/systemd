/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "systemd/sd-messages.h"
#include "socket-util.h"
#include "selinux-util.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-kmsg.h"
#include "journald-console.h"
#include "journald-wall.h"

/* Warn once every 30s if we missed syslog message */
#define WARN_FORWARD_SYSLOG_MISSED_USEC (30 * USEC_PER_SEC)

static void forward_syslog_iovec(Server *s, const struct iovec *iovec, unsigned n_iovec, const struct ucred *ucred, const struct timeval *tv) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/syslog",
        };
        struct msghdr msghdr = {
                .msg_iov = (struct iovec *) iovec,
                .msg_iovlen = n_iovec,
                .msg_name = (struct sockaddr*) &sa.sa,
                .msg_namelen = offsetof(union sockaddr_union, un.sun_path)
                               + strlen("/run/systemd/journal/syslog"),
        };
        struct cmsghdr *cmsg;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control;

        assert(s);
        assert(iovec);
        assert(n_iovec > 0);

        if (ucred) {
                zero(control);
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&msghdr);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));
                msghdr.msg_controllen = cmsg->cmsg_len;
        }

        /* Forward the syslog message we received via /dev/log to
         * /run/systemd/syslog. Unfortunately we currently can't set
         * the SO_TIMESTAMP auxiliary data, and hence we don't. */

        if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return;

        /* The socket is full? I guess the syslog implementation is
         * too slow, and we shouldn't wait for that... */
        if (errno == EAGAIN) {
                s->n_forward_syslog_missed++;
                return;
        }

        if (ucred && (errno == ESRCH || errno == EPERM)) {
                struct ucred u;

                /* Hmm, presumably the sender process vanished
                 * by now, or we don't have CAP_SYS_AMDIN, so
                 * let's fix it as good as we can, and retry */

                u = *ucred;
                u.pid = getpid();
                memcpy(CMSG_DATA(cmsg), &u, sizeof(struct ucred));

                if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                        return;

                if (errno == EAGAIN) {
                        s->n_forward_syslog_missed++;
                        return;
                }
        }

        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to forward syslog message: %m");
}

static int maybe_open_remote_syslog(Server *s) {
        int fd;

        assert(s);

        if (s->remote_syslog_fd > 0) return s->remote_syslog_fd;

        if (s->remote_syslog_dest.in.sin_addr.s_addr == INADDR_NONE) {
                return 0;
        } else {
                log_warning("remote syslog forwarding target configured: %s",
                                inet_ntoa(s->remote_syslog_dest.in.sin_addr));
        }
        if (s->remote_syslog_dest.in.sin_family != AF_INET) { // set in config
                log_warning("non AF_INET target for remote syslog forwarding configured. ignoring.");
                return 0;
        }

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error("socket() failed for remote syslog forwarding: %m");
                return 0;
        } else {
                s->remote_syslog_fd = fd;
        }

        return s->remote_syslog_fd;
}

static void forward_remote_syslog_iovec(Server *s, const struct iovec *iovec, unsigned n_iovec) {
        int fd;
        assert(s);
        assert(iovec);

        fd = maybe_open_remote_syslog(s);
        if (!fd) return;
        struct msghdr msghdr = {
                .msg_iov = (struct iovec *) iovec,
                .msg_iovlen = n_iovec,
                .msg_name = (struct sockaddr*) &s->remote_syslog_dest,
                .msg_namelen = sizeof(s->remote_syslog_dest),
        };
        sendmsg(fd, &msghdr, MSG_NOSIGNAL);
        // this might fail and indeed, we do ignore it
        // (logging shall not wait for network to become available)
}

static void forward_syslog_raw(Server *s, int priority, const char *buffer, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec;

        assert(s);
        assert(buffer);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        IOVEC_SET_STRING(iovec, buffer);
        forward_syslog_iovec(s, &iovec, 1, ucred, tv);
}

static int syslog_fill_iovec(SyslogMessage *sm, struct iovec *iovec, unsigned *n_iovec) {
        enum rfc5424 {PRIVER=0, TIMESTAMP, HOSTNAME, SP_HOSTNAME, APPNAME, SP_APPNAME, PROCID, MSGID, STRUDATA, MSG};
        int offset;

        if (*n_iovec < MSG+1) return -1;
        assert(sm);
        /* valid rfc5424 range of prioriy is 0..191
         * (3 bit severity from 0 to 7;
         *  5 bit facility from 0 to 23)
         */
        if (sm->priority>>3>23)
                sm->priority = (sm->priority&7) + (23<<3); /* limit facility to 0..23 */

        /* priority and version */
        zero(sm->_priver);
        sprintf(sm->_priver, "<%i>1 ", sm->priority);
        IOVEC_SET_STRING(iovec[PRIVER], sm->_priver);

        /* timestamp */
        if (strftime(sm->_timestamp, sizeof(sm->_timestamp), "%Y-%m-%dT%H:%M:%S%z ", &sm->timestamp) <= 0) {
                IOVEC_SET_STRING(iovec[TIMESTAMP], "- ");
        } else {
                IOVEC_SET_STRING(iovec[TIMESTAMP], sm->_timestamp);
        }

        offset = 0;
        if (strncmp("_HOSTNAME=", sm->hostname, 10) == 0) offset = 10;
        IOVEC_SET_STRING(iovec[HOSTNAME], sm->hostname+offset);
        IOVEC_SET_STRING(iovec[SP_HOSTNAME], " ");
        IOVEC_SET_STRING(iovec[APPNAME], sm->appname);
        IOVEC_SET_STRING(iovec[SP_APPNAME], " ");

        if (sm->procid) {
                snprintf(sm->_procid, sizeof(sm->_procid), "["PID_FMT"]: ", sm->procid);
                char_array_0(sm->_procid);
        } else {
                sprintf(sm->_procid, "- ");
        }
        IOVEC_SET_STRING(iovec[PROCID], sm->_procid);

        IOVEC_SET_STRING(iovec[MSGID], sm->msgid);
        IOVEC_SET_STRING(iovec[STRUDATA], " - ");

        IOVEC_SET_STRING(iovec[MSG], sm->message);
        *n_iovec = MSG+1;
        return *n_iovec;
}

static void syslog_init_message(SyslogMessage *sm) {
        /* some parts of a rfc5424 syslog message may
         * be carry a "-" if respective data is n/a.
         */
        sm->priority = 14;
        sm->procid = 0;
        sm->hostname =
        sm->appname =
        sm->msgid =
        sm->message = "-";
}

void server_forward_syslog(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec[10];
        int n = 0;
        time_t t;
        char *ident_buf = NULL;
        SyslogMessage sm;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        syslog_init_message(&sm);

        /* First: priority field and VERSION */
        sm.priority = priority;

        /* Second: timestamp */
        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        if (!localtime_r(&t, &sm.timestamp))
                return;
        if (!isempty(s->hostname_field))
                sm.hostname = s->hostname_field;

        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                sm.procid = ucred->pid;
        }

        if (identifier) sm.appname = identifier;

        sm.message = message;

        /* fill iovec from SyslogMessage struct */
        n = sizeof(iovec)/sizeof(struct iovec);
        if (syslog_fill_iovec(&sm, (struct iovec*)iovec, &n) <= 0)
                return;

        if (s->forward_to_syslog)
                forward_syslog_iovec(s, iovec, n, ucred, tv);

        if (s->forward_to_remote_syslog)
                forward_remote_syslog_iovec(s, iovec, n);

        free(ident_buf);
}

int syslog_fixup_facility(int priority) {

        if ((priority & LOG_FACMASK) == 0)
                return (priority & LOG_PRIMASK) | LOG_USER;

        return priority;
}

size_t syslog_parse_identifier(const char **buf, char **identifier, char **pid) {
        const char *p;
        char *t;
        size_t l, e;

        assert(buf);
        assert(identifier);
        assert(pid);

        p = *buf;

        p += strspn(p, WHITESPACE);
        l = strcspn(p, WHITESPACE);

        if (l <= 0 ||
            p[l-1] != ':')
                return 0;

        e = l;
        l--;

        if (p[l-1] == ']') {
                size_t k = l-1;

                for (;;) {

                        if (p[k] == '[') {
                                t = strndup(p+k+1, l-k-2);
                                if (t)
                                        *pid = t;

                                l = k;
                                break;
                        }

                        if (k == 0)
                                break;

                        k--;
                }
        }

        t = strndup(p, l);
        if (t)
                *identifier = t;

        e += strspn(p + e, WHITESPACE);
        *buf = p + e;
        return e;
}

static void syslog_skip_date(char **buf) {
        enum {
                LETTER,
                SPACE,
                NUMBER,
                SPACE_OR_NUMBER,
                COLON
        } sequence[] = {
                LETTER, LETTER, LETTER,
                SPACE,
                SPACE_OR_NUMBER, NUMBER,
                SPACE,
                SPACE_OR_NUMBER, NUMBER,
                COLON,
                SPACE_OR_NUMBER, NUMBER,
                COLON,
                SPACE_OR_NUMBER, NUMBER,
                SPACE
        };

        char *p;
        unsigned i;

        assert(buf);
        assert(*buf);

        p = *buf;

        for (i = 0; i < ELEMENTSOF(sequence); i++, p++) {

                if (!*p)
                        return;

                switch (sequence[i]) {

                case SPACE:
                        if (*p != ' ')
                                return;
                        break;

                case SPACE_OR_NUMBER:
                        if (*p == ' ')
                                break;

                        /* fall through */

                case NUMBER:
                        if (*p < '0' || *p > '9')
                                return;

                        break;

                case LETTER:
                        if (!(*p >= 'A' && *p <= 'Z') &&
                            !(*p >= 'a' && *p <= 'z'))
                                return;

                        break;

                case COLON:
                        if (*p != ':')
                                return;
                        break;

                }
        }

        *buf = p;
}

void server_process_syslog_message(
        Server *s,
        const char *buf,
        const struct ucred *ucred,
        const struct timeval *tv,
        const char *label,
        size_t label_len) {

        char syslog_priority[sizeof("PRIORITY=") + DECIMAL_STR_MAX(int)],
             syslog_facility[sizeof("SYSLOG_FACILITY") + DECIMAL_STR_MAX(int)];
        const char *message = NULL, *syslog_identifier = NULL, *syslog_pid = NULL;
        struct iovec iovec[N_IOVEC_META_FIELDS + 6];
        unsigned n = 0;
        int priority = LOG_USER | LOG_INFO;
        _cleanup_free_ char *identifier = NULL, *pid = NULL;
        time_t t;
        SyslogMessage sm;

        assert(s);
        assert(buf);

        syslog_init_message(&sm);

        if (!isempty(s->hostname_field))
                sm.hostname = s->hostname_field;

        syslog_parse_priority(&buf, &priority, true);

        syslog_skip_date((char**) &buf);
        syslog_parse_identifier(&buf, &identifier, &pid);

        if (s->forward_to_kmsg)
                server_forward_kmsg(s, priority, identifier, buf, ucred);

        if (s->forward_to_console)
                server_forward_console(s, priority, identifier, buf, ucred);

        if (s->forward_to_wall)
                server_forward_wall(s, priority, identifier, buf, ucred);

        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=syslog");

        sprintf(syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK);
        IOVEC_SET_STRING(iovec[n++], syslog_priority);
        sm.priority = priority;

        if (priority & LOG_FACMASK) {
                sprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                IOVEC_SET_STRING(iovec[n++], syslog_facility);
        }

        if (identifier) {
                syslog_identifier = strjoina("SYSLOG_IDENTIFIER=", identifier);
                if (syslog_identifier)
                        IOVEC_SET_STRING(iovec[n++], syslog_identifier);
                sm.appname = identifier;
        }

        if (pid) {
                syslog_pid = strjoina("SYSLOG_PID=", pid);
                if (syslog_pid)
                        IOVEC_SET_STRING(iovec[n++], syslog_pid);
                if (parse_pid(pid, &sm.procid))
                        sm.procid = 0;
        }

        message = strjoina("MESSAGE=", buf);
        if (message) {
                IOVEC_SET_STRING(iovec[n++], message);
                sm.message = buf;
        }

        server_dispatch_message(s, iovec, n, ELEMENTSOF(iovec), ucred, tv, label, label_len, NULL, priority, 0);

        /* timestamp for SyslogMessage struct: */
        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        if (!localtime_r(&t, &sm.timestamp))
                return;

        /* fill iovec from SyslogMessage struct */
        n = sizeof(iovec)/sizeof(struct iovec);
        if (syslog_fill_iovec(&sm, (struct iovec*)iovec, &n) <= 0)
                return;

        if (s->forward_to_syslog)
                forward_syslog_iovec(s, iovec, n, ucred, tv);
                /* TODO: decision between raw and rewritten rfc5424
                 * should be configurable
                 * forward_syslog_raw(s, priority, orig, ucred, tv);
                 */

        if (s->forward_to_remote_syslog)
                forward_remote_syslog_iovec(s, iovec, n);

}

int server_open_syslog_socket(Server *s) {
        static const int one = 1;
        int r;

        assert(s);

        if (s->syslog_fd < 0) {
                static const union sockaddr_union sa = {
                        .un.sun_family = AF_UNIX,
                        .un.sun_path = "/run/systemd/journal/dev-log",
                };

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->syslog_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                unlink(sa.un.sun_path);

                r = bind(s->syslog_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                chmod(sa.un.sun_path, 0666);
        } else
                fd_nonblock(s->syslog_fd, 1);

        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_PASSCRED failed: %m");

#ifdef HAVE_SELINUX
        if (mac_selinux_use()) {
                r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));
                if (r < 0)
                        log_warning_errno(errno, "SO_PASSSEC failed: %m");
        }
#endif

        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_TIMESTAMP failed: %m");

        r = sd_event_add_io(s->event, &s->syslog_event_source, s->syslog_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add syslog server fd to event loop: %m");

        return 0;
}

void server_maybe_warn_forward_syslog_missed(Server *s) {
        usec_t n;
        assert(s);

        if (s->n_forward_syslog_missed <= 0)
                return;

        n = now(CLOCK_MONOTONIC);
        if (s->last_warn_forward_syslog_missed + WARN_FORWARD_SYSLOG_MISSED_USEC > n)
                return;

        server_driver_message(s, SD_MESSAGE_FORWARD_SYSLOG_MISSED, "Forwarding to syslog missed %u messages.", s->n_forward_syslog_missed);

        s->n_forward_syslog_missed = 0;
        s->last_warn_forward_syslog_missed = n;
}
