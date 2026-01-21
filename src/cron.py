# -*- coding: utf-8 -*-
from __future__ import print_function
import datetime


from .simpleLogger import get_logger
# from . import simpleLogger


_CRON_MONTHS = dict((n, i+1) for i, n in enumerate(["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]))
_CRON_DOW = dict((n, i) for i, n in enumerate(["sun","mon","tue","wed","thu","fri","sat"]))

try:
    long
except NameError:
    long = int


def _parse_field(spec, minv, maxv, names=None):
    out = set()
    if isinstance(spec, (int, long)):
        return set([int(spec)])
    s = (spec or "*").strip().lower()

    def name_to_num(tok):
        if names and tok in names:
            return names[tok]
        return int(tok)

    for part in s.split(","):
        part = part.strip()
        if part == "*":
            rng = (minv, maxv)
            step = 1
        else:
            if "/" in part:
                base, step_s = part.split("/", 1)
                step = int(step_s)
            else:
                base, step = part, 1

            if base == "*":
                rng = (minv, maxv)
            elif "-" in base:
                a, b = base.split("-", 1)
                a = name_to_num(a)
                b = name_to_num(b)
                rng = (int(a), int(b))
            else:
                v = name_to_num(base)
                rng = (int(v), int(v))

        a, b = rng
        a = max(minv, a)
        b = min(maxv, b)
        for v in range(a, b + 1):
            if (v - a) % step == 0:
                out.add(v)
    return out


class CronSchedule(object):
    def __init__(self, cron_expr=None, weekly=None, monthly=None, daily=None, interval_minutes=None, log=get_logger()):
        self.log = log
        self.interval_minutes = None
        if cron_expr:
            self._from_cron(cron_expr)
        elif weekly:
            self._from_weekly(weekly)
        elif monthly:
            self._from_monthly(monthly)
        elif daily:
            self._from_daily(daily)
        elif interval_minutes:
            self.interval_minutes = max(1, int(interval_minutes))
        else:
            self._from_daily("02:00")

    def _from_cron(self, expr):
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError("Invalid cron expression (need 5 fields): %r" % expr)
        m_s, h_s, dom_s, mon_s, dow_s = parts
        self._minutes = _parse_field(m_s, 0, 59)
        self._hours = _parse_field(h_s, 0, 23)
        self._dom = _parse_field(dom_s, 1, 31)
        self._mon = _parse_field(mon_s, 1, 12, _CRON_MONTHS)
        dow_set = _parse_field(dow_s.replace("7", "0"), 0, 6, _CRON_DOW)
        self._dow = set([d % 7 for d in dow_set])
        self.interval_minutes = None

    def _from_weekly(self, weekly):
        runAt = weekly.get("runAt", "02:00")
        hh, mm = [int(x) for x in runAt.split(":")]
        self._minutes = set([mm])
        self._hours = set([hh])
        days = [d.lower()[:3] for d in weekly.get("days", ["mon"])]
        self._dom = set(range(1, 32))
        self._mon = set(range(1, 13))
        self._dow = set([_CRON_DOW[d] for d in days if d in _CRON_DOW])
        self.interval_minutes = None

    def _from_monthly(self, monthly):
        runAt = monthly.get("runAt", "02:00")
        hh, mm = [int(x) for x in runAt.split(":")]
        self._minutes = set([mm])
        self._hours = set([hh])
        doms = monthly.get("days", [1])
        self._dom = set(int(d) for d in doms)
        self._mon = set(range(1, 13))
        self._dow = set(range(0, 7))
        self.interval_minutes = None

    def _from_daily(self, daily):
        hh, mm = [int(x) for x in daily.split(":")]
        self._minutes = set([mm])
        self._hours = set([hh])
        self._dom = set(range(1, 31 + 1))
        self._mon = set(range(1, 12 + 1))
        self._dow = set(range(0, 7))
        self.interval_minutes = None

    def next_run_after(self, dt):
        self.log.verbose('dt: {}'.format(dt))
        if self.interval_minutes:
            return dt + datetime.timedelta(minutes=self.interval_minutes)
        probe = (dt + datetime.timedelta(minutes=1)).replace(second=0, microsecond=0)
        limit = dt + datetime.timedelta(days=400)
        while probe <= limit:
            if (probe.minute in self._minutes and
                probe.hour in self._hours and
                probe.day in self._dom and
                probe.month in self._mon and
                ((probe.weekday() + 1) % 7) in set((d + 1) % 7 for d in self._dow)):
                return probe
            probe += datetime.timedelta(minutes=1)
        return dt + datetime.timedelta(hours=24)
