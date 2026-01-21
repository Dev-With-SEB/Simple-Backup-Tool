# -*- coding: utf-8 -*-
from __future__ import print_function
import threading
import datetime

#from simpleLogger import get_logger
from . import simpleLogger


SCHEDULER_TICK_SEC = 10

class Scheduler(threading.Thread):
    daemon = True
    def __init__(self, get_config_fn, run_now_queue, stop_evt, schedulerReload, log=simpleLogger.get_logger()):
        threading.Thread.__init__(self, name="Scheduler")
        self.log = log
        self.next_run = None
        self.stop_evt = stop_evt
        self.get_config = get_config_fn
        self.run_now_queue = run_now_queue
        self.schedulerReload = schedulerReload


    def _compute_next(self, cfg, anchor_dt):
        """
        Compute next run after anchor_dt.
        Returns a datetime or None. Logs and defends against bad schedule output.
        """
        try:
            nxt = cfg.schedule.next_run_after(anchor_dt)
        except Exception as e:
            self.log.error("schedule.next_run_after error: {}".format(e))
            return None

        if nxt is None:
            self.log.verbose("Scheduler: schedule returned None for next_run_after({})".format(anchor_dt))
        return nxt


    def run(self):
        thread_name = threading.current_thread().name
        self.log.debug("Starting [{}] thread".format(thread_name))

        while not self.stop_evt.is_set():
            try:
                cfg = self.get_config()
                if not cfg:
                    self.log.verbose("Scheduler: no config; sleeping {}s".format(SCHEDULER_TICK_SEC))
                    self.stop_evt.wait(timeout=SCHEDULER_TICK_SEC)
                    continue

                # Full precision; we won’t floor seconds here
                now = datetime.datetime.now()
   #             now = datetime.datetime.now().replace(second=0, microsecond=0)                

                # Recompute on reload or first time
                with threading.Lock():
                    if self.schedulerReload or self.next_run is None:
                        if self.schedulerReload:
                            self.log.verbose("Scheduler: reload requested; recomputing schedule from now")
                            self.schedulerReload = False
                        self.next_run = self._compute_next(cfg, now)
                        self.log.verbose("Scheduler: next_run (recomputed) -> {}".format(self.next_run))

                # If due (now >= next_run), queue exactly one run and compute the next
                if self.next_run is not None and now >= self.next_run:
                    self.log.info("Scheduler: queueing RUN (due at {})".format(self.next_run))
                    self.run_now_queue.put("RUN")

                    # Compute next based on the due time we just satisfied
                    next_anchor = self.next_run
                    self.next_run = self._compute_next(cfg, next_anchor)

                    # Defensive bump if schedule returns same or earlier time
                    if self.next_run is not None and self.next_run <= next_anchor:
                        self.next_run = next_anchor + datetime.timedelta(minutes=1)
                        self.log.verbose("Scheduler: non-increasing next_run; nudged to {}".format(self.next_run))

                self.log.verbose("\nnow:      {}\nnext_run: {}".format(now, self.next_run))

            except Exception as e:
                import traceback
                self.log.error("Scheduler error: {}\n{}".format(e, traceback.format_exc()))

            self.stop_evt.wait(timeout=SCHEDULER_TICK_SEC)

        self.log.debug("Stopping [{}] thread...".format(thread_name))    
