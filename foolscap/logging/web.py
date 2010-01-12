
import pickle, time, urllib
from twisted.internet import reactor
from twisted.application import strports
from twisted.python import usage
from foolscap import base32
from foolscap.eventual import fireEventually
from foolscap.logging import log
from twisted.web import server, static, html, resource

class WebViewerOptions(usage.Options):
    synopsis = "Usage: flogtool web-viewer DUMPFILE.pickle"

    optFlags = [
        ("quiet", "q", "Don't print instructions to stdout"),
        ("open", "o", "Open the page in your webbrowser automatically"),
        ]

    optParameters = [
        ("port", "p", "tcp:0",
         "strports specification of where the web server should listen."),
        ("timestamps", "t", "local", "Default format for timestamps: local or utc"),
        ]

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

    def opt_timestamps(self, arg):
        if arg not in ("local", "utc"):
            raise usage.UsageError("--timestamps= must be one of 'local' or 'utc'")
        self["timestamps"] = arg

FLOG_CSS = """
span.MODELINE {
 font-size: 60%;
}
span.NOISY {
 color: #000080;
}
span.OPERATIONAL {
 color: #000000;
}
span.UNUSUAL {
 color: #000000;
 background-color: #ff8080;
}
span.INFREQUENT {
 color: #000000;
 background-color: #ff8080;
}
span.CURIOUS {
 color: #000000;
 background-color: #ff8080;
}
span.WEIRD {
 color: #000000;
 background-color: #ff4040;
}
span.SCARY {
 color: #000000;
 background-color: #ff4040;
}
span.BAD {
 color: #000000;
 background-color: #ff0000;
}

"""

def format_time(t, mode="local"):
    lt = time.localtime(t)
    gt = time.gmtime(t)
    if mode == "local":
        time_s = time.strftime("%H:%M:%S", lt)
        time_s = time_s + ".%03d" % int(1000*(t - int(t)))
    else:
        time_s = time.strftime("%H:%M:%S", gt)
        time_s = time_s + ".%03d" % int(1000*(t - int(t)))
        time_s += "Z"
    time_utc = time.strftime("%Y-%m-%d_%H:%M:%S", gt)
    microsecs_s = ".%06d" % int(1000000*(t - int(t)))
    time_utc = time_utc + microsecs_s
    time_utc += "Z"
    time_local = time.strftime("%Y-%m-%d_%H:%M:%S", lt)
    time_local = time_local + microsecs_s
    time_local += time.strftime("%z", lt)
    time_ctime = time.ctime(t).replace(" ", "&nbsp;")
    extended = "Local=%s  Local=%s  UTC=%s" % (time_ctime, time_local, time_utc)
    return time_s, extended

class Welcome(resource.Resource):
    def __init__(self, viewer, timestamps):
        self.viewer = viewer
        self.default_timestamps = timestamps
        resource.Resource.__init__(self)

    def fromto_time(self, t, timestamps):
        if t is None:
            return "?"
        ign, extended = format_time(float(t), timestamps)
        tz = time.strftime("%z", time.localtime(t))
        return '<span title="%s">%s (%s)</span>' % (extended, time.ctime(t), tz)

    def render(self, req):
        timestamps = self.default_timestamps
        data = "<html>"
        data += "<head><title>Foolscap Log Viewer</title></head>\n"
        data += "<body>\n"
        data += "<h1>Foolscap Log Viewer</h1>\n"

        data += "<h2>Logfiles:</h2>\n"
        if self.viewer.logfiles:
            data += "<ul>\n"
            for lfnum,lf in enumerate(self.viewer.logfiles):
                data += " <li>%s:\n" % html.escape(lf)
                data += " <ul>\n"
                ((first_number, first_time),
                 (last_number, last_time),
                 num_events, levels, pid, versions) = self.viewer.summaries[lf]
                data += "  <li>PID %s</li>\n" % html.escape(str(pid))
                if versions:
                    data += "  <li>Application Versions:\n"
                    data += "   <ul>\n"
                    for name in sorted(versions.keys()):
                        ver = versions[name]
                        data += "    <li>%s: %s</li>\n" % (html.escape(name),
                                                           html.escape(ver))
                    data += "   </ul>\n"
                    data += "  </li>\n"
                if first_time and last_time:
                    duration = int(last_time - first_time)
                else:
                    duration = "?"

                data += ("  <li>%s events covering %s seconds</li>\n" %
                         (num_events, duration))

                from_time_s = self.fromto_time(float(first_time), timestamps)
                to_time_s = self.fromto_time(float(last_time), timestamps)
                data += '  <li>from %s to %s</li>\n' % (from_time_s, to_time_s)
                for level in sorted(levels.keys()):
                    data += ('  <li><a href="summary/%d-%d">%d events</a> '
                             'at level %s</li>\n' %
                             (lfnum, level, len(levels[level]),
                              level))
                if self.viewer.triggers:
                    data += " <li>Incident Triggers:\n"
                    data += "  <ul>\n"
                    for t in self.viewer.triggers:
                        le = self.viewer.number_map[t]
                        data += "   <li>"
                        href_base = "/all-events?timestamps=%s" % timestamps
                        data += le.to_html(href_base, timestamps)
                        data += "   </li>\n"
                    data += "  </ul>\n"
                    data += " </li>\n"
                data += " </ul>\n"
            data += "</ul>\n"
        else:
            data += "none!"

        data += '<h2><a href="all-events?timestamps=%s">' % timestamps
        data += 'View All Events</a></h2>\n'
        data += '<form action="reload" method="post">\n'
        data += ' <input type="submit" value="Reload Logfile" />\n'
        data += '</form>\n'

        data += "</body></html>"
        req.setHeader("content-type", "text/html")
        return data

class Summary(resource.Resource):
    def __init__(self, viewer):
        self._viewer = viewer
        resource.Resource.__init__(self)

    def getChild(self, path, req):
        if "-" in path:
            lfnum,levelnum = map(int, path.split("-"))
            lf = self._viewer.logfiles[lfnum]
            (first, last, num_events, levels,
             pid, versions) = self._viewer.summaries[lf]
            events = levels[levelnum]
            return SummaryView(events, levelnum)
        return resource.Resource.getChild(self, path, req)

class SummaryView(resource.Resource):
    def __init__(self, events, levelnum):
        self._events = events
        self._levelnum = levelnum
        resource.Resource.__init__(self)

    def render(self, req):
        data = "<html>"
        data += "<head><title>Foolscap Log Viewer</title>\n"
        data += '<link href="flog.css" rel="stylesheet" type="text/css" />'
        data += "</head>\n"
        data += "<body>\n"
        data += "<h1>Events at level %d</h1>\n" % self._levelnum

        data += "<ul>\n"
        for e in self._events:
            data += "<li>" + e.to_html("/all-events") + "</li>\n"
        data += "</ul>\n"
        data += "</body>\n"
        data += "</html>\n"
        return data



class EventView(resource.Resource):
    def __init__(self, viewer):
        self.viewer = viewer
        resource.Resource.__init__(self)

    def render(self, req):
        sortby = req.args.get("sort", ["nested"])[0]
        timestamps = req.args.get("timestamps", ["local"])[0]

        data = "<html>"
        data += "<head><title>Foolscap Log Viewer</title>\n"
        data += '<link href="flog.css" rel="stylesheet" type="text/css" />'
        data += "</head>\n"
        data += "<body>\n"
        data += "<h1>Event Log</h1>\n"

        data += "%d root events " % len(self.viewer.root_events)

        url = "/all-events?sort=%s" % sortby
        other_timestamps = ['<a href="%s&timestamps=local">local</a>' % url,
                            '<a href="%s&timestamps=utc">utc</a>' % url]
        url = "/all-events?timestamps=%s" % timestamps
        other_sortby = ['<a href="%s&sort=nested">nested</a>' % url,
                        '<a href="%s&sort=number">number</a>' % url,
                        '<a href="%s&sort=time">time</a>' % url]
        modeline = ''.join(['<span class="MODELINE">',
                            'timestamps=%s ' % timestamps,
                            '(switch to %s) ' % ", ".join(other_timestamps),
                            'sort=%s ' % sortby,
                            '(switch to %s)' % ", ".join(other_sortby),
                            '</span>\n'])
        data += modeline

        data += "<ul>\n"
        if sortby == "nested":
            for e in self.viewer.root_events:
                data += self._emit_events(0, e, timestamps)
        elif sortby == "number":
            numbers = sorted(self.viewer.number_map.keys())
            for n in numbers:
                e = self.viewer.number_map[n]
                data += '<li><span class="%s">' % e.level_class()
                data += e.to_html(timestamps=timestamps)
                data += '</span></li>\n'
        elif sortby == "time":
            events = self.viewer.number_map.values()
            events.sort(lambda a,b: cmp(a.e['d']['time'], b.e['d']['time']))
            for e in events:
                data += '<li><span class="%s">' % e.level_class()
                data += e.to_html(timestamps=timestamps)
                data += '</span></li>\n'
        else:
            data += "<b>unknown sort argument '%s'</b>\n" % sortby

        data += "</ul>\n"
        req.setHeader("content-type", "text/html")
        return data

    def _emit_events(self, indent, event, timestamps):
        indent_s = " " * indent
        data = (indent_s
                + '<li><span class="%s">' % event.level_class()
                + event.to_html(timestamps=timestamps)
                + "</span></li>\n"
                )
        if event.children:
            data += indent_s + "<ul>\n"
            for child in event.children:
                data += self._emit_events(indent+1, child, timestamps)
            data += indent_s + "</ul>\n"
        return data


class LogEvent:
    def __init__(self, e):
        self.e = e
        self.parent = None
        self.children = []
        self.index = None
        self.anchor_index = "no-number"
        self.incarnation = base32.encode(e['d']['incarnation'][0])
        if 'num' in e['d']:
            self.index = (e['from'], e['d']['num'])
            self.anchor_index = "%s_%s_%d" % (urllib.quote(e['from']),
                                              self.incarnation,
                                              e['d']['num'])
        self.parent_index = None
        if 'parent' in e['d']:
            self.parent_index = (e['from'], e['d']['parent'])
        self.is_trigger = False

    LEVELMAP = {
        log.NOISY: "NOISY",
        log.OPERATIONAL: "OPERATIONAL",
        log.UNUSUAL: "UNUSUAL",
        log.INFREQUENT: "INFREQUENT",
        log.CURIOUS: "CURIOUS",
        log.WEIRD: "WEIRD",
        log.SCARY: "SCARY",
        log.BAD: "BAD",
        }

    def level_class(self):
        level = self.e['d'].get('level', log.OPERATIONAL)
        return self.LEVELMAP.get(level, "UNKNOWN")

    def to_html(self, href_base="", timestamps="local"):
        d = self.e['d']
        time_short, time_extended = format_time(d['time'], timestamps)
        msg = html.escape(log.format_message(d))
        if 'failure' in d:
            lines = str(d['failure']).split("\n")
            html_lines = [html.escape(line) for line in lines]
            f_html = "\n".join(html_lines)
            msg += " FAILURE:<pre>%s</pre>" % f_html
        level = d.get('level', log.OPERATIONAL)
        level_s = ""
        if level >= log.UNUSUAL:
            level_s = self.LEVELMAP.get(level, "") + " "
        details = "  ".join(["Event #%d" % d['num'],
                             "TubID=%s" % self.e['from'],
                             "Incarnation=%s" % self.incarnation,
                             time_extended])
        label = '<span title="%s">%s</span>' % (details, time_short)
        data = '%s [<span id="E%s"><a href="%s#E%s">%d</a></span>]: %s%s' \
               % (label,
                  self.anchor_index, href_base, self.anchor_index, d['num'],
                  level_s, msg)
        if self.is_trigger:
            data += " [INCIDENT-TRIGGER]"
        return data

class Reload(resource.Resource):

    def __init__(self, viewer):
        self.viewer = viewer
        resource.Resource.__init__(self)

    def render_POST(self, req):
        self.viewer.load_logfiles()
        req.redirect("/")
        return ''

class WebViewer:

    def run(self, options):
        d = fireEventually(options)
        d.addCallback(self.start)
        d.addErrback(self._error)
        print "starting.."
        reactor.run()

    def _error(self, f):
        print "ERROR", f
        reactor.stop()

    def start(self, options):
        root = static.Data("placeholder", "text/plain")
        welcome = Welcome(self, options["timestamps"])
        root.putChild("", welcome)
        root.putChild("welcome", welcome) # we used to only do this
        root.putChild("reload", Reload(self))
        root.putChild("all-events", EventView(self))
        root.putChild("summary", Summary(self))
        root.putChild("flog.css", static.Data(FLOG_CSS, "text/css"))
        s = server.Site(root)
        self.serv = strports.service(options['port'], s)
        self.serv.startService()
        portnum = self.serv._port.getHost().port
        # TODO: this makes all sort of assumptions: HTTP-vs-HTTPS, localhost.
        url = "http://localhost:%d/" % portnum

        if not options["quiet"]:
            print "scanning.."
        self.logfiles = [options.dumpfile]
        self.load_logfiles()

        if not options["quiet"]:
            print "please point your browser at:"
            print url
        if options["open"]:
            import webbrowser
            webbrowser.open(url)

        return url # for tests

    def load_logfiles(self):
        #self.summary = {} # keyed by logfile name
        (self.summaries,
         self.root_events,
         self.number_map,
         self.triggers) = self.process_logfiles(self.logfiles)

    def process_logfiles(self, logfiles):
        summaries = {}
        # build up a tree of events based upon parent/child relationships
        number_map = {}
        roots = []
        trigger_numbers = []
        first_event_from = None

        for lf in logfiles:
            (first_event_number, first_event_time) = (None, None)
            (last_event_number, last_event_time) = (None, None)
            num_events = 0
            levels = {}
            pid = None

            for e in self.get_events(lf):
                if "header" in e:
                    h = e["header"]
                    if h["type"] == "incident":
                        t = h["trigger"]
                        trigger_numbers.append(t["num"])
                    pid = h.get("pid")
                    versions = h.get("versions", {})
                if "d" not in e:
                    continue # skip headers
                if not first_event_from:
                    first_event_from = e['from']
                le = LogEvent(e)
                if le.index:
                    number_map[le.index] = le
                if le.parent_index in number_map:
                    le.parent = number_map[le.parent_index]
                    le.parent.children.append(le)
                else:
                    roots.append(le)
                d = e['d']
                level = d.get("level", "NORMAL")
                number = d.get("num", None)
                when = d.get("time")
                if number in trigger_numbers:
                    le.is_trigger = True

                if False:
                    # this is only meaningful if the logfile contains events
                    # from just a single tub and incarnation, but our current
                    # LogGatherer combines multiple processes' logs into a
                    # single file.
                    if first_event_number is None:
                        first_event_number = number
                    elif number is not None:
                        first_event_number = min(first_event_number, number)

                    if last_event_number is None:
                        last_event_number = number
                    elif number is not None:
                        last_event_number = max(last_event_number, number)

                if first_event_time is None:
                    first_event_time = when
                elif when is not None:
                    first_event_time = min(first_event_time, when)
                if last_event_time is None:
                    last_event_time = when
                elif when is not None:
                    last_event_time = max(last_event_time, when)

                num_events += 1
                if level not in levels:
                    levels[level] = []
                levels[level].append(le)

            summary = ( (first_event_number, first_event_time),
                        (last_event_number, last_event_time),
                        num_events, levels, pid, versions )
            summaries[lf] = summary

        triggers = [(first_event_from, num) for num in trigger_numbers]

        return summaries, roots, number_map, triggers

    def get_events(self, fn):
        if fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(fn, "r")
        else:
            f = open(fn, "rb")
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break
            except ValueError, ex:
                print "truncated pickle file? (%s): %s" % (fn, ex)
                break

