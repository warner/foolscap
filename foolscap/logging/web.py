
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
        ]

    optParameters = [
        ["port", "p", "tcp:0",
         "strports specification of where the web server should listen."],
        ]

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

FLOG_CSS = """
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

class Welcome(resource.Resource):
    def __init__(self, viewer):
        self.viewer = viewer
        resource.Resource.__init__(self)

    def render(self, req):
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
                 num_events, levels) = self.viewer.summaries[lf]
                if first_time and last_time:
                    duration = int(last_time - first_time)
                else:
                    duration = "?"
                if first_time is not None:
                    first_time = time.ctime(float(first_time))
                if last_time is not None:
                    last_time = time.ctime(float(last_time))

                data += ("  <li>%s events covering %s seconds</li>\n" %
                         (num_events, duration))
                data += ("  <li>from %s to %s</li>\n" %
                         (first_time, last_time))
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
                        href_base = "/all-events"
                        data += le.to_html(href_base)
                        data += "   </li>\n"
                    data += "  </ul>\n"
                    data += " </li>\n"
                data += " </ul>\n"
            data += "</ul>\n"
        else:
            data += "none!"

        data += '<h2><a href="all-events">View All Events</a></h2>\n'
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
            (first, last, num_events, levels) = self._viewer.summaries[lf]
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
        data = "<html>"
        data += "<head><title>Foolscap Log Viewer</title>\n"
        data += '<link href="flog.css" rel="stylesheet" type="text/css" />'
        data += "</head>\n"
        data += "<body>\n"
        data += "<h1>Event Log</h1>\n"

        data += "%d root events" % len(self.viewer.root_events)

        sortby = req.args.get("sort", ["nested"])[0]

        data += "<ul>\n"
        if sortby == "nested":
            for e in self.viewer.root_events:
                data += self._emit_events(0, e)
        elif sortby == "number":
            numbers = sorted(self.viewer.number_map.keys())
            for n in numbers:
                e = self.viewer.number_map[n]
                data += '<li><span class="%s">' % e.level_class()
                data += e.to_html()
                data += '</span></li>\n'
        elif sortby == "time":
            events = self.viewer.number_map.values()
            events.sort(lambda a,b: cmp(a.e['d']['time'], b.e['d']['time']))
            for e in events:
                data += '<li><span class="%s">' % e.level_class()
                data += e.to_html()
                data += '</span></li>\n'
        else:
            data += "<b>unknown sort argument '%s'</b>\n" % sortby

        data += "</ul>\n"
        req.setHeader("content-type", "text/html")
        return data

    def _emit_events(self, indent, event):
        indent_s = " " * indent
        data = (indent_s
                + '<li><span class="%s">' % event.level_class()
                + event.to_html()
                + "</span></li>\n"
                )
        if event.children:
            data += indent_s + "<ul>\n"
            for child in event.children:
                data += self._emit_events(indent+1, child)
            data += indent_s + "</ul>\n"
        return data


class LogEvent:
    def __init__(self, e):
        self.e = e
        self.parent = None
        self.children = []
        self.index = None
        if 'num' in e['d']:
            self.index = (e['from'], e['d']['num'])
            incarnation = base32.encode(e['d']['incarnation'][0])
            self.anchor_index = "%s_%s_%d" % (urllib.quote(e['from']),
                                              incarnation,
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

    def to_html(self, href_base=""):
        d = self.e['d']
        time_s = time.strftime("%H:%M:%S", time.localtime(d['time']))
        time_s = time_s + ".%03d" % int(1000*(d['time'] - int(d['time'])))
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
        data = '%s [<span id="E%s"><a href="%s#E%s">%d</a></span>]: %s%s' \
               % (time_s,
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
        req.redirect("welcome")
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
        welcome = Welcome(self)
        root.putChild("welcome", welcome)
        root.putChild("reload", Reload(self))
        root.putChild("all-events", EventView(self))
        root.putChild("summary", Summary(self))
        root.putChild("flog.css", static.Data(FLOG_CSS, "text/css"))
        s = server.Site(root)
        self.serv = strports.service(options['port'], s)
        self.serv.startService()
        portnum = self.serv._port.getHost().port
        # TODO: this makes all sort of assumptions: HTTP-vs-HTTPS, localhost.
        url = "http://localhost:%d/welcome" % portnum

        if not options["quiet"]:
            print "scanning.."
        self.logfiles = [options.dumpfile]
        self.load_logfiles()

        if not options["quiet"]:
            print "please point your browser at:"
            print url

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

            for e in self.get_events(lf):
                if "header" in e:
                    if e["header"]["type"] == "incident":
                        t = e["header"]["trigger"]
                        trigger_numbers.append(t["num"])
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
                        num_events, levels )
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

