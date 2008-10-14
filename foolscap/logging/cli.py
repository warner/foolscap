
import sys
from StringIO import StringIO
from twisted.python import usage

import foolscap
from foolscap.logging.tail import TailOptions, LogTail
from foolscap.logging.gatherer import \
     CreateGatherOptions, create_log_gatherer, \
     CreateIncidentGatherOptions, create_incident_gatherer
from foolscap.logging.dumper import DumpOptions, LogDumper
from foolscap.logging.web import WebViewerOptions, WebViewer
from foolscap.logging.filter import FilterOptions, Filter
from foolscap.logging.incident import ClassifyOptions, IncidentClassifier

class Options(usage.Options):
    synopsis = "Usage: flogtool (tail|create-gatherer|dump|filter|web-viewer)"

    subCommands = [
        ("tail", None, TailOptions, "follow logs of the target node"),
        ("create-gatherer", None, CreateGatherOptions,
         "Make a .tac which will record all logs to a given directory"),
        ("create-incident-gatherer", None, CreateIncidentGatherOptions,
         "Make a .tac which will record all incidents to a given directory"),
        ("dump", None, DumpOptions,
         "dump the logs recorded by 'logtool gather'"),
        ("filter", None, FilterOptions,
         "produce a new file with a subset of the events from another file"),
        ("web-viewer", None, WebViewerOptions,
         "view the logs through a web page"),
        ("classify-incident", None, ClassifyOptions,
         "classify a stored Incident file"),
        ]

    def postOptions(self):
        if not hasattr(self, 'subOptions'):
            raise usage.UsageError("must specify a command")

    def opt_help(self):
        print self.synopsis
        sys.exit(0)

    def opt_version(self):
        from twisted import copyright
        print "Foolscap version:", foolscap.__version__
        print "Twisted version:", copyright.version
        sys.exit(0)


def dispatch(command, options):
    if command == "tail":
        lt = LogTail(options)
        lt.run(options.target_furl)

    elif command == "create-gatherer":
        create_log_gatherer(options)

    elif command == "create-incident-gatherer":
        create_incident_gatherer(options)

    elif command == "dump":
        ld = LogDumper()
        ld.run(options)

    elif command == "filter":
        f = Filter()
        f.run(options)

    elif command == "web-viewer":
        wv = WebViewer()
        wv.run(options)

    elif command == "classify-incident":
        ic = IncidentClassifier()
        ic.run(options)

    else:
        print "unknown command '%s'" % command
        raise NotImplementedError

def run_flogtool(argv=None, run_by_human=True):
    if argv:
        command_name = argv[0]
    else:
        command_name = sys.argv[0]
    config = Options()
    try:
        config.parseOptions(argv)
    except usage.error, e:
        if not run_by_human:
            raise
        print "%s:  %s" % (command_name, e)
        print
        c = getattr(config, 'subOptions', config)
        print str(c)
        sys.exit(1)

    command = config.subCommand
    so = config.subOptions
    if not run_by_human:
        so.stdout = StringIO()
        so.stderr = StringIO()
    dispatch(command, so)
    if not run_by_human:
        return (so.stdout.getvalue(), so.stderr.getvalue())
