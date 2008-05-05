
import sys
from twisted.python import usage

import foolscap
from foolscap.logging.tail import TailOptions
from foolscap.logging.gatherer import CreateGatherOptions
from foolscap.logging.dumper import DumpOptions
from foolscap.logging.web import WebViewerOptions
from foolscap.logging.filter import FilterOptions

class Options(usage.Options):
    synopsis = "Usage: flogtool (tail|create-gatherer|dump|filter|web-viewer)"

    subCommands = [
        ("tail", None, TailOptions, "follow logs of the target node"),
        ("create-gatherer", None, CreateGatherOptions,
         "Make a .tac which will record all logs to a given directory"),
        ("dump", None, DumpOptions,
         "dump the logs recorded by 'logtool gather'"),
        ("filter", None, FilterOptions,
         "produce a new file with a subset of the events from another file"),
        ("web-viewer", None, WebViewerOptions,
         "view the logs through a web page"),
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
        from foolscap.logging.tail import LogTail
        lt = LogTail(options)
        lt.run(options.target_furl)

    elif command == "create-gatherer":
        from foolscap.logging.gatherer import create_log_gatherer
        create_log_gatherer(options)

    elif command == "dump":
        from foolscap.logging.dumper import LogDumper
        ld = LogDumper()
        ld.run(options)

    elif command == "filter":
        from foolscap.logging.filter import Filter
        f = Filter()
        f.run(options)

    elif command == "web-viewer":
        from foolscap.logging.web import WebViewer
        wv = WebViewer()
        wv.run(options)

    else:
        print "unknown command '%s'" % command
        raise NotImplementedError

def run_flogtool(argv=sys.argv, run_by_human=True):
    config = Options()
    try:
        config.parseOptions(argv)
    except usage.error, e:
        if not run_by_human:
            raise
        print "%s:  %s" % (argv[0], e)
        print
        c = getattr(config, 'subOptions', config)
        print str(c)
        sys.exit(1)

    command = config.subCommand
    so = config.subOptions
    dispatch(command, so)
