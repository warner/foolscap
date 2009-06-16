
import os.path
from StringIO import StringIO
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap.api import Tub
from foolscap.appserver import cli, server
from foolscap.test.common import ShouldFailMixin, crypto_available

class RequiresCryptoBase:
    def setUp(self):
        if not crypto_available:
            raise unittest.SkipTest("crypto not available")

class CLI(RequiresCryptoBase, unittest.TestCase):
    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_create(self):
        basedir = "appserver/CLI/create"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        return d

    def test_create_no_clobber_dir(self):
        basedir = "appserver/CLI/create_no_clobber_dir"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        os.mkdir(serverdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 1)
            self.failUnlessIn("Refusing to touch pre-existing directory", err)
            self.failIf(os.path.exists(os.path.join(serverdir, "port")))
            self.failIf(os.path.exists(os.path.join(serverdir, "services")))
        d.addCallback(_check)
        return d

    def test_create2(self):
        basedir = "appserver/CLI/create2"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", "--port", "tcp:0", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
            got_port = open(os.path.join(serverdir, "port"), "r").read().strip()
            self.failIfEqual(got_port, "tcp:0") # it should pick a real port
            portnum = int(got_port[got_port.find(":")+1:])
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.failUnless(prefix.endswith(":%d/" % portnum), prefix)
        d.addCallback(_check)
        return d

    def test_create3(self):
        basedir = "appserver/CLI/create3"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", "--location", "proxy.example.com:12345",
                         serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
            # pick an arbitrary port, but FURLs should reference the proxy
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.failUnless(prefix.endswith("@proxy.example.com:12345/"), prefix)
        d.addCallback(_check)
        return d

    def test_create4(self):
        basedir = "appserver/CLI/create4"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", "--port", "0", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
            got_port = open(os.path.join(serverdir, "port"), "r").read().strip()
            self.failIfEqual(got_port, "tcp:0") # it should pick a real port
            portnum = int(got_port[got_port.find(":")+1:])
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.failUnless(prefix.endswith(":%d/" % portnum), prefix)
        d.addCallback(_check)
        return d

    def test_add(self):
        basedir = "appserver/CLI/add"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            lines = out.splitlines()
            self.failUnless(lines[0].startswith("Service added in "))
            servicedir = lines[0].split()[-1]
            self.failUnless(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            swiss = furl[furl.rfind("/")+1:]
            servicedir2 = os.path.join(serverdir, "services", swiss)
            self.failUnlessEqual(os.path.abspath(servicedir),
                                 os.path.abspath(servicedir2))
        d.addCallback(_check_add)
        return d

    def test_add_comment(self):
        basedir = "appserver/CLI/add_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               "--comment", "commentary here",
                                               serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            lines = out.splitlines()
            self.failUnless(lines[0].startswith("Service added in "))
            servicedir = lines[0].split()[-1]
            self.failUnless(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            swiss = furl[furl.rfind("/")+1:]
            servicedir2 = os.path.join(serverdir, "services", swiss)
            self.failUnlessEqual(os.path.abspath(servicedir),
                                 os.path.abspath(servicedir2))
            comment = open(os.path.join(servicedir, "comment")).read().strip()
            self.failUnlessEqual(comment, "commentary here")
        d.addCallback(_check_add)
        return d

    def test_add_badargs(self):
        basedir = "appserver/CLI/add_badargs"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        servicesdir = os.path.join(serverdir, "services")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               serverdir,
                                               "file-uploader",
                                               # missing targetdir
                                               ))
        def _check_add((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("Error", err)
            self.failUnlessIn("Wrong number of arguments", err)
            self.failUnlessEqual(os.listdir(servicesdir), [])
        d.addCallback(_check_add)

        d.addCallback(lambda ign: self.run_cli("add",
                                               serverdir,
                                               "file-uploader",
                                               "nonexistent-targetdir",
                                               ))
        def _check_add2((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("Error", err)
            self.failUnlessIn("targetdir ", err)
            self.failUnlessIn(" must already exist", err)
            self.failUnlessEqual(os.listdir(servicesdir), [])
        d.addCallback(_check_add2)
        return d

    def test_list(self):
        basedir = "appserver/CLI/list"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        servicesdir = os.path.join(serverdir, "services")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
        d.addCallback(_check_add)
        d.addCallback(lambda ign: self.run_cli("list", serverdir))
        def _check_list((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            services = os.listdir(servicesdir)
            self.failUnlessEqual(len(services), 1)
            swissnum = services[0]
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            expected_furl = prefix + swissnum
            lines = out.splitlines()
            self.failUnlessEqual(lines[0], "")
            self.failUnlessEqual(lines[1], swissnum+":")
            self.failUnlessEqual(lines[2], " file-uploader %s" % incomingdir)
            self.failUnlessEqual(lines[3], " " + expected_furl)
        d.addCallback(_check_list)
        return d

    def test_list_comment(self):
        basedir = "appserver/CLI/list_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        servicesdir = os.path.join(serverdir, "services")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               "--comment", "commentary here",
                                               serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
        d.addCallback(_check_add)
        d.addCallback(lambda ign: self.run_cli("list", serverdir))
        def _check_list((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            services = os.listdir(servicesdir)
            self.failUnlessEqual(len(services), 1)
            swissnum = services[0]
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            expected_furl = prefix + swissnum
            lines = out.splitlines()
            self.failUnlessEqual(lines[0], "")
            self.failUnlessEqual(lines[1], swissnum+":")
            self.failUnlessEqual(lines[2], " file-uploader %s" % incomingdir)
            self.failUnlessEqual(lines[3], " # commentary here")
            self.failUnlessEqual(lines[4], " " + expected_furl)
        d.addCallback(_check_list)
        return d

class Server(RequiresCryptoBase, unittest.TestCase, ShouldFailMixin):
    def setUp(self):
        RequiresCryptoBase.setUp(self)
        self.s = service.MultiService()
        self.s.startService()
    def tearDown(self):
        return self.s.stopService()

    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_run(self):
        basedir = "appserver/Server/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)

        self.tub = Tub()
        self.tub.setServiceParent(self.s)
        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            lines = out.splitlines()
            self.failUnless(lines[1].startswith("FURL is pb://"))
            self.furl = lines[1].split()[-1]
        d.addCallback(_check_add)
        stdout = StringIO()
        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)
            return ap.when_ready()
        d.addCallback(_start_server)
        # make sure the server can actually instantiate a service
        d.addCallback(lambda _ign: self.tub.getReference(self.furl))
        def _got_rref(rref):
            # great!
            pass
        d.addCallback(_got_rref)
        d.addCallback(lambda ign:
                      self.shouldFail(KeyError, "getReference(bogus)",
                                      "unable to find reference for name ",
                                      self.tub.getReference,
                                      self.furl+".bogus"))
        return d
    

class Upload(RequiresCryptoBase, unittest.TestCase, ShouldFailMixin):
    def setUp(self):
        RequiresCryptoBase.setUp(self)
        self.s = service.MultiService()
        self.s.startService()
    def tearDown(self):
        return self.s.stopService()

    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(cli.run_flappclient, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_run(self):
        basedir = "appserver/Upload/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        furlfile = os.path.join(basedir, "furlfile")

        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "file-uploader", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            lines = out.splitlines()
            self.failUnless(lines[1].startswith("FURL is pb://"))
            self.furl = lines[1].split()[-1]
            f = open(furlfile,"w")
            f.write("\n") # it should ignore blank lines
            f.write("# it should ignore comments like this\n")
            f.write(self.furl+"\n")
            f.write("# and it should only pay attention to the first FURL\n")
            f.write(self.furl+".bogus\n")
            f.close()
        d.addCallback(_check_add)
        stdout = StringIO()
        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)
            return ap.when_ready()
        d.addCallback(_start_server)

        sourcefile = os.path.join(basedir, "foo.txt")
        f = open(sourcefile, "wb")
        DATA = "This is some source text.\n"
        f.write(DATA)
        f.close()
        d.addCallback(lambda _ign: self.run_client("--furl", self.furl,
                                                   "upload",
                                                   sourcefile))
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), "File uploaded")
            self.failUnlessEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "foo.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA)
        d.addCallback(_check_client)

        sourcefile2 = os.path.join(basedir, "bar.txt")
        f = open(sourcefile2, "wb")
        DATA2 = "This is also some source text.\n"
        f.write(DATA2)
        f.close()
        d.addCallback(lambda _ign: self.run_client("--furlfile", furlfile,
                                                   "upload",
                                                   sourcefile2))
        def _check_client2((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), "File uploaded")
            self.failUnlessEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "bar.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA2)
        d.addCallback(_check_client2)

        empty_furlfile = furlfile + ".empty"
        open(empty_furlfile, "wb").close()
        d.addCallback(lambda _ign: self.run_client("--furlfile", empty_furlfile,
                                                   "upload",
                                                   sourcefile2))
        def _check_client3((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("must provide --furl or --furlfile", err.strip())
        d.addCallback(_check_client3)

        return d
    
class Client(unittest.TestCase):

    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(cli.run_flappclient, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_no_command(self):
        d = self.run_client()
        def _check_client1((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("must provide --furl or --furlfile", err)
        d.addCallback(_check_client1)

        d.addCallback(lambda _ign: self.run_client("--furl", "foo"))
        def _check_client2((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("must specify a command", err)
        d.addCallback(_check_client2)
        return d

    def OFF_test_help(self):
        d = self.run_client("--help")
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("XXX", out)
            self.failUnlessEqual("", err.strip())
        d.addCallback(_check_client)
        return d

    def OFF_test_version(self):
        d = self.run_client("--version")
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("Foolscap version:", out)
            self.failUnlessEqual("", err.strip())
        d.addCallback(_check_client)
        return d
