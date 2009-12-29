
import os.path
from StringIO import StringIO
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap.api import Tub, eventually
from foolscap.appserver import cli, server, client
from foolscap.test.common import ShouldFailMixin, crypto_available, StallMixin

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
            # check that the directory is group/world-inaccessible, even on
            # windows where those concepts are pretty fuzzy. Do this by
            # making sure the mode doesn't change when we chmod it again.
            mode1 = os.stat(serverdir).st_mode
            os.chmod(serverdir, 0700)
            mode2 = os.stat(serverdir).st_mode
            self.failUnlessEqual("%o" % mode1, "%o" % mode2)
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
        d = self.run_cli("create", "--port","tcp:0", "--umask","022", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
            got_port = open(os.path.join(serverdir, "port"), "r").read().strip()
            self.failIfEqual(got_port, "tcp:0") # it should pick a real port
            portnum = int(got_port[got_port.find(":")+1:])
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.failUnless(prefix.endswith(":%d/" % portnum), prefix)
            umask = open(os.path.join(serverdir, "umask")).read().strip()
            self.failUnlessEqual(umask, "0022")
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
                                               "upload-file", incomingdir))
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
                                               "upload-file", incomingdir))
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
                                               "upload-file",
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
                                               "upload-file",
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
                                               "upload-file", incomingdir))
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
            self.failUnlessEqual(lines[2], " upload-file %s" % incomingdir)
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
                                               "upload-file", incomingdir))
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
            self.failUnlessEqual(lines[2], " upload-file %s" % incomingdir)
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
                                               "upload-file", incomingdir))
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
        d = defer.maybeDeferred(client.run_flappclient, argv=argv, run_by_human=False)
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
                                               "upload-file", incomingdir))
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
                                                   "upload-file",
                                                   sourcefile))
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), "foo.txt: uploaded")
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
                                                   "upload-file",
                                                   sourcefile2))
        def _check_client2((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), "bar.txt: uploaded")
            self.failUnlessEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "bar.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA2)
        d.addCallback(_check_client2)

        empty_furlfile = furlfile + ".empty"
        open(empty_furlfile, "wb").close()
        d.addCallback(lambda _ign: self.run_client("--furlfile", empty_furlfile,
                                                   "upload-file",
                                                   sourcefile2))
        def _check_client3((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessIn("must provide --furl or --furlfile", err.strip())
        d.addCallback(_check_client3)

        sourcefile3 = os.path.join(basedir, "file3.txt")
        f = open(sourcefile3, "wb")
        DATA3 = "file number 3\n"
        f.write(DATA3)
        f.close()

        sourcefile4 = os.path.join(basedir, "file4.txt")
        f = open(sourcefile4, "wb")
        DATA4 = "file number 4\n"
        f.write(DATA4)
        f.close()

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furl, "upload-file",
                                      sourcefile3, sourcefile4))
        def _check_client4((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("file3.txt: uploaded", out)
            self.failUnlessIn("file4.txt: uploaded", out)
            self.failUnlessEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "file3.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA3)
            fn = os.path.join(incomingdir, "file4.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA4)
        d.addCallback(_check_client4)

        return d
    
class Client(unittest.TestCase):

    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(client.run_flappclient, argv=argv, run_by_human=False)
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

    def test_help(self):
        d = self.run_client("--help")
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("Usage: flappclient [--furl=|--furlfile=] ", out)
            self.failUnlessEqual("", err.strip())
        d.addCallback(_check_client)
        return d

    def test_version(self):
        d = self.run_client("--version")
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("Foolscap version:", out)
            self.failUnlessEqual("", err.strip())
        d.addCallback(_check_client)
        return d

class RunCommand(unittest.TestCase, RequiresCryptoBase, StallMixin):
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
        d = defer.maybeDeferred(client.run_flappclient,
                                argv=argv, run_by_human=False,
                                stdio=None)
        return d # fires with (rc,out,err)

    def run_client_with_stdin(self, stdin, *args):
        argv = ["flappclient"] + list(args)
        def my_stdio(proto):
            eventually(proto.connectionMade)
            eventually(proto.dataReceived, stdin)
            eventually(proto.connectionLost, None)
        d = defer.maybeDeferred(client.run_flappclient,
                                argv=argv, run_by_human=False,
                                stdio=my_stdio)
        return d # fires with (rc,out,err)

    def add(self, serverdir, *args):
        d = self.run_cli("add", serverdir, *args)
        def _get_furl((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            lines = out.splitlines()
            self.failUnless(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            return furl
        d.addCallback(_get_furl)
        return d

    def stash_furl(self, furl, which):
        self.furls[which] = furl

    def test_run(self):
        basedir = "appserver/RunCommand/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        self.furls = {}

        d = self.run_cli("create", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        targetfile = os.path.join(incomingdir, "foo.txt")
        DATA = "Contents of foo.txt.\n"

        def _populate_foo(ign):
            f = open(targetfile, "wb")
            f.write(DATA)
            f.close()
        d.addCallback(_populate_foo)

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-log-stdin", "--log-stdout",
                               "--no-log-stderr",
                               incomingdir, "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 0)
        stdout = StringIO()
        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)
            return ap.when_ready()
        d.addCallback(_start_server)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[0], "run-command"))
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out, DATA)
            self.failUnlessEqual(err.strip(), "")
        d.addCallback(_check_client)

        def _delete_foo(ign):
            os.unlink(targetfile)
        d.addCallback(_delete_foo)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[0], "run-command"))
        def _check_client2((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessEqual(out, "")
            self.failUnlessEqual(err.strip(),
                                 "cat: foo.txt: No such file or directory")
        d.addCallback(_check_client2)

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command", "--accept-stdin",
                               "--log-stdin", "--no-log-stdout", "--log-stderr",
                               incomingdir,
                               "dd", "of=bar.txt"))
        d.addCallback(self.stash_furl, 1)

        barfile = os.path.join(incomingdir, "bar.txt")
        DATA2 = "Pass this\ninto stdin\n"
        d.addCallback(lambda _ign:
                      self.run_client_with_stdin(DATA2,
                                                 "--furl", self.furls[1], "run-command"))
        def _check_client3((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            bardata = open(barfile,"rb").read()
            self.failUnlessEqual(bardata, DATA2)
            # these checks depend upon /bin/dd behaving consistently
            self.failUnlessEqual(out, "")
            self.failUnlessIn("records in", err.strip())
        d.addCallback(_check_client3)

        # exercise some more options

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--send-stdout", "--no-stderr",
                               incomingdir,
                               "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 2)

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--no-stdout", "--send-stderr",
                               incomingdir,
                               "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 3)

        d.addCallback(_populate_foo)
            
        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[2], "run-command"))
        def _check_client4((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out, DATA)
            self.failUnlessEqual(err, "")
        d.addCallback(_check_client4)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[3], "run-command"))
        def _check_client5((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out, "") # --no-stdout
            self.failUnlessEqual(err, "")
        d.addCallback(_check_client5)

        d.addCallback(_delete_foo)
        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[2], "run-command"))
        def _check_client6((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessEqual(out, "")
            self.failUnlessEqual(err, "") # --no-stderr
        d.addCallback(_check_client6)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[3], "run-command"))
        def _check_client7((rc,out,err)):
            self.failIfEqual(rc, 0)
            self.failUnlessEqual(out, "") # --no-stdout
            self.failUnlessEqual(err.strip(),
                                 "cat: foo.txt: No such file or directory")
        d.addCallback(_check_client7)

        return d
    
