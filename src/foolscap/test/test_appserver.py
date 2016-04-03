
import os, sys, json
from StringIO import StringIO
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap.api import Tub, eventually
from foolscap.appserver import cli, server, client
from foolscap.test.common import ShouldFailMixin, StallMixin
from foolscap.util import allocate_tcp_port

orig_service_data = {"version": 1,
                     "services": {
                         "swiss1": {"relative_basedir": "1",
                                    "type": "type1",
                                    "args": ["args1a", "args1b"],
                                    "comment": None,
                                    },
                         "swiss2": {"relative_basedir": "2",
                                    "type": "type2",
                                    "args": ["args2a", "args2b"],
                                    "comment": "comment2",
                                    },
                         }}

# copied+trimmed from the old-format appserver/cli.py
def old_add_service(basedir, service_type, service_args, comment, swissnum):
    service_basedir = os.path.join(basedir, "services", swissnum)
    os.makedirs(service_basedir)
    f = open(os.path.join(service_basedir, "service_type"), "w")
    f.write(service_type + "\n")
    f.close()
    f = open(os.path.join(service_basedir, "service_args"), "w")
    f.write(repr(service_args) + "\n")
    f.close()
    if comment:
        f = open(os.path.join(service_basedir, "comment"), "w")
        f.write(comment + "\n")
        f.close()
    furl_prefix = open(os.path.join(basedir, "furl_prefix")).read().strip()
    furl = furl_prefix + swissnum
    return furl, service_basedir

class ServiceData(unittest.TestCase):
    def test_parse_json(self):
        basedir = "appserver/ServiceData/parse_json"
        os.makedirs(basedir)
        f = open(os.path.join(basedir, "services.json"), "wb")
        json.dump(orig_service_data, f)
        f.close()
        data = server.load_service_data(basedir)
        self.failUnlessEqual(orig_service_data, data)

    def test_parse_files_and_upgrade(self):
        # create a structure with individual files, and make sure we parse it
        # correctly. Test the git-foolscap case with slashes in the swissnum.
        basedir = "appserver/ServiceData/parse_files"
        os.makedirs(basedir)
        J = os.path.join

        f = open(os.path.join(basedir, "furl_prefix"), "wb")
        f.write("prefix")
        f.close()

        old_add_service(basedir,
                        "type1", ("args1a", "args1b"), None, "swiss1")
        old_add_service(basedir,
                        "type2", ("args2a", "args2b"), "comment2", "swiss2")
        old_add_service(basedir,
                        "type3", ("args3a", "args3b"), "comment3", "swiss3/3")

        data = server.load_service_data(basedir)
        expected = {"version": 1,
                    "services": {
                        "swiss1": {"relative_basedir": J("services","swiss1"),
                                   "type": "type1",
                                   "args": ["args1a", "args1b"],
                                   "comment": None,
                                   },
                        "swiss2": {"relative_basedir": J("services","swiss2"),
                                   "type": "type2",
                                   "args": ["args2a", "args2b"],
                                   "comment": "comment2",
                                   },
                        J("swiss3","3"): {"relative_basedir":
                                        J("services","swiss3","3"),
                                        "type": "type3",
                                        "args": ["args3a", "args3b"],
                                        "comment": "comment3",
                                        },
                        }}
        self.failUnlessEqual(data, expected)

        s4 = {"relative_basedir": J("services","4"),
              "type": "type4",
              "args": ["args4a", "args4b"],
              "comment": "comment4",
              }
        data["services"]["swiss4"] = s4
        server.save_service_data(basedir, data) # this upgrades to JSON
        data2 = server.load_service_data(basedir) # reads JSON, not files
        expected["services"]["swiss4"] = s4
        self.failUnlessEqual(data2, expected)

    def test_bad_version(self):
        basedir = "appserver/ServiceData/bad_version"
        os.makedirs(basedir)
        orig = {"version": 99}
        f = open(os.path.join(basedir, "services.json"), "wb")
        json.dump(orig, f)
        f.close()
        e = self.failUnlessRaises(server.UnknownVersion,
                                  server.load_service_data, basedir)
        self.failUnlessIn("unable to handle version 99", str(e))

    def test_save(self):
        basedir = "appserver/ServiceData/save"
        os.makedirs(basedir)
        server.save_service_data(basedir, orig_service_data)

        data = server.load_service_data(basedir)
        self.failUnlessEqual(orig_service_data, data)


class CLI(unittest.TestCase):
    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_create(self):
        basedir = "appserver/CLI/create"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", "--location", "localhost:1234", serverdir)
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
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
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
        portnum = allocate_tcp_port()
        d = self.run_cli("create",
                         "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         "--umask", "022", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
            got_port = open(os.path.join(serverdir, "port"), "r").read().strip()
            self.failUnlessEqual(got_port, "tcp:%d" % portnum)
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

    def test_add(self):
        basedir = "appserver/CLI/add"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
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
            data = server.load_service_data(serverdir)
            servicedir2 = os.path.join(serverdir,
                                       data["services"][swiss]["relative_basedir"])
            self.failUnlessEqual(os.path.abspath(servicedir),
                                 os.path.abspath(servicedir2))
            self.failUnlessEqual(data["services"][swiss]["comment"], None)
        d.addCallback(_check_add)
        return d

    def test_add_service(self):
        basedir = "appserver/CLI/add_service"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        def _check_add(ign):
            furl1,servicedir1a = cli.add_service(serverdir,
                                                 "upload-file", (incomingdir,),
                                                 None)
            self.failUnless(os.path.isdir(servicedir1a))
            asd1 = os.path.abspath(servicedir1a)
            self.failUnless(asd1.startswith(os.path.abspath(basedir)))
            swiss1 = furl1[furl1.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir1b = os.path.join(serverdir,
                                        data["services"][swiss1]["relative_basedir"])
            self.failUnlessEqual(os.path.abspath(servicedir1a),
                                 os.path.abspath(servicedir1b))

            # add a second service, to make sure the "find the next-highest
            # available servicedir" logic works from both empty and non-empty
            # starting points
            furl2,servicedir2a = cli.add_service(serverdir,
                                                 "run-command", ("dummy",),
                                                 None)
            self.failUnless(os.path.isdir(servicedir2a))
            asd2 = os.path.abspath(servicedir2a)
            self.failUnless(asd2.startswith(os.path.abspath(basedir)))
            swiss2 = furl2[furl2.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir2b = os.path.join(serverdir,
                                        data["services"][swiss2]["relative_basedir"])
            self.failUnlessEqual(os.path.abspath(servicedir2a),
                                 os.path.abspath(servicedir2b))
        d.addCallback(_check_add)
        return d

    def test_add_comment(self):
        basedir = "appserver/CLI/add_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
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
            data = server.load_service_data(serverdir)
            servicedir2 = os.path.join(serverdir,
                                       data["services"][swiss]["relative_basedir"])
            self.failUnlessEqual(os.path.abspath(servicedir),
                                 os.path.abspath(servicedir2))
            self.failUnlessEqual(data["services"][swiss]["comment"],
                                 "commentary here")
        d.addCallback(_check_add)
        return d

    def test_add_badargs(self):
        basedir = "appserver/CLI/add_badargs"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        servicesdir = os.path.join(serverdir, "services")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
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
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
        def _check((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnless(os.path.isdir(serverdir))
        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "upload-file", incomingdir))
        def _check_add((rc,out,err)):
            self.failUnlessEqual(rc, 0)
        d.addCallback(_check_add)

        def _check_list_services(ign):
            services = cli.list_services(serverdir)
            self.failUnlessEqual(len(services), 1)
            s = services[0]
            self.failUnlessEqual(s.service_type, "upload-file")
            self.failUnlessEqual(s.service_args, [incomingdir] )
        d.addCallback(_check_list_services)

        d.addCallback(lambda ign: self.run_cli("list", serverdir))
        def _check_list((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            s = cli.list_services(serverdir)[0]
            lines = out.splitlines()
            self.failUnlessEqual(lines[0], "")
            self.failUnlessEqual(lines[1], s.swissnum+":")
            self.failUnlessEqual(lines[2], " upload-file %s" % incomingdir)
            self.failUnlessEqual(lines[3], " " + s.furl)
            self.failUnlessEqual(lines[4], " " + s.service_basedir)
        d.addCallback(_check_list)
        return d

    def test_list_comment(self):
        basedir = "appserver/CLI/list_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)
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
            s = cli.list_services(serverdir)[0]
            lines = out.splitlines()
            self.failUnlessEqual(lines[0], "")
            self.failUnlessEqual(lines[1], s.swissnum+":")
            self.failUnlessEqual(lines[2], " upload-file %s" % incomingdir)
            self.failUnlessEqual(lines[3], " # commentary here")
            self.failUnlessEqual(lines[4], " " + s.furl)
            self.failUnlessEqual(lines[5], " " + s.service_basedir)
        d.addCallback(_check_list)
        return d

class Server(unittest.TestCase, ShouldFailMixin):
    def setUp(self):
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
        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)
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

class Upload(unittest.TestCase, ShouldFailMixin):
    def setUp(self):
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

        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)
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

        sourcefile5 = os.path.join(basedir, "file5.txt")
        f = open(sourcefile5, "wb")
        DATA5 = "file number 5\n"
        f.write(DATA5)
        f.close()

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furl, "upload-file",
                                      sourcefile3, sourcefile4, sourcefile5))
        def _check_client4((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessIn("file3.txt: uploaded", out)
            self.failUnlessIn("file4.txt: uploaded", out)
            self.failUnlessIn("file5.txt: uploaded", out)
            self.failUnlessEqual(err.strip(), "")

            fn = os.path.join(incomingdir, "file3.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA3)

            fn = os.path.join(incomingdir, "file4.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA4)

            fn = os.path.join(incomingdir, "file5.txt")
            self.failUnless(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.failUnlessEqual(contents, DATA5)

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

class RunCommand(unittest.TestCase, StallMixin):
    def setUp(self):
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

        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)
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

        helper = os.path.join(os.path.dirname(__file__), "apphelper.py")
        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-log-stdin", "--log-stdout",
                               "--no-log-stderr",
                               incomingdir,
                               sys.executable, helper, "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 0)
        stdout = StringIO()
        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)
        d.addCallback(_start_server)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[0], "run-command"))
        def _check_client((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), DATA.strip())
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
                               sys.executable, helper, "dd", "of=bar.txt"))
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
            # we use a script instead of the real dd; we know how it behaves
            self.failUnlessEqual(out, "")
            self.failUnlessIn("records in", err.strip())
        d.addCallback(_check_client3)

        # exercise some more options

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--send-stdout", "--no-stderr",
                               incomingdir,
                               sys.executable, helper, "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 2)

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--no-stdout", "--send-stderr",
                               incomingdir,
                               sys.executable, helper, "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 3)

        d.addCallback(_populate_foo)

        d.addCallback(lambda _ign:
                      self.run_client("--furl", self.furls[2], "run-command"))
        def _check_client4((rc,out,err)):
            self.failUnlessEqual(rc, 0)
            self.failUnlessEqual(out.strip(), DATA.strip())
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
