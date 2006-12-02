# -*- test-case-name: foolscap.test.test_interfaces -*-

from zope.interface import implementsOnly, Interface
from twisted.trial import unittest

from foolscap import schema, remoteinterface
from foolscap import RemoteInterface
from foolscap.remoteinterface import getRemoteInterface
from foolscap.remoteinterface import RemoteInterfaceRegistry

from foolscap.test.common import TargetMixin
from foolscap.test.common import getRemoteInterfaceName, Target, RIMyTarget, \
     RIMyTarget2, TargetWithoutInterfaces


class IFoo(Interface):
    # non-remote Interface
    pass

class Target2(Target):
    implementsOnly(IFoo, RIMyTarget2)

class TestInterface(TargetMixin, unittest.TestCase):

    def testTypes(self):
        self.failUnless(isinstance(RIMyTarget,
                                   remoteinterface.RemoteInterfaceClass))
        self.failUnless(isinstance(RIMyTarget2,
                                   remoteinterface.RemoteInterfaceClass))

    def testRegister(self):
        reg = RemoteInterfaceRegistry
        self.failUnlessEqual(reg["RIMyTarget"], RIMyTarget)
        self.failUnlessEqual(reg["RIMyTargetInterface2"], RIMyTarget2)

    def testDuplicateRegistry(self):
        try:
            class RIMyTarget(RemoteInterface):
                def foo(bar=int): return int
        except remoteinterface.DuplicateRemoteInterfaceError:
            pass
        else:
            self.fail("duplicate registration not caught")

    def testInterface1(self):
        # verify that we extract the right interfaces from a local object.
        # also check that the registry stuff works.
        self.setupBrokers()
        rr, target = self.setupTarget(Target())
        iface = getRemoteInterface(target)
        self.failUnlessEqual(iface, RIMyTarget)
        iname = getRemoteInterfaceName(target)
        self.failUnlessEqual(iname, "RIMyTarget")
        self.failUnlessIdentical(RemoteInterfaceRegistry["RIMyTarget"],
                                 RIMyTarget)
        
        rr, target = self.setupTarget(Target2())
        iname = getRemoteInterfaceName(target)
        self.failUnlessEqual(iname, "RIMyTargetInterface2")
        self.failUnlessIdentical(\
            RemoteInterfaceRegistry["RIMyTargetInterface2"], RIMyTarget2)


    def testInterface2(self):
        # verify that RemoteInterfaces have the right attributes
        t = Target()
        iface = getRemoteInterface(t)
        self.failUnlessEqual(iface, RIMyTarget)

        # 'add' is defined with 'def'
        s1 = RIMyTarget['add']
        self.failUnless(isinstance(s1, schema.RemoteMethodSchema))
        ok, s2 = s1.getArgConstraint("a")
        self.failUnless(ok)
        self.failUnless(isinstance(s2, schema.IntegerConstraint))
        self.failUnless(s2.checkObject(12) == None)
        self.failUnlessRaises(schema.Violation, s2.checkObject, "string")
        s3 = s1.getResponseConstraint()
        self.failUnless(isinstance(s3, schema.IntegerConstraint))

        # 'add1' is defined as a class attribute
        s1 = RIMyTarget['add1']
        self.failUnless(isinstance(s1, schema.RemoteMethodSchema))
        ok, s2 = s1.getArgConstraint("a")
        self.failUnless(ok)
        self.failUnless(isinstance(s2, schema.IntegerConstraint))
        self.failUnless(s2.checkObject(12) == None)
        self.failUnlessRaises(schema.Violation, s2.checkObject, "string")
        s3 = s1.getResponseConstraint()
        self.failUnless(isinstance(s3, schema.IntegerConstraint))

        s1 = RIMyTarget['join']
        self.failUnless(isinstance(s1.getArgConstraint("a")[1],
                                   schema.StringConstraint))
        self.failUnless(isinstance(s1.getArgConstraint("c")[1],
                                   schema.IntegerConstraint))
        s3 = RIMyTarget['join'].getResponseConstraint()
        self.failUnless(isinstance(s3, schema.StringConstraint))

        s1 = RIMyTarget['disputed']
        self.failUnless(isinstance(s1.getArgConstraint("a")[1],
                                   schema.IntegerConstraint))
        s3 = s1.getResponseConstraint()
        self.failUnless(isinstance(s3, schema.IntegerConstraint))


    def testInterface3(self):
        t = TargetWithoutInterfaces()
        iface = getRemoteInterface(t)
        self.failIf(iface)

