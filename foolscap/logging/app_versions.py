
import twisted
import foolscap

# You might want to modify this to include the version of your application.
# Just do:
#
#  from foolscap.logging import app_versions
#  app_versions.add_version("myapp", myversion)

versions = {"twisted": twisted.__version__,
            "foolscap": foolscap.__version__,
            }

def add_version(name, version):
    versions[name] = str(version)

