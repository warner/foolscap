<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Flappserver: The Foolscap Application Server</title>
<style src="stylesheet-unprocessed.css"></style>
</head>

<body>
<h1>Flappserver: The Foolscap Application Server</h1>

<p>Foolscap provides an "app server", to conveniently deploy small
applications that were written by others. It fulfills the same role as
"twistd" does for Twisted code: it allows sysadmins to configure and launch
services without obligating them to write Python code for each one.</p>

<h2>Example</h2>

<p>This example creates a file-uploading service on one machine, and uses the
corresponding client on a different machine to transfer a file. There are
many different kinds of services that can be managed this way: file-uploading
is just one of them.</p>

<pre class="shell">
## run this on the server machine
S% flappserver create ~/fs
Listening on 127.0.0.1:12345
Foolscap Application Server created in ~/fs
S% mkdir ~/incoming
S% flappserver add ~/fs upload-file ~/incoming
Service created, FURL is pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/47nvyzu6dj6apyrdl7alpe2xasmi52jt
S% flappserver start ~/fs
Server Started
S%

## run this on the client machine
C% echo "pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/47nvyzu6dj6apyrdl7alpe2xasmi52jt" >~/.upload.furl
C% flappclient --furlfile ~/.upload.furl upload-file foo.jpg
## that uploads the local file "foo.jpg" to the server
C%

## run this on the server machine
S% ls ~/incoming
foo.jpg
S%
</pre>


<h2>Concepts</h2>

<p>"flappserver" is both the name of the Foolscap Application Server and the
name of the command used to create, configure, and launch it. Each server
creates a single foolscap Tub, which listens on one or more TCP ports, and is
configured with a "location hint string" that explains (to eventual clients)
how to contact the server. The server is given a working directory to store
persistent data, including the Tub's private key.</p>

<p>Each flappserver hosts an arbitrary number of "services". Each service
gets a distinct FURL (all sharing the same TubID and location). Each service
gets a private subdirectory which contains its configuration arguments and
any persistent state it wants to maintain.</p>

<p>When adding a service to a flappserver, you must specify the "service
type". This indicates which kind of service you want to create. Any remaining
arguments on the "flappserver add" command line will be passed to the service
and can be used to configure its behavior. For each service that is added, a
new FURL is generated and returned to the user (so they can copy it to the
client system that wants to contact this service). The FURL can also be
retrieved later through the "flappserver list" command.</p>

<p>Nothing happens until the flappserver is started, with "flappserver
start". This is simply a front-end for twistd, so it takes twistd arguments
like --nodaemon, --syslog, etc (use "twistd --help" for a complete list). The
server will run in the background as a standard unix daemon. "flappserver
stop" will shut down the daemon.</p>

<h2>Services</h2>

<p>The app server has a list of known service types. You can add multiple
services of the same type to a single app server. This is analogous to
object-oriented programming: the service types are <b>classes</b>, and the
app server holds zero or more <b>instances</b> of each type (each of which is
probably configured slightly differently).</p>

<p>Service types are defined by plugins, each of which provides the code to
implement a named service.</p>

<p>The basic services that ship with Foolscap are:</p>

<ul>
  <li><b>upload-file</b>: allow files to be written into a single directory
  by the corresponding "flappclient upload-file" command. Files are streamed
  to a neighboring temporary file before being atomically moved into place.
  The client gets to choose the target filename. Optionally allow the
  creation and use of subdirectories.</li>

  <li><b>run-command</b>: allow a preconfigured shell command to be executed
  by the corresponding "flappclient run-command" invocation. Client receives
  stdout/stderr/rc. Command runs in a preconfigured working directory.
  Optionally allow the client to provide stdin to the command. In a future
  version: optionally provide locking around the command (allow only one
  instance to run at a time), optionally merge multiple pending invocations,
  optionally allow the client to provide arguments to the command.</li>
</ul>

<h2>Commands</h2>

<h3><code>flappserver create BASEDIR [options]</code></h3>

<p>Create a new server, using BASEDIR as a working directory. BASEDIR should
not already exist, and nothing else should touch its contents. BASEDIR will
be created with mode 0700, to prevent other users from reading it and
learning the private key.</p>

<p>"create" options:</p>

<ul>
  <li><code>--port</code>: strports description of the TCP port
  to listen on</li>

  <li><code>--location</code>: location hints to use in generated
  FURLs. If not provided, the server will attempt to enumerate all network
  interfaces and create a location hint string using each viable IP address
  it finds. If you have configured an external NAT or port forwarding for
  this server, you will need to set --location with the externally-visible
  listening port.</li>

  <li><code>--umask</code>: set the (octal) file-creation mask that the
  server will use at runtime. When your services are invoked, any files they
  create will have accesss-permissions (the file "mode") controlled by this
  value. <code>flappserver create</code> will copy your current umask and use
  it in the server unless you override it with this option.
  <code>--umask=022</code> is a good way to let those created files be
  world-readable, and <code>--umask=077</code> is used to make them
  non-world-redable.</li>

</ul>


<h3><code>flappserver add BASEDIR [options] SERVICE-TYPE SERVICE-ARGS</code></h3>

<p>Add a new service to the existing server that lives in BASEDIR. The new
service will be of type SERVICE-TYPE (such as "upload-file" or
"run-command"), and will be configured with SERVICE-ARGS.</p>

<p>A new unguessable "swissnum" will be generated for the service, from which
a FURL will be computed. Clients must use this FURL to contact the service.
The FURL will be printed to stdout, where it can be copied and transferred to
client machines. It can also be viewed later using the "list" command.</p>

<p>The service instance will be created lazily, when a client actually
connects to the FURL. There will be only one instance per service, which will
last until the flappserver is terminated. (services are of course free to
create new per-request objects, which can last as long as necessary)</p>

<p>The "add" command takes certain options. Separately, each SERVICE-TYPE
will accept one or more SERVICE-ARGS, whose format depends upon the specific
type of service being created. The "add" command options must appear before
the SERVICE-TYPE parameter, while the SERVICE-ARGS always appear after the
SERVICE-TYPE parameter.</p>

<p>"add" options:</p>

<ul>
  <li><code>--comment</code>: short string explaining what this service is
  used for, appears in the output of <code>flappserver list</code></li>
</ul>


<h3><code>flappserver list BASEDIR</code></h3>

<p>List information about each service that has been configured in the given
flappserver. Each service is listed with the unguessable "swissnum", followed
by the service-type and service-args, then any --comment that was given to
the add command, finishing with the access FURL:</p>

<pre class="shell">
% flappserver list ~/fs

47nvyzu6dj6apyrdl7alpe2xasmi52jt:
 upload-file ~/incoming --allow-subdirectories
 # --comment text appears here
 pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/47nvyzu6dj6apyrdl7alpe2xasmi52jt

jgdqovf3tfd5xog34bxmkqwd3dxgycak:
 upload-file ~/repo/packages
 pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/jgdqovf3tfd5xog34bxmkqwd3dxgycak

22ngipsyp2smmgguemf5hu45prz4jeui:
 run-command ~/repo make update-repository
 pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/22ngipsyp2smmgguemf5hu45prz4jeui

%
</pre>

<p>The "list" command takes no options.</p>


<h3><code>flappserver start BASEDIR [twistd options]</code></h3>

<p>Launch (and usually daemonize) the server that lives in BASEDIR. This
command will return quickly, leaving the server running in the background.
Logs will be written to BASEDIR/twistd.log unless overridden.</p>

<p>The "start" command accepts the same options as twistd, so use
<code>twistd --help</code> to see the options that will be recognized.
"flappserver start BASEDIR" is equivalent to "cd BASEDIR &amp;&amp; twistd -y
*.tac [options]".</p>


<h3><code>flappserver stop BASEDIR</code></h3>

<p>Terminate the server that is running in BASEDIR. This is equivalent to "cd
BASEDIR &amp;&amp; kill `cat twistd.pid`".</p>

<p>The "stop" command takes no options.</p>


<h3><code>flappserver restart BASEDIR [twistd options]</code></h3>

<p>Terminate and restart the server that is running in BASEDIR. This is
equivalent to "flappserver stop BASEDIR &amp;&amp; flappserver start BASEDIR
[options]".</p>

<p>The "restart" command takes the same twistd arguments as <b>start</b>.</p>

<h2>Services</h2>

<h3><code>upload-file [options] TARGETDIR</code></h3>

<p>This service accepts files from <code>flappclient upload-file</code>,
placing them in TARGETDIR (which must already exist and be writable by the
flappserver). The filenames are chosen by the client. Existing files will be
overwritten. This service will never write client files above TARGETDIR, even
if the client attempts to use ".." or other pathname metacharacters (assuming
that a local user has not placed upwards-leading symlinks in TARGETDIR). It
will only write to subdirectories of TARGETDIR if the service was configured
with <code>--allow-subdirectories</code>, in which case the client controls
which subdirectory is used (and created if necessary).</p>

<p>The files will be created with the flappserver's configured
<code>--umask</code>, typically captured when the server is first created. If
the server winds up with a restrictive umask like 077, then the files created
in TARGETDIR will not be readable by other users.</p>

<p>TODO: <code>--allow-subdirectories</code> is not yet implemented.</p>

<p>Example:</p>

<pre class="shell">
% flappserver create --listen 12345 --location example.com:12345 ~/fl
Foolscap Application Server created in /usr/home/warner/fl
TubID u5bca3u2wklkyyv7wzjetmfltyqeb6kv, listening on port tcp:12345
Now launch the daemon with 'flappserver start /usr/home/warner/fl'
% flappserver add ~/fl upload-file ~/incoming
Service added in /usr/home/warner/fl/services/vx3s2tb62ywct4pdgdicdpbxgz4ly7po
FURL is pb://u5bca3u2wklkyyv7wzjetmfltyqeb6kv@example.com:12345/vx3s2tb62ywct4pdgdicdpbxgz4ly7po
% flappserver start ~/fl
Launching Server...
Server Running
%
</pre>


<h3><code>run-command [options] TARGETDIR COMMAND..</code></h3>

<p>This service invokes a preconfigured command in response to requests from
<code>flappclient run-command</code>. The command is always run with
TARGETDIR as its current working directory.</p>

<p>COMMAND will be run with the flappserver's configured
<code>--umask</code>, typically captured when the server is first created. If
the server winds up with a restrictive umask like 077, then when COMMAND is
run with that umask any files it creates will not be readable by other
users.</p>

<p>"run-command" options:</p>

<ul>
  <li><code>--accept-stdin</code>: if set, any data written to the client's
  stdin will be streamed to the stdin of COMMAND. When the client's stdin is
  closed, the COMMAND's stdin will also be closed. If omitted, the client
  will be instructed to not read from its stdin, and COMMAND will not receive
  any stdin (the pipe will be left open, however).</li>
  <li><code>--no-stdin</code>: [default] opposite of --accept-stdin.</li>

  <li><code>--send-stdout</code>: [default] if set, any data written by
  COMMAND to its stdout will be streamed to the client, which will deliver
  the data to its own stdout pipe.</li>
  <li><code>--no-stdout</code>: if set, any data written by COMMAND to its
  stdout will be discarded, and not sent to the client.</li>

  <li><code>--send-stderr</code>: [default] if set, any data written by
  COMMAND to its stderr will be streamed to the client, which will deliver
  the data to its own stderr pipe.</li>
  <li><code>--no-stderr</code>: if set, any data written by COMMAND to its
  stderr will be discarded, and not sent to the client.</li>

  <li><code>--log-stdin</code>: if set, all incoming stdin data will be
  written to the twistd.log</li>
  <li><code>--no-log-stdin</code>: [default] do not log incoming stdin</li>

  <li><code>--log-stdout</code>: if set, all outgoing stdout data will be
  written to the twistd.log</li>
  <li><code>--no-log-stdout</code>: [default] do not log outgoing stdout</li>

  <li><code>--log-stderr</code>: [default] if set, all outgoing stderr data
  will be written to the twistd.log</li>
  <li><code>--no-log-stderr</code>: do not log outgoing stderr</li>

</ul>

<p>The numeric exit status of COMMAND will be delivered to the client, which
will exit with the same status. If COMMAND terminates with a signal, a
suitable non-zero exit status will be delivered (127).</p>

<p>Future options will allow the client to modify COMMAND (in tightly
controlled ways), and to wrap a semaphore around the invocation of COMMAND so
that overlapping requests do not cause overlapping invocations. Another
likely option is to coalesce multiple pending requests into a single
invocation.</p>


<h2>Clients</h2>

<p>To talk to the services described above, Foolscap comes with a simple
multipurpose client tool named <code>flappclient</code>. This tool always
takes a <code>--furl=</code> or <code>--furlfile=</code> argument to specify
the FURL of the target server.</p>

<p>For <code>--furlfile=</code>, the FURL should be stored in the given file.
The client will ignore blank lines and comment lines (those which begin with
"#"). It will use the first FURL it sees in the file, ignoring everything
beyond that point. It is a good practice to put a comment in your furlfiles
to remind you what the FURL points to and where you got it from:</p>

<pre class="shell">
% cat ~/upload.furl
# this FURL points to a file-uploader on ftp.example.com:~/incoming
pb://kykr3p2hsippfgxqq2icrbrncee2f6ef@127.0.0.1:12345/47nvyzu6dj6apyrdl7alpe2xasmi52jt
%
% flappclient --furlfile ~/upload.furl upload-file foo.txt bar.txt
foo.txt: uploaded
bar.txt: uploaded
%
</pre>

<p>The --furlfile form is useful to keep the secret FURL out of a transcript
of the command being run, such as in a buildbot logfile. Naming your
furlfiles after their purpose is a good practice: the filename then behaves
like a "pet name": a local identifier that hides the secure connection
information.</p>

<h3><code>flappclient [--furl|--furlfile] upload-file SOURCEFILES..</code></h3>

<p>This contacts a file-uploader service as created with <code>flappserver
add BASEDIR upload-file TARGETDIR</code> and sends it one or more local
files.</p>

<p>The basename of each SOURCEFILE will be used to provide the remote
filename.</p>

<p>TODO (not yet implemented): If there is only one SOURCEFILE argument, then
the <code>--target-filename=</code> option can be used to override the remote
filename. If the server side has enabled subdirectories, then
<code>--target-subdirectory=</code> can be used to place the file in a
subdirectory of the server's targetdir.</p>


<h3><code>flappclient [--furl|--furlfile] run-command</code></h3>

<p>This contacts a command-executing service as created with
<code>flappserver add BASEDIR run-command TARGETDIR COMMAND</code> and asks
it to invoke the preconfigured command.</p>

<p>If the server was configured with <code>--accept-stdin</code>, the client
will read from stdin until it is closed, continuously sending data to the
server, then closing the server's stdin pipe (this is useful for commands
like 'grep' which read from stdin). If not, the client will ignore its
stdin.</p>

<p>By default, the client will write to its stdout and stderr as data arrives
from the server (however the server can be configured to not send stdout or
stderr). Once the server's process exits, the client will exit with the same
exit code.</p>

</body></html>
