# Matterlay

Matterlay is a small relay bridge between [Mattermost](https://Mattermost.com) and
IRC. Unlike for example [MatterBridge](https://github.com/42wim/matterbridge) it
does not connect to an existing IRC network and try to bridge the content there.
Instead, it runs its own dedicated service process emulating an IRC server. This
gives it more control over things like nickname mapping. It is intended for personal
relaying, not mapping existing public channels.

*This code is definitely a work in progress at this point*


## Installing

Matterlay is a simple Python 3 script. It is built on the *asyncio* module, and uses
the new async syntax from Python 3.5+. It also uses the following modules:

* aiohttp
* passlib
* pycrypto (1.7 or later)
* websockets

When run the script will bind to localhost on port 9991. At this point that's hardcoded,
but this should be moved to a config file or commandline parameter. Currently there
is no TLS support.


## Connecting

Multi-user is supported, but not particularly well tested at this point.

A user logs in with an IRC client to port 9991 on localhost, and should always use
the same nick as the name used in the Mattermost server. (This needs to be changed
once support for multiple Mattermost servers is properly done).

After logging in, a virtual channel named *matterlay* will be automatically created.
In this channel, the user should identify by sending the command `identify password`.
If there is no user by this name, one will be created with the given password. If there
is one already, it will be authenticated with the same password (and disconnected if
it's wrong).

Once authenticated, a Mattermost server can be added by using the *add* command in
this virtual control channel, like this:

```
add Mattermostserver.mydomain.com topsecretMattermostpassword
```

If a server is added, it will automatically be connected to when the user is identified.

## Usage

### Channels

Channels are auto created for any channel that the user is present in in the Mattermost
client.

At this point, there is no support for joining channels beyond that. So channel joining
has to happen from the Mattermost web client or mobile client.

### Direct messages

Direct messages are fully supported both to existing open DM channels and new ones. Just
use `/msg nick message` to open a new channel.

### Searching for users

In the command channel, the *search* command can be used to do a general search for users
when the nickname is not used, like this:

```
search joe
```

Which will return a list of all users matching joe, including information on them. The
matching is controlled by the Mattermost server, and normally matches both name and
email address.
