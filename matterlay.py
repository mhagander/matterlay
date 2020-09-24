#!/usr/bin/env python3

import asyncio
import aiohttp
import json
import websockets
import sqlite3
import base64
from passlib.hash import pbkdf2_sha256
from passlib.crypto.digest import pbkdf2_hmac
from Crypto import Random
from Crypto.Cipher import AES


db = sqlite3.connect('matterlay.db')

class MattermostClient():
    def __init__(self, host):
        self.host = host
        self.token = ''

        self.channel_to_dm_map = {}
        self.dm_to_channel_map = {}

    def auth_header(self):
        if self.token == '':
            return {}
        return {"Authorization": "Bearer {token:s}".format(token=self.token)}

    async def make_request(self, method, endpoint, options={}):
        headers={"content-type": "text/javascript"}
        if self.token:
            headers['Authorization']="Bearer {token:s}".format(token=self.token)

        async with aiohttp.request(
            method,
            url='https://' + self.host + '/api/v4' + endpoint,
            headers=headers,
            data=json.dumps(options),
        ) as response:
            return response

    async def connect_websocket(self, handler):
        url = 'wss://{0}/api/v4/websocket'.format(self.host)
        websocket = await websockets.connect(url)

        # Authenticate
        j = json.dumps({'seq': 1, 'action': 'authentication_challenge', 'data': { 'token': self.token }}).encode('utf8')
        await websocket.send(j)
        while True:
            msg = await websocket.recv()
            j = json.loads(msg)
            if j.get('status', None) == 'OK' and j.get('seq_reply', None) == 1:
                # Authentication OK!
                break
            # Else we wait and hope for another message that is the status message

        # Loop
        while True:
            try:
                await asyncio.wait_for(self._process_websocket(websocket, handler), 30)
            except asyncio.TimeoutError:
                # On timeout, we send a ping/pong round
                await websocket.pong()

    async def _process_websocket(self, websocket, handler):
        while True:
            msg = await websocket.recv()
            await handler(msg)


    async def login(self, user, password):
        result = await self.make_request('post', '/users/login', {
            'login_id': user,
            'password': password,
        })
        if result.status == 200:
            self.token = result.headers['Token']
            self.cookies = result.cookies
            r = await result.json()
            if 'id' in r:
                self.userid = r['id']
            if 'username' in r:
                self.username = r['username']
        else:
            raise Exception("Failed to log in ")

    async def get_team_by_name(self, team):
        result = await self.make_request('get', '/teams/name/{0}'.format(team))
        j = await result.json()
        return j

    async def get_user_by_username(self, user):
        try:
            result = await self.make_request('get', '/users/username/{0}'.format(user))
            j = await result.json()
        except aiohttp.errors.HttpProcessingError as e:
            if e.code == 404:
                return None
            raise
        return j

    async def get_user_namestring(self, nick):
        result = await self.get_user_by_username(nick)
        if not result:
            return None
        try:
            return '{0} {1} ({2})'.format(result['first_name'], result['last_name'], result['position'])
        except:
            return 'Found, but not parseable'

    async def search_users(self, keyword, teamid):
        result = await self.make_request('post', '/users/search', {'term': keyword, 'team_id': teamid})
        j = await result.json()
        return j

    async def get_channel_by_name(self, team, channel):
        result = await self.make_request('get', '/teams/name/{0}/channels/name/{1}'.format(team, channel))
        j = await result.json()
        return j

    async def get_all_channels(self, teamid):
        result = await self.make_request('get', '/users/{0}/teams/{1}/channels'.format(self.userid, teamid))
        j = await result.json()
        # Return public and private channels, not direct messages
        return [c for c in j if c['type'] in ('O', 'P')]

    async def get_channel_members(self, channel_id):
        result = await self.make_request('get', '/users?per_page=200&in_channel={0}'.format(channel_id))
        j = await result.json()
        return j

    async def get_dm_channel_from_id(self, channel_id, selfnick):
        # Return the name of the IRC channel to use based on mattermost channel id
        # Figure out who the other user is. First check the cache
        if channel_id in self.channel_to_dm_map:
            return self.channel_to_dm_map[channel_id]

        ulist = await self.get_channel_members(channel_id)
        nicks = [u['nickname'] for u in ulist if u['nickname'] != selfnick]
        if len(nicks) == 1:
            self.channel_to_dm_map[channel_id] = nicks[0]
            self.dm_to_channel_map[nicks[0]] = channel_id
            return nicks[0]
        else:
            print("Invalid number of nicks in DM channel: %s" % [u['nickname'] for u in ulist])
            return None

    async def get_dm_channel_from_nick(self, nick, teamid):
        # Return the mattermost channel based on the irc nick

        # First check the cache
        if nick in self.dm_to_channel_map:
            return self.dm_to_channel_map[nick]

        # Get all DM channels to see if we can find the right one already
        result = await self.make_request('get', '/users/{0}/teams/{1}/channels'.format(self.userid, teamid))
        j = await result.json()
        for c in j:
            if c['type'] == 'D':
                # Do we already know about this channel?
                if c['name'] in self.channel_to_dm_map:
                    continue
                # Learn about this new DM channel
                ulist = await self.get_channel_members(c['id'])
                nicks = [u['nickname'] for u in ulist if u['nickname'] == nick]
                if len(nicks) == 1:
                    self.channel_to_dm_map[c['id']] = nick
                    self.dm_to_channel_map[nick] = c['id']
                    return c['id']
        print("No DM channel found for %s, trying to create one" % nick)
        u = await self.get_user_by_username(nick)
        if not u:
            print("User %s not found" % nick)
            return None
        result = await self.make_request('post', '/channels/direct', [self.userid, u['id']])
        c = await result.json()
        self.channel_to_dm_map[c['id']] = nick
        self.dm_to_channel_map[nick] = c['id']
        return c['id']

    async def create_post(self, channel_id, message):
        await self.make_request('post', '/posts', {
            'channel_id': channel_id,
            'message': message,
        })


class Matterlay(object):
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.nick = None
        self.channels = {}
        self.joined_channels = []
        self.team_name = None
        self.team_id = None
        self.pending_sends = []

    async def get_team(self):
        if not self.team_id:
            r = await self.mattermost.get_team_by_name(self.team_name)
            self.team_id = r['id']
        return self.team_id

    async def get_channel(self, channel):
        if not channel in self.channels:
            self.channels[channel] = await self.mattermost.get_channel_by_name(self.team_name, channel)
        return self.channels[channel]

    async def raw_reply(self, s, flush=True):
        self.writer.write(s.encode('utf8'))
        if flush:
            await self.writer.drain()

    async def reply(self, s, flush=True):
        await self.raw_reply(':matterlay PRIVMSG {0} :{1}\r\n'.format(self.nick, s), flush)

    async def set_topic(self, channel, topic):
        await self.raw_reply(':matterlay 332 {0} {1} :{2}\r\n'.format(self.nick, channel, topic))

    async def maybe_join_channel(self, channel, channeljson=None):
        if channel in self.joined_channels:
            # Already joined
            return
        await self.raw_reply(':{0} JOIN :{1}\r\n'.format(self.nick, channel))
        self.joined_channels.append(channel)
        if channeljson:
            ch = self.channels[channel] = channeljson
        else:
            ch = await self.get_channel(channel)
        await self.set_topic(channel, ch['header'])
        await self.refresh_channel_names(channel)

    async def channel_post(self, sender, channel, s, flush=True):
        if channel[0] == '#':
            await self.maybe_join_channel(channel)
        for l in s.splitlines():
            await self.raw_reply(':{0} PRIVMSG {1} :{2}\r\n'.format(sender, channel, l), flush)

    async def refresh_channel_names(self, channel):
        ch = await self.get_channel(channel)
        members = await self.mattermost.get_channel_members(ch['id'])

        await self.raw_reply(":matterlay 353 {0} = {1} :{2}\r\n".format(self.nick,
                                                                          channel,
                                                                          " ".join([m['nickname'] for m in members])))
        await self.raw_reply(":matterlay 366 {0} {1} :End of /NAMES list\r\n".format(self.nick, channel))

    async def search_users(self, keyword):
        users = await self.mattermost.search_users(keyword, self.team_id)
        for u in users:
            await self.reply('{0}: {1} {2} ({3})'.format(u['username'], u['first_name'], u['last_name'], u['position']))
        await self.reply('Found {0} users matching {1}'.format(len(users), keyword))

    async def _get_line(self):
        l = await self.reader.readline()
        return l.decode('utf8').rstrip()

    async def add_mattermost_server(self, host, team, password):
        curs = db.cursor()
        curs.execute("SELECT host, team, password FROM mattermost_accounts WHERE user=?", (self.internal_id, ))
        if curs.fetchall():
            await self.reply('Sorry, no support for multiple servers yet')
            return
        key = pbkdf2_hmac('sha256', self.actual_password, self.nick, 10000)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(password)
        curs.execute("INSERT INTO mattermost_accounts (user, host, team, password) VALUES (?,?,?,?)", (self.internal_id, host, team, base64.b64encode(msg)))
        db.commit()
        await self.reply('New server added')
        await self.connect_to_mattermost()

    async def connect_to_mattermost(self):
        curs = db.cursor()
        curs.execute("SELECT host, team, password FROM mattermost_accounts WHERE user=?", (self.internal_id, ))
        servers = curs.fetchall()
        if len(servers) == 0:
            await self.reply('No mattermost servers configured yet, not connecting to anything')
        elif len(servers) == 1:
            for host, team, pwd in servers:
                await self.reply('Connecting to server {0}'.format(host))
                # Decrypt the password. Strart by un-b64ing it
                key = pbkdf2_hmac('sha256', self.actual_password, self.nick, 10000)
                msg = base64.b64decode(pwd)
                dec = AES.new(key, AES.MODE_CFB, msg[:16])
                password = dec.decrypt(msg[16:]).decode('utf8')
                self.team_name = team
                asyncio.ensure_future(self.mattermost_handler(host, password))
        else:
            await self.reply('XXX: Multiple servers not implemented yet')

    async def process_prelogin(self):
        while True:
            l = await self._get_line()
            if not l:
                break
            if l.startswith("NICK "):
                self.nick = l[5:].lstrip(':')
                await self.raw_reply(':matterlay 001 {0} Welcome!\r\n'.format(self.nick), False)
                await self.reply('Welcome to matterlay. Please identify. Remember that your nick must match that in Mattermost.')
            elif l.startswith("PRIVMSG matterlay :"):
                if l[18:27].upper() == ":IDENTIFY":
                    pwd = l[28:]
                    curs = db.cursor()
                    curs.execute("SELECT id, hashedpwd FROM users WHERE nick=?", (self.nick, ))
                    ret = curs.fetchall()
                    if len(ret) == 1:
                        # Found user! Check password.
                        if not pbkdf2_sha256.verify(pwd, ret[0][1]):
                            await self.reply('Invalid password, bye.')
                            return
                        # Yay password!
                        self.internal_id = ret[0][0]
                        self.actual_password = pwd
                        await self.reply('Hello {0}, identification complete.'.format(self.nick))
                        # Break out of loop and proceed to actual dialogue
                        break
                    else:
                        # User not found, so create one!
                        hash = pbkdf2_sha256.encrypt(pwd, salt_size=16)
                        curs.execute("INSERT INTO users (nick, hashedpwd) VALUES (?,?)", (self.nick, hash))
                        self.internal_id = curs.lastrowid
                        db.commit()
                        await self.reply('Hello {0}. A new account has been set up for you with the given password'.format(self.nick))
                        self.actual_password = pwd
                        # Proceed to actual dialogue now
                        break
                else:
                    await self.reply('Please start by identifying. Remember that your nick must match that in Mattermost.')
            else:
                # Don't bother logging invalid commands before identifying
                pass


    async def run(self):
        try:
            await self.process_prelogin()

            # Do we have any mattermost servers yet?
            await self.connect_to_mattermost()

            # Loop for all IRC commands
            while True:
                l = await self._get_line()
                if not l:
                    break
                elif l.startswith("PING "):
                    await self.raw_reply(':matterlay PONG matterlay\r\n')
                elif l.startswith("JOIN "):
                    # This part isn't really implemented yet. We auto-join all mattermost channels
                    # when traffic comes the other way, but we should perhaps be able to force-join
                    # channels as well, as they might show up after the fact?
                    pieces = l.split(' ',2 )
                    if pieces[1] not in self.joined_channels:
                        await self.reply("Sorry, JOIN not implemented yet")
                elif l.startswith("PRIVMSG "):
                    pieces = l.split(' ', 2)
                    if pieces[1] == 'matterlay':
                        # Sending message to the matterlay channel
                        if pieces[2] == ':help':
                            await self.reply('Commands:')
                            await self.reply(' add <hostname> <team> <password>')
                            await self.reply(' search <searchterm>')
                        elif pieces[2].startswith(':add'):
                            cmd = pieces[2].split()
                            if len(cmd) != 4:
                                await self.reply("Usage: add <hostname> <team> <password")
                            else:
                                await self.add_mattermost_server(*cmd[1:])
                        elif pieces[2].startswith(':search'):
                            cmd = pieces[2].split()
                            if len(cmd) != 2:
                                await self.reply("Usage: search <keyword>")
                            else:
                                await self.search_users(cmd[1])
                        else:
                            await self.reply("Unknown command %s, try 'help'" % pieces[2])
                    elif pieces[1][0] == '#':
                        # Got a message on a channel, so post it over to mattermost
                        channel = pieces[1][1:]
                        c = await self.get_channel(channel)
                        self.pending_sends.append(pieces[2][1:])
                        await self.mattermost.create_post(c['id'], pieces[2][1:])
                    else:
                        # Private message. Find a channel for it, or create
                        # one if we have to.
                        # NOTE! If trying to message self, don't pick a random
                        # channel :) Instead, just drop the message.
                        if pieces[1] == self.nick:
                            await self.reply('Cannot DM yourself!')
                            continue
                        cid = await self.mattermost.get_dm_channel_from_nick(pieces[1], self.team_id)
                        if cid:
                            self.pending_sends.append(pieces[2][1:])
                            await self.mattermost.create_post(cid, pieces[2][1:])
                        else:
                            await self.reply('Could not find user %s' % pieces[1])
                elif l.startswith("NAMES"):
                    pieces = l.split(' ', 1)
                    await self.refresh_channel_names(pieces[1])
                elif l.startswith("WHOIS"):
                    pieces = l.split(' ', 1)
                    nickinfo = await self.mattermost.get_user_namestring(pieces[1])
                    if nickinfo:
                        await self.raw_reply(":matterlay 311 {0} {0} {0} matterlay * :{1}\r\n".format(pieces[1], nickinfo))
                    else:
                        await self.raw_reply(":matterlay 401 {0} No such nick\r\n".format(pieces[1]))
                elif l.startswith("MODE "):
                    # Ignore mode requests for now, but don't complain about them.
                    pass
                elif l.startswith("QUIT"):
                    break
                else:
                    print("Unknown IRC input: %s" % l)
        finally:
            try:
                self.writer.close()
                self.reader.close()
            except:
                pass

    async def mattermost_event_handler(self, event):
        try:
            j = json.loads(event)
            if j['event'] == 'posted':
                # Something got posted in a channel
                msg = json.loads(j['data']['post'])
                if j['data']['sender_name'].lstrip('@') == self.nick:
                    # Is this something sent from *this* client?
                    if msg['message'] in self.pending_sends:
                        self.pending_sends.remove(msg['message'])
                        print("Posted message in {0} came back.".format(j['data']['channel_name']))
                        return

                if j['data']['channel_type'] == 'D':
                    # Direct message channel, so rename it based on the
                    # id of the user instead
                    post = json.loads(j['data']['post'])
                    channel = await self.mattermost.get_dm_channel_from_id(post['channel_id'], self.nick)
                    if not channel:
                        # Just ignore it if we don't know what to do with it
                        print("Channel {0} not found".format(post['channel_id']))
                        return
                else:
                    # Regular channel
                    channel = '#' + j['data']['channel_name']

                # XXX: downgrade to debug
                print("{0} posted in {1}: {2}".format(
                    j['data']['sender_name'],
                    channel,
                    msg['message']))

                await self.channel_post(j['data']['sender_name'].lstrip('@'), channel, msg['message'])
            elif j['event'] == 'channel_updated':
                ch = json.loads(j['data']['channel'])
                channel = ch['name']
                topic = ch['header']
                await self.set_topic('#'+channel, topic)
            elif j['event'] in ('user_added', ):
                # XXX: refresh membership in channel!
                # But we need to figure out which channel first :)
                print(j)
            elif j['event'] in ('channel_viewed', 'preferences_changed'):
                return
            else:
                print("Unhandled event: {0}".format(j['event']))
        except Exception as e:
            print("Mattermost event handler exception: {0}".format(e))


    async def mattermost_handler(self, host, password):
        self.mattermost = MattermostClient(host)
        try:
            await self.mattermost.login(self.nick, password)
        except Exception as e:
            print("Login exception: {}".format(e))
            await self.reply('Login failed.')
            return

        await self.reply('Logged in to mattermost, listing and joining channels')

        # Join all applicable channels
        channels = await self.mattermost.get_all_channels(await self.get_team())
        for ch in channels:
            await self.maybe_join_channel('#' + ch['name'], ch)

        # Set up a websocket to track events
        # In case this socket gets closed (e.g. network closure),
        # try to open a new one a few seconds later.
        while True:
            try:
                await self.mattermost.connect_websocket(self.mattermost_event_handler)
            except:
                print("Websocket connection closed. Retrying in 5 seconds.")
                await asyncio.sleep(5)



async def irc_server(reader, writer):
    # Each new connection gets a Matterlay object, and runs independently in it.
    await Matterlay(reader, writer).run()

async def irc_handler():
    await asyncio.start_server(irc_server, '127.0.0.1', 9991)


if __name__ == "__main__":
    c = db.cursor()

    # Set up the database schema.
    # XXX: this is really not going to scale once we ever want to change the schema,
    #      but for now it's so trivial we can get away with it.
    c.execute("CREATE TABLE IF NOT EXISTS users (id integer PRIMARY KEY AUTOINCREMENT, nick text NOT NULL UNIQUE, hashedpwd text NOT NULL)");
    c.execute("CREATE TABLE IF NOT EXISTS mattermost_accounts(id integer PRIMARY KEY AUTOINCREMENT, user int NOT NULL REFERENCES users(id), host text not null, team text, password text)")
    db.commit()

    loop = asyncio.get_event_loop()

    asyncio.ensure_future(irc_handler())

    loop.run_forever()
    loop.close()
