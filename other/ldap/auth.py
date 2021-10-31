#!/usr/bin/python3

import json
import jwt
import re
from datetime import datetime, timezone, timedelta
from aiohttp import web
import aiohttp_cors
from ldap3 import Server, Connection

from credentials import credentials, crypto_key  

async def handler(request):
    body = await request.json()

    if not ("username" in body and "group" in body and "password" in body):
        return web.HTTPBadRequest()

    username = body["username"]
    # check whether the user can connect to the LDAP service
    conn=None
    group=None
    try:
        conn=Connection(
            Server(credentials.ldap_host, port=credentials.ldap_port),
            user=f'cn={body["username"]},{credentials.user_branch}',
            password=body["password"],
            check_names=True,
            raise_exceptions=True
        )
        conn.bind()
        filtre  = f'(&(objectClass={credentials.account_field})(cn={body["username"]}))'
        conn.search(
            search_base = credentials.user_branch,
            search_filter = filtre,
            attributes = credentials.attributes
        )
        # use conn.response to find the group this user belongs to
        member_of = conn.response[0]["attributes"]["memberOf"]
        m = re.match("^cn=([^,]+),.*", member_of[0], re.I)
        group = m.group(1)
    except:
        return web.HTTPUnauthorized()

    now = datetime.now(tz=timezone.utc)
    token = {
        "sub": username,
        "group": group,
        "permissions": {"present": True},
        "iat": now,
        "exp": now + timedelta(seconds=30),
    }
    return web.Response(
        headers={"Content-Type": "application/jwt"},
        body=jwt.encode(token, crypto_key, algorithm="HS256"),
    )

app = web.Application()
route = app.router.add_route("POST", "/", handler)
cors = aiohttp_cors.setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(
        expose_headers="*",
        allow_headers="*",
    )
})
cors.add(route)
web.run_app(app, port=1234)
