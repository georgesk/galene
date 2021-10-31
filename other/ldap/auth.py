#!/usr/bin/python3

import json
import jwt
from datetime import datetime, timezone, timedelta
from aiohttp import web
import aiohttp_cors
from ldap3 import Server, Connection

from credentials import credentials, private_crypto_key  

async def handler(request):
    body = await request.json()

    if not ("username" in body and "group" in body and "password" in body):
        return web.HTTPBadRequest()

    username = body["username"]
    # check whether the user can connect to the LDAP service
    conn=None
    try:
        conn=Connection(
            Server(credentials.ldap_host, port=credentials.ldap_port),
            user=body["username"],
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
        print("HELLO conn.response = ", conn.response)
    except:
        return web.HTTPUnauthorized()

    now = datetime.now(tz=timezone.utc)
    token = {
        "sub": username,
        "aud": body["group"],
        "permissions": {"present": True},
        "iat": now,
        "exp": now + timedelta(seconds=30),
    }
    signed = jwt.encode(token, private_crypto_key, algorithm="HS256")
    return web.Response(
        headers={"Content-Type": "aplication/jwt"},
        body=signed,
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
