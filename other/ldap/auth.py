#!/usr/bin/python3

import json
import jwt
from datetime import datetime, timezone, timedelta
from aiohttp import web
import aiohttp_cors

secret = b"\1\2\3\4"

users = {
    "john": "secret",
    "peter": "secret2",
}

async def handler(request):
    body = await request.json()

    if not ("username" in body and "group" in body and "password" in body):
        return web.HTTPBadRequest()

    username = body["username"]
    if not (username in users) or users[username] != body["password"]:
        return web.HTTPUnauthorized()

    now = datetime.now(tz=timezone.utc)
    token = {
        "sub": username,
        "aud": body["group"],
        "permissions": {"present": True},
        "iat": now,
        "exp": now + timedelta(seconds=30),
    }
    signed = jwt.encode(token, secret, algorithm="HS256")
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
