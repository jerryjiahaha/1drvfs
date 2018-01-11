#!/usr/bin/env python3

import asyncio
import logging
import uuid
import webbrowser
import urllib.parse
from typing import Dict

import tornado.web
from tornado.platform.asyncio import AsyncIOMainLoop, to_asyncio_future
import tornado.httpclient
import tornado.escape

import config

logging.basicConfig(level=logging.DEBUG)

"""
@ref: https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth
Step 1. Get an authorization code
GET https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={client_id}&scope={scope}
  &response_type=code&redirect_uri={redirect_uri}
"""


SECRET = config.SECRET
APP_ID = config.APP_ID
AUTH_API = "https://login.microsoftonline.com/common/oauth2/v2.0/"
MS_GRAPH = "https://graph.microsoft.com/v1.0/"
REDIRECT_URI = "http://localhost:5000/login/authorized"
RESPONSE_TYPE = "code"
SCOPES = ["Files.ReadWrite.All", "offline_access", "User.Read",] # space-separated list

class response_result:
    def __init__(self, status="empty", body=None):
        self._status = status
        self._body = body

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, value):
        self._body = value

    def as_dict(self):
        return {
            "status": self.status,
            "body": self.body,
        }

class OAuthManager:
    def __init__(self):
        self._access_token = None
        self._refresh_token = None
        self._ttl = -1
        self._scope = []
        self._refresh_cond = asyncio.Condition()
        self._available_cond = asyncio.Condition()
        asyncio.ensure_future(self.service_refresh_token())

    async def service_refresh_token(self):
        """auto refresh token"""
        print("service refresh token")
        while True:
            print("ttl:", self._ttl)
            if self._ttl <= 0:
                print("lock")
                await self._refresh_cond.acquire()
                print("wait")
                await self._refresh_cond.wait()
                self._refresh_cond.release()
                continue
            if self._ttl <= 1800: # less than 10min
                await self.refresh_token(self._refresh_token)
            await asyncio.sleep(10)
            self._ttl -= 10

    @staticmethod
    def get_query_dict(kw_ext: Dict):
        default = {
            "client_id": APP_ID,
            "redirect_uri": REDIRECT_URI,
            "client_secret": SECRET,
        }
        default.update(kw_ext)
        return default

    async def request_api(self, url):
        print("request_api", url)
        if self._available_cond.locked():
            print("not available, acquiring...")
            await self._available_cond.acquire()
            print("waiting...")
            await self._available_cond.wait()
            self._available_cond.release()
        token = self._access_token
        client = tornado.httpclient.AsyncHTTPClient()
        request = tornado.httpclient.HTTPRequest(url, \
            headers={"Authorization": f"bearer {token}"},
        )
        ret = response_result()
        try:
            future = client.fetch(request)
            response = await to_asyncio_future(future)
            ret.status = "success"
        except tornado.httpclient.HTTPError as err:
            print(err)
            response = err.response
            ret.status = "fail"
        ret.body = tornado.escape.json_decode(response.body.decode())
        return ret.as_dict()

    @classmethod
    async def post(self, keywords: Dict):
        url = f"{AUTH_API}token"
        body = urllib.parse.urlencode(keywords)
        print(url, body)
        request = tornado.httpclient.HTTPRequest(
            url, method="POST", body=body,
        )
        client = tornado.httpclient.AsyncHTTPClient()
        ret = response_result()
        try:
            response = await to_asyncio_future(client.fetch(request))
            print(response)
            ret.status = "success"
        except tornado.httpclient.HTTPError as e:
            print(e)
            response = e.response
            ret.status = "fail"
        ret.body = tornado.escape.json_decode(response.body.decode())
        return ret.as_dict()

    async def update_token_info(self, body):
        self._access_token = body["access_token"]
        self._refresh_token = body["refresh_token"]
        self._ttl = body["expires_in"]
        print("update_token acquire")
        await self._refresh_cond.acquire()
        print("notify all")
        self._refresh_cond.notify_all()
        self._refresh_cond.release()

    async def perform_token_request(self, query_kw: Dict):
        await self._available_cond.acquire()
        ret = await self.post(query_kw)
        print(ret)
        if ret["status"] == "success":
            await self.update_token_info(ret["body"])
        self._available_cond.notify_all()
        self._available_cond.release()

    async def redeem_code_tokens(self, code):
        """Step 2 in https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth
        """
        print("redeem_token")
        query_kw = self.get_query_dict({
            "code": code,
            "grant_type": "authorization_code",
        })
        await self.perform_token_request(query_kw)

    async def refresh_token(self, token):
        """Step 3 in https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth
        """
        print("refresh_token")
        query_kw = self.get_query_dict({
            "refresh_token": token,
            "grant_type": "refresh_token",
        })
        await self.perform_token_request(query_kw)


class Application(tornado.web.Application):
    def __init__(self, oauth_manager=None):
        handlers = [
            (r"/", IndexHandler,),
            (r"/login/(?P<action>\S+?)/?", OAuthorizedHandler,),
            (r"/api/start/", StartHandler),
            (r"/api/list/", ApiListHandler),
        ]
        settings = {
            "debug": True,
        }
        self._session_manager = set()
        self._session_code = {}
        if oauth_manager is None:
            self.oauth_manager = OAuthManager()
        else:
            self.oauth_manager = oauth_manager
        super().__init__(handlers, **settings)

    def gen_session(self):
        """just return uuid"""
        return str(uuid.uuid4())

    def create_session(self):
        """create new session and add into session manager"""
        session = self.gen_session()
        self._session_manager.add(session)
        print(self._session_manager)
        return session

    def find_session(self, session):
        """find session in session manager"""
        return session in self._session_manager

    def save_code(self, session, code):
        """save session's coresponding code"""
        self._session_code[session] = code


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.write(
            """
            <html>
            <head></head>
            <body>
                <a href="/login/oauth/">oauth</a>
                <a href="/api/list/">list</a>
            </body>
            </html>
            """
        )

class StartHandler(tornado.web.RequestHandler):
    def get(self):
        session = self.get_cookie("session")
        if not self.application.find_session(session):
            self.write_error(404)
            return

class ApiListHandler(tornado.web.RequestHandler):
    @property
    def oauth_manager(self):
        return self.application.oauth_manager

    async def get(self):
        ret = await self.oauth_manager.request_api(f"{MS_GRAPH}me/drive")
        print(ret)
        self.write(ret)

class OAuthorizedHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        print('init handler')
        super().__init__(*args, **kwargs)

    async def get(self, action):
        print(action)
        print("cookies:", self.cookies)
        if action == "oauth_browser":
            self.set_cookie("session", self.application.create_session())
            await self.fetch_auth_token()
        elif action == "authorized":
            await self.authorized()
        elif action == "oauth":
            self.set_cookie("session", self.application.create_session())
            url = self.get_auth_code()
            self.redirect(url)
        else:
            self.write_error(404)

    async def authorized(self):
        session = self.get_cookie("session")
        if not self.application.find_session(session):
            print(f"session {session} not found")
            self.write_error(404)
            return
        code = self.get_query_argument("code")
        print(code)
        self.application.save_code(session, code)
        self.write(code)
        print("redeem code tokens")
        task = asyncio.ensure_future( \
            self.application.oauth_manager.redeem_code_tokens(code))
        await task

    def get_auth_code(self):
        api = f"{AUTH_API}authorize"
        query_kw = {
            "client_id": APP_ID,
            "scope": " ".join(SCOPES),
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
        }
        query_str = urllib.parse.urlencode(query_kw, quote_via=urllib.parse.quote)
        url_str = f"{api}?{query_str}"
        print(url_str)
        return url_str

    async def fetch_auth_token(self):
        url_str = self.get_auth_code()
        await asyncio.get_event_loop().run_in_executor(None,
                webbrowser.open_new_tab, url_str)
        self.write(url_str)


if __name__ == '__main__':
    AsyncIOMainLoop().install()
    app = Application()
    app.listen(5000)
    print("running")
    asyncio.get_event_loop().run_forever()
   
