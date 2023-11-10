import re
import aiohttp
from getpass import getpass
from datetime import datetime
from typing import Tuple, Union, Optional
from aiohttp.client_exceptions import ClientError, ClientConnectorCertificateError
from time import sleep, localtime, strftime
from prettytable import PrettyTable

USER_AGENT = "Mozilla/5.0 (Linux; Android 12; SM-S906N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36"

sesskeyPattern = re.compile(r'"sesskey":"(\w+)","sessiontimeout"')
csrfPattern = re.compile(r'<input type="hidden" name="csrfToken" value="(\d+)"></input>')
executionPattern = re.compile(r'<input type="hidden" name="execution" value="(\w+)"/>')
ltPattern = re.compile(r'<input type="hidden" name="lt" value="(\S+)"/>')
jSessionIDPattern = re.compile(r'JSESSIONID=(\w+);')
idpPattern = re.compile(r'<a class="btn btn-secondary btn-block" title="XJTLU Account" href="(\S+)">XJTLU Account</a>')

SAMLRequestPattern = re.compile(r"""<meta http-equiv="refresh" content="0;URL='(\S+)'">""")

relayStatePattern = re.compile(r'<input type="hidden" name="RelayState" value="(\S+)"/>')
SAMLResponsePattern = re.compile(r'<input type="hidden" name="SAMLResponse" value="(\S+)"/>')


class CORE:
    def __init__(self,
                 session: aiohttp.ClientSession,
                 username: str) -> None:
        self.session = session
        self.username = username
        self.sessKey: Optional[str] = None

    @staticmethod
    def log_debug(cls, r):
        """
        For debugging
        :param cls: instance
        :param r: Actual print content
        :return:
        """
        print(f"\033[34m[INFO]\033[0m: {r}")

    @staticmethod
    def log_info(cls, r):
        """
        Output logs are created with
        :param cls: instance
        :param r: Actual print content
        :return:
        """
        print(f"\033[32m[INFO]\033[0m: {r}")

    @staticmethod
    def log_error(cls, r):
        """
        Error reporting with
        :param cls: instance
        :param r: Actual print content
        :return:
        """
        print(f"\033[31m[ERROR]\033[0m: {r}")

    async def auth(self, password) -> None:
        """
        The whole login process in learning mall
        :param username: Username
        :param password: User's Password
        :return:
        """
        async with self.session.get(
                url="https://core.xjtlu.edu.cn/local/login/index.php"
        ) as response:
            text = await response.text()
            sessKey = sesskeyPattern.findall(text)[0]
            idpUrl = idpPattern.findall(text)[0].replace(";", "&")
        async with self.session.get(
                url=idpUrl,
                allow_redirects=False
        ) as response:
            text = await response.text()
            samlUrl = SAMLRequestPattern.findall(text)[0]
        async with await self.session.get(
                url=samlUrl,
                headers={"user-agent": USER_AGENT},
                allow_redirects=False
        ) as response:
            nextUrl = response.headers.getone("Location")
        await self.session.get(url=nextUrl, allow_redirects=False)
        await self.session.get(url="https://sso.xjtlu.edu.cn/AuthnEngine", allow_redirects=False)

        async with self.session.get(
                url='https://sso.xjtlu.edu.cn/login'
        ) as response:
            if response.status == 200:
                text = await response.text()
                csrfToken = csrfPattern.findall(text)[0]
                lt = ltPattern.findall(text)[0]
                execution = executionPattern.findall(text)[0]
        await self.session.post(
            url="https://sso.xjtlu.edu.cn/login",
            data={
                "eid": "esc",
                "isShowRandomCode": "0",
                "keyCacheCode": f"{lt}_KEY",
                "lt": lt,
                "execution": execution,
                "_eventId": "submit",
                "authType": "pwd",
                "cert": "",
                "csrfToken": csrfToken,
                "username": self.username,
                "password": password,
                "adPasswd": "",
                "ldapPasswd": "",
                "otpCode": "",
                "smsCode": "",
                "randomCode": ""
            },
            allow_redirects=False
        )
        await self.session.get(url="https://sso.xjtlu.edu.cn/Authn/Credential", allow_redirects=False)

        async with self.session.get(
                url="https://sso.xjtlu.edu.cn/profile/SAML2/Unsolicited/SSO",
                allow_redirects=False
        ) as response:
            text = await response.text()
            ReplyState = relayStatePattern.findall(text)[0]
            SAMLResponse = SAMLResponsePattern.findall(text)[0]

        async with self.session.post(
                url="https://core.xjtlu.edu.cn/auth/saml2/sp/saml2-acs.php/core.xjtlu.edu.cn",
                data={
                    "ReplyState": ReplyState,
                    "SAMLResponse": SAMLResponse
                },
                allow_redirects=False
        ) as response:
            nextUrl = response.headers.getone("Location")

        await self.session.get(url=nextUrl, allow_redirects=False)

        async with self.session.get(url="https://core.xjtlu.edu.cn") as response:
            text = await response.text()
            sessKey = sesskeyPattern.findall(text)[0]
            self.sessKey = sessKey

    async def get_timeline(self):
        time_now = int(datetime.now().timestamp())
        async with self.session.post(
                url=f"https://core.xjtlu.edu.cn/lib/ajax/service.php?sesskey={self.sessKey}&info=core_calendar_get_action_events_by_timesort",
                json=[{
                    "index": 0,
                    "methodname": "core_calendar_get_action_events_by_timesort",
                    "args": {
                        "limitnum": 6,
                        "timesortfrom": time_now,
                        "limittononsuspendedevents": True
                    }
                }]
        ) as resp:
            datas = (await resp.json())[0]
            if not datas["error"]:
                pass
            events = datas["data"]["events"]

        tab = PrettyTable(['ID', 'Name', 'URL', 'DDL'])
        for event in events:
            if event["modulename"] == "quiz":
                tab.add_row([event["id"], 
                    event["name"].encode().decode("utf-8"), 
                    event["url"], 
                    strftime('%Y-%m-%d %H:%M', localtime(int(event["timeusermidnight"])))]
                )

        print(tab)


async def main():
    try:
        async with aiohttp.ClientSession() as session:

            print(f"⚠️We will neither save nor upload your account password⚠️")
            u = input("Please enter your account:")
            p = getpass("Please enter your password:")
            app = CORE(session, u)
            await app.auth(p)
            while True:
                await app.get_timeline()
                sleep(30)

    except KeyboardInterrupt:
        print("\n")
        CORE.log_info(None, "Thanks for using.")
    except ClientConnectorCertificateError:
        print("\n")
        CORE.log_error(None, "Network error, SSL authentication error")
        CORE.log_info(None, "Please check your Python version (requires 3.7.5^) or turn off the Magic Network (#^. ^#)")
    except ClientError:
        print("\n")
        CORE.log_error(None, "Network connection error")


if __name__ == '__main__':
    import asyncio

    print("""   ____            _           __  __                   _   _                  
  / __ \          (_)         |  \/  |                 (_) | |                 
 | |  | |  _   _   _   ____   | \  / |   ___    _ __    _  | |_    ___    _ __ 
 | |  | | | | | | | | |_  /   | |\/| |  / _ \  | '_ \  | | | __|  / _ \  | '__|
 | |__| | | |_| | | |  / /    | |  | | | (_) | | | | | | | | |_  | (_) | | |   
  \___\_\  \__,_| |_| /___|   |_|  |_|  \___/  |_| |_| |_|  \__|  \___/  |_|   
                                           
    Github: https://github.com/AprilNEA/quiz-monitor
    License: GPL-3.0 (\033[32mopen source and free\033[0m)
    Author: AprilNEA (https://sku.moe)
    Email: github@sku.moe
    """)
    asyncio.run(main())