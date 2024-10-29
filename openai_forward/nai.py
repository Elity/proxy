from loguru import logger

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from openai_forward.tool import env2list

class NAIBase:
    API_NOVEL = "https://api.novelai.net"
    TEXT_NOVEL = "https://text.novelai.net"
    IP_WHITELIST = env2list("IP_WHITELIST", sep=" ")
    IP_BLACKLIST = env2list("IP_BLACKLIST", sep=" ")

    timeout = 600

    def validate_request_host(self, ip):
        if self.IP_WHITELIST and ip not in self.IP_WHITELIST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden, ip={ip} not in whitelist!",
            )
        if self.IP_BLACKLIST and ip in self.IP_BLACKLIST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden, ip={ip} in blacklist!",
            )

    @classmethod
    async def _reverse_proxy(cls, request: Request):
        body = await request.json()
        BASE_URL = cls.API_NOVEL if 'clio' in body['model'] else cls.TEXT_NOVEL
        if 'parameters' in body and body['parameters'] is not None:
            if 'repetition_penalty_whitelist' in body['parameters']:
                repetition_penalty_whitelist = body['parameters']['repetition_penalty_whitelist'] if body['parameters']['repetition_penalty_whitelist'] is not None else []
                new_whitelist = []
                for sublist in repetition_penalty_whitelist:
                    if isinstance(sublist, int):
                        new_whitelist.append(sublist)
                    else:
                        new_whitelist.extend(sublist)
                body['parameters']['repetition_penalty_whitelist'] = new_whitelist
            if 'max_length' in body['parameters']:
                body['parameters']['max_length'] = min(int(body['parameters']['max_length']), 150) if body['parameters']['max_length'] is not None else 150
            if 'min_length' in body['parameters']:
                body['parameters']['min_length'] = min(int(body['parameters']['min_length']), 150) if body['parameters']['min_length'] is not None else 50
        client = httpx.AsyncClient(base_url=BASE_URL, http1=True, http2=False)
        url_path = request.url.path
        url = httpx.URL(path=url_path, query=request.url.query.encode("utf-8"))
        headers = dict(request.headers)
        auth = headers.pop("authorization", "")
        content_type = headers.pop("content-type", "application/json")
        auth_headers_dict = {"Content-Type": content_type, "Authorization": auth}

        req = client.build_request(
            request.method,
            url,
            json=body,
            headers=auth_headers_dict,
            timeout=cls.timeout,
        )
        try:
            r = await client.send(req, stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            error_info = (
                f"{type(e)}: {e} | "
                f"Please check if host={request.client.host} can access [{BASE_URL}] successfully?"
            )
            logger.error(error_info)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=error_info
            )
        except Exception as e:
            logger.exception(f"{type(e)}:")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e
            )

        aiter_bytes = r.aiter_bytes()
        return StreamingResponse(
            aiter_bytes,
            status_code=r.status_code,
            media_type=r.headers.get("content-type"),
            background=BackgroundTask(r.aclose),
        )


class NovelAI(NAIBase):
    def __init__(self):
        if self.IP_BLACKLIST or self.IP_WHITELIST:
            self.validate_host = True
        else:
            self.validate_host = False

    async def reverse_proxy(self, request: Request):
        if self.validate_host:
            self.validate_request_host(request.client.host)
        return await self._reverse_proxy(request)