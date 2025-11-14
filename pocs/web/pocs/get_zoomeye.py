from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)

minimum_version_required('1.9.11')


class POC(POCBase):
    name = 'get_zoomeye'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'country:"JP"'}

    def _verify(self):
        result = {}
        flag = 1
        result['VerifyInfo'] = {}
        result['VerifyInfo']['url'] = self.url
        return self.parse_output(result)


register_poc(POC)
